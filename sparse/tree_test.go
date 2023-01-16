package sparse

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSparseBinarySummationTree(t *testing.T) {
	tree := Tree{
		FanOut: 2,
		ID2Path: func(id string) []uint16 {
			var res []uint16
			for i := 0; i < len(id); i++ {
				res = append(res, uint16(id[i]-'0'))
			}
			return res
		},
		UpdateInnerVertex: func(key string, node interface{}, descendants []interface{}, _ bool, _ int) interface{} {
			var sum int
			for _, n := range descendants {
				if n != nil {
					sum += n.(int)
				}
			}
			return sum
		},
	}

	originalUpdateVertex := tree.UpdateInnerVertex
	var leaves []bool
	var indices []int
	instrumentedUpdateInnerVertex := func(key string, node interface{}, descendants []interface{}, leaf bool, index int) interface{} {
		leaves = append(leaves, leaf)
		indices = append(indices, index)
		return originalUpdateVertex(key, node, descendants, leaf, index)
	}
	tree.UpdateInnerVertex = instrumentedUpdateInnerVertex

	expectedIndices := map[string][]int{
		"00": {0, 0},
		"01": {1, 0},
		"10": {0, 1},
		"11": {1, 1},
	}

	for _, tst := range []struct {
		string
		int
	}{
		{
			"00", 5,
		},
		{
			"01", 4,
		},
		{
			"10", 3,
		},
		{
			"11", 2,
		},
	} {
		t.Run(tst.string, func(t *testing.T) {
			tree.Put(tst.string, tst.int)
			assert.Equal(t, expectedIndices[tst.string], indices)
			indices = nil
			assert.True(t, leaves[0])
			leaves = leaves[1:]
			assert.False(t, leaves[0])
			assert.Len(t, leaves, 1)
			leaves = nil
		})
	}

	for _, tst := range []struct {
		string
		int
	}{
		{"00", 5},
		{"01", 4},
		{"10", 3},
		{"11", 2},
		{"0", 9},
		{"1", 5},
		{"", 14},
	} {
		t.Run(tst.string, func(t *testing.T) {
			val, _, ok := tree.Get(tst.string)
			assert.True(t, ok)
			assert.Equal(t, tst.int, val.(int))
		})
	}
}

func TestSSNSummationTree(t *testing.T) {
	tree := Tree{
		FanOut:  7,
		ID2Path: DigitPath(7),
		UpdateInnerVertex: func(key string, node interface{}, descendants []interface{}, _ bool, _ int) interface{} {
			var sum int
			for _, n := range descendants {
				if n != nil {
					sum += n.(int)
				}
			}
			return sum
		},
	}

	for _, tst := range []struct {
		string
		int
	}{
		{"123456789", 5},
		{
			"123456780", 4,
		},
		{
			"123456700", 3,
		},
		{
			"123456000", 2,
		},
	} {
		tst := tst
		t.Run(tst.string, func(t *testing.T) {
			tree.Put(tst.string, tst.int)
		})
	}

	for _, tst := range []struct {
		bool
		string
		int
	}{
		{
			true, "123456789", 5,
		},
		{
			true, "123456780", 4,
		},
		{
			true, "123456700", 3,
		},
		{
			true, "123456000", 2,
		},
		{
			false, "123406700", 0,
		},
	} {
		tst := tst
		t.Run(tst.string, func(t *testing.T) {
			val, _, ok := tree.Get(tst.string)
			if ok {
				assert.Equalf(t, tst.int, val, "%d is empty", tst.int)
			}
			assert.Equal(t, tst.bool, ok)
		})
	}
}

func TestSparsePowerTwoSummationTree(t *testing.T) {
	tree := Tree{
		FanOut:  7,
		ID2Path: HexId2PathForFanOut(7),
		UpdateInnerVertex: func(key string, node interface{}, descendants []interface{}, _ bool, _ int) interface{} {
			var sum int
			for _, n := range descendants {
				if n != nil {
					sum += n.(int)
				}
			}
			return sum
		},
	}

	for _, tst := range []struct {
		string
		int
	}{
		{
			hash("5"), 5,
		},
		{
			hash("4"), 4,
		},
		{
			hash("3"), 3,
		},
		{
			hash("2"), 2,
		},
	} {
		tst := tst
		t.Run(tst.string, func(t *testing.T) {
			tree.Put(tst.string, tst.int)
		})
	}

	for _, tst := range []struct {
		bool
		string
		int
	}{
		{
			true, hash("5"), 5,
		},
		{
			true, hash("4"), 4,
		},
		{
			true, hash("3"), 3,
		},
		{
			true, hash("2"), 2,
		},
		{
			false, hash("1"), 0,
		},
	} {
		tst := tst
		t.Run(tst.string, func(t *testing.T) {
			val, _, ok := tree.Get(tst.string)
			if ok {
				assert.Equalf(t, tst.int, val, "%d is empty", tst.int)
			}
			assert.Equal(t, tst.bool, ok)
		})
	}
}

func TestHexPathIsInCorrectLength(t *testing.T) {

	for fanout := range ExpectedHexPathLengthByFanOut {
		id2Path := HexId2PathForFanOut(fanout)

		pathLengths := make(map[int]int)

		for i := 0; i < 10000; i++ {
			buff := make([]byte, 32)
			_, err := rand.Read(buff)
			assert.NoError(t, err)

			s := hex.EncodeToString(buff)

			pathLengths[len(id2Path(s))]++
		}

		assert.Len(t, pathLengths, 1, pathLengths)
	}

}
