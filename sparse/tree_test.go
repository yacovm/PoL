package sparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSparseBinarySummationTree(t *testing.T) {
	tree := Tree{
		FanOut: 2,
		ID2Path: func(id string) []uint8 {
			var res []uint8
			for i := 0; i < len(id); i++ {
				res = append(res, id[i]-'0')
			}
			return res
		},
		UpdateInnerVertex: func(node interface{}, descendants []interface{}) interface{} {
			var sum int
			for _, n := range descendants {
				if n != nil {
					sum += n.(int)
				}
			}
			return sum
		},
	}

	tree.Put("00", 5)
	tree.Put("01", 4)
	tree.Put("10", 3)
	tree.Put("11", 2)

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
			val, ok := tree.Get(tst.string)
			assert.True(t, ok)
			assert.Equal(t, tst.int, val.(int))
		})
	}
}
