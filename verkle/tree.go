package verkle

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	math "github.com/IBM/mathlib"
	"pol/common"
	"pol/pp"
	"pol/sparse"
	"strconv"
)

var (
	c          = math.Curves[1]
	GroupOrder = c.GroupOrder
)

type Tree struct {
	pp    *pp.PP
	depth int
	tree  *sparse.Tree
}

type Vertex struct {
	values     common.Vec
	sum        *math.Zr
	commitment *math.G1
}

func NewVerkleTree(fanOut uint16) *Tree {
	var id2Path func(string) []uint16

	if isPowerOfTwo(fanOut) {
		id2Path = hexId2Path
	} else {
		id2Path = decimalId2Path
	}
	t := &Tree{
		pp: pp.NewPublicParams(int(fanOut + 1)),
		tree: &sparse.Tree{
			FanOut:  int(fanOut),
			ID2Path: id2Path,
		},
	}

	t.tree.UpdateInnerVertex = t.updateInnerVertex
	return t

}

func (t *Tree) Get(id string) (int, bool) {
	n, ok := t.tree.Get(id)
	if !ok {
		return 0, false
	}
	return int(n.(int64)), true
}

func (t *Tree) Put(id string, data int) {
	t.validateInput(id, data)
	t.tree.Put(id, int64(data))
}

func (t *Tree) validateInput(id string, data interface{}) {
	if _, isInt := data.(int); !isInt {
		panic(fmt.Sprintf("Verkle tree leaf entries can only be of type int"))
	}

	path := t.tree.ID2Path(id)
	if t.depth == 0 {
		t.depth = len(path)
	}

	if t.depth != len(path) {
		panic(fmt.Sprintf("Verkle tree of depth %d cannot insert leaves at depth %d", t.depth, len(path)))
	}
}

func (t *Tree) updateInnerVertex(node interface{}, descendants []interface{}, descendantsLeaves bool, index int) interface{} {
	if descendantsLeaves {
		return t.updateLayerAboveLeaves(node, descendants, index)
	}
	return t.updateInnerLayer(node, descendants, index)
}

func (t *Tree) updateInnerLayer(node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex
	if node == nil {
		v = &Vertex{
			sum: c.NewZrFromInt(0),
		}

		for _, desc := range descendants {
			if desc == nil {
				v.values = append(v.values, c.NewZrFromInt(0))
				continue
			}
			val := desc.(*Vertex).sum
			v.sum = v.sum.Plus(val)
			v.values = append(v.values, val)
		}

		v.values = append(v.values, v.sum)
		v.commitment = pp.Commit(t.pp, v.values)

		return v
	}

	v = node.(*Vertex)
	oldVal := v.values[index]
	newVal := descendants[index].(*Vertex).sum

	v.sum = updateSum(v.sum, oldVal, newVal)

	// Update index with new value
	pp.Update(t.pp, v.commitment, v.values, newVal, index)
	v.values[index] = newVal

	// Update last entry with sum
	pp.Update(t.pp, v.commitment, v.values, v.sum, len(v.values))

	return v
}

func (t *Tree) updateLayerAboveLeaves(node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex
	if node == nil {
		v = &Vertex{
			sum: c.NewZrFromInt(0),
		}

		for _, desc := range descendants {
			if desc == nil {
				v.values = append(v.values, c.NewZrFromInt(0))
				continue
			}
			val := desc.(int64)
			v.sum = v.sum.Plus(c.NewZrFromInt(val))
			v.values = append(v.values, c.NewZrFromInt(val))
		}

		v.values = append(v.values, v.sum)
		v.commitment = pp.Commit(t.pp, v.values)

		return v
	}

	v = node.(*Vertex)
	oldVal := v.values[index]
	new := descendants[index].(int64)
	newVal := c.NewZrFromInt(new)

	v.sum = updateSum(v.sum, oldVal, newVal)

	// Update index with new value
	pp.Update(t.pp, v.commitment, v.values, newVal, index)
	v.values[index] = newVal

	// Update last entry with sum
	pp.Update(t.pp, v.commitment, v.values, v.sum, len(v.values))

	return v
}

func updateSum(sum, removed, added *math.Zr) *math.Zr {
	return c.ModAdd(sum, c.ModSub(added, removed, c.GroupOrder), c.GroupOrder)
}

func decimalId2Path(s string) []uint16 {
	var res []uint16

	for i := 0; i < len(s); i++ {
		decimal := fmt.Sprintf("%v", s[i])
		n, err := strconv.ParseUint(decimal, 10, 16)
		if err != nil {
			panic(fmt.Sprintf("%s is not a decimal string", decimal))
		}
		res = append(res, uint16(n))
	}

	return res
}

func hexId2Path(s string) []uint16 {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("%s is not a hexadecimal string", s))
	}

	var res []uint16
	for len(bytes) > 0 {
		if len(bytes) < 2 {
			bytes = []byte{0, bytes[0]}
		}
		res = append(res, binary.LittleEndian.Uint16(bytes[:2]))
		bytes = bytes[2:]
	}

	return res
}

func isPowerOfTwo(n uint16) bool {
	if n == 1 {
		return false
	}

	for {
		lsb := n & 1
		n = n >> 1
		if n == 0 && lsb == 1 {
			return true
		}
		if lsb == 1 {
			return false
		}
	}
}
