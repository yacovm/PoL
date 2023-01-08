package verkle

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"pol/common"
	"pol/pp"
	"pol/sparse"
	"strconv"

	math "github.com/IBM/mathlib"
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
	blindingFactor *math.Zr
	values         map[uint16]*math.Zr
	digests        map[uint16]*math.Zr
	sum            *math.Zr
	V              *math.G1 // Commitment to values of descendants
	W              *math.G1 // Commitment to digests of descendants
}

func (v *Vertex) Digest() *math.Zr {
	h := sha256.New()
	h.Write(v.V.Bytes())
	if v.W != nil {
		h.Write(v.W.Bytes())
	}
	hash := h.Sum(nil)
	return common.FieldElementFromBytes(hash)
}

func NewVerkleTree(fanOut uint16) *Tree {
	var id2Path func(string) []uint16

	if common.IsPowerOfTwo(fanOut) {
		id2Path = sparse.HexId2PathForFanout(fanOut)
	} else {
		id2Path = decimalId2Path
	}
	t := &Tree{
		pp: pp.NewPublicParams(int(fanOut + 2)),
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
	t.validateInput(id, data) // TODO: remove this later for performance improvements
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
			blindingFactor: c.NewRandomZr(rand.Reader),
			sum:            c.NewZrFromInt(0),
			values:         make(map[uint16]*math.Zr),
			digests:        make(map[uint16]*math.Zr),
		}

		// value vector
		m := make(common.Vec, 0, len(descendants)+2)

		// digest vector
		d := make(common.Vec, 0, len(descendants)+2)

		for i, desc := range descendants {
			if desc == nil {
				m = append(m, c.NewZrFromInt(0))
				d = append(d, c.NewZrFromInt(0))
				continue
			}
			val := desc.(*Vertex).sum
			v.sum = v.sum.Plus(val)
			v.values[uint16(i)] = val
			digest := desc.(*Vertex).Digest()
			v.digests[uint16(i)] = digest
			m = append(m, val)
			d = append(d, digest)
		}

		// Artificially append the sum
		m = append(m, v.sum)

		// Artificially append the blinding factor
		m = append(m, v.blindingFactor)

		// Commit to values
		v.V = pp.Commit(t.pp, m)

		// Artificially append two empty values
		d = append(d, c.NewZrFromInt(0))
		d = append(d, c.NewZrFromInt(0))

		// Commit to digests
		v.W = pp.Commit(t.pp, d)

		return v
	}

	v = node.(*Vertex)
	oldVal := v.values[uint16(index)]
	if oldVal == nil {
		oldVal = c.NewZrFromInt(0)
	}
	newVal := descendants[index].(*Vertex).sum
	newDigest := descendants[index].(*Vertex).Digest()

	v.sum = updateSum(v.sum, oldVal, newVal)

	// Update index with new value and digest
	m := make(common.Vec, t.pp.N)
	d := make(common.Vec, t.pp.N)

	for i := 0; i < len(m); i++ {
		if val, exists := v.values[uint16(i)]; exists {
			m[uint16(i)] = val
			d[uint16(i)] = v.digests[uint16(i)]
		} else {
			m[uint16(i)] = c.NewZrFromInt(0)
			d[uint16(i)] = c.NewZrFromInt(0)
		}
	}

	// Artificially append the sum
	m = append(m, v.sum)

	pp.Update(t.pp, v.V, m, newVal, index)
	v.values[uint16(index)] = newVal

	// Update last entry with sum
	pp.Update(t.pp, v.V, m, v.sum, len(v.values))

	// Update the new digest
	pp.Update(t.pp, v.W, d, newDigest, index)
	v.digests[uint16(index)] = newDigest

	return v
}

func (t *Tree) updateLayerAboveLeaves(node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex
	if node == nil {
		v = &Vertex{
			blindingFactor: c.NewRandomZr(rand.Reader),
			sum:            c.NewZrFromInt(0),
			values:         make(map[uint16]*math.Zr),
			digests:        make(map[uint16]*math.Zr),
		}

		m := make(common.Vec, 0, len(descendants)+2)

		for i, desc := range descendants {
			if desc == nil {
				m = append(m, c.NewZrFromInt(0))
				continue
			}

			val := desc.(int64)
			num := c.NewZrFromInt(val)
			v.sum = v.sum.Plus(num)
			v.values[uint16(i)] = num
			m = append(m, num)
		}

		// Artificially append the sum
		m = append(m, v.sum)

		// Artificially append the blinding factor
		m = append(m, v.blindingFactor)

		v.V = pp.Commit(t.pp, m)

		return v
	}

	v = node.(*Vertex)
	oldVal := v.values[uint16(index)]
	if oldVal == nil {
		oldVal = c.NewZrFromInt(0)
	}
	new := descendants[index].(int64)
	newVal := c.NewZrFromInt(new)

	v.sum = updateSum(v.sum, oldVal, newVal)

	// Update index with new value
	m := make(common.Vec, t.pp.N)
	for i := 0; i < len(m); i++ {
		if val, exists := v.values[uint16(i)]; exists {
			m[uint16(i)] = val
		} else {
			m[uint16(i)] = c.NewZrFromInt(0)
		}
	}

	// Artificially append the sum
	m = append(m, v.sum)

	// Update index with new value
	pp.Update(t.pp, v.V, m, newVal, index)
	v.values[uint16(index)] = newVal

	// Update last entry with sum
	pp.Update(t.pp, v.V, m, v.sum, len(v.values))

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
