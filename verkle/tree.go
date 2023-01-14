package verkle

import (
	"crypto/rand"
	"crypto/sha256"
	math "github.com/IBM/mathlib"
	"pol/common"
	"pol/pp"
	"pol/sparse"
	"pol/sum"
)

var (
	c          = math.Curves[1]
	GroupOrder = c.GroupOrder
)

type Tree struct {
	PP    *pp.PP
	depth int
	Tree  *sparse.Tree
}

type Vertex struct {
	BlindingFactor *math.Zr
	values         map[uint16]*math.Zr
	Digests        map[uint16]*math.Zr
	sum            *math.Zr
	V              *math.G1 // Commitment to values of descendants
	W              *math.G1 // Commitment to Digests of descendants
}

type Vertices []*Vertex

func (vs Vertices) SumArgument(pp *sum.PP) *sum.Proof {
	commitments := make(common.G1v, len(vs))
	vectors := make([]common.Vec, len(vs))
	randomness := make(common.Vec, len(vs))
	for i, v := range vs {
		commitments[i] = v.V
		randomness[i] = v.BlindingFactor
		vectors[i] = make(common.Vec, len(pp.H))
		for j := uint16(0); j < uint16(len(pp.H)); j++ {
			if n, exists := v.values[j]; exists {
				vectors[i][j] = n
			} else {
				vectors[i][j] = common.IntToZr(0)
			}
			// Put the sum in the last index
			if j == uint16(len(pp.H)-1) {
				vectors[i][j] = v.sum
			}
		}
	}
	return sum.NewAggregatedArgument(pp, commitments, vectors, randomness)
}

func (v *Vertex) Values(n int) common.Vec {
	res := make(common.Vec, n)
	for j := uint16(0); j < uint16(n); j++ {
		if n, exists := v.values[j]; exists {
			res[j] = n
		} else {
			res[j] = common.IntToZr(0)
		}
		// Put the sum in the last index
		if j == uint16(n-1) {
			res[j] = v.sum
		}
	}

	return res
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

func NewVerkleTree(fanOut uint16, id2Path func(string) []uint16) *Tree {
	t := &Tree{
		PP: pp.NewPublicParams(int(fanOut + 2)),
		Tree: &sparse.Tree{
			FanOut:  int(fanOut),
			ID2Path: id2Path,
		},
	}

	t.Tree.UpdateInnerVertex = t.updateInnerVertex
	return t

}

func (t *Tree) Get(id string) (int64, []*Vertex, bool) {
	n, path, ok := t.Tree.Get(id)
	if !ok {
		return 0, nil, false
	}

	verticesAlongThePath := make([]*Vertex, len(path))
	for i := 0; i < len(verticesAlongThePath); i++ {
		verticesAlongThePath[i] = path[i].(*sparse.Vertex).Data.(*Vertex)
	}

	return n.(int64), verticesAlongThePath, true
}

func (t *Tree) Put(id string, data int64) {
	t.Tree.Put(id, data)
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
			BlindingFactor: c.NewRandomZr(rand.Reader),
			sum:            c.NewZrFromInt(0),
			values:         make(map[uint16]*math.Zr),
			Digests:        make(map[uint16]*math.Zr),
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
			v.Digests[uint16(i)] = digest
			m = append(m, val)
			d = append(d, digest)
		}

		// Artificially append the sum
		m = append(m, v.sum)

		// Artificially append the blinding factor
		m = append(m, v.BlindingFactor)

		// Commit to values
		v.V = pp.Commit(t.PP, m)

		// Artificially append two empty values
		d = append(d, c.NewZrFromInt(0))
		d = append(d, c.NewZrFromInt(0))

		// Commit to Digests
		v.W = pp.Commit(t.PP, d)

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
	m := make(common.Vec, t.PP.N)
	d := make(common.Vec, t.PP.N)

	for i := 0; i < len(m); i++ {
		if val, exists := v.values[uint16(i)]; exists {
			m[uint16(i)] = val
			d[uint16(i)] = v.Digests[uint16(i)]
		} else {
			m[uint16(i)] = c.NewZrFromInt(0)
			d[uint16(i)] = c.NewZrFromInt(0)
		}
	}

	// Artificially append the sum
	m = append(m, v.sum)

	pp.Update(t.PP, v.V, m, newVal, index)
	v.values[uint16(index)] = newVal

	// Update last entry with sum
	pp.Update(t.PP, v.V, m, v.sum, len(v.values))

	// Update the new digest
	pp.Update(t.PP, v.W, d, newDigest, index)
	v.Digests[uint16(index)] = newDigest

	return v
}

func (t *Tree) updateLayerAboveLeaves(node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex
	if node == nil {
		v = &Vertex{
			BlindingFactor: c.NewRandomZr(rand.Reader),
			sum:            c.NewZrFromInt(0),
			values:         make(map[uint16]*math.Zr),
			Digests:        make(map[uint16]*math.Zr),
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
		m = append(m, v.BlindingFactor)

		v.V = pp.Commit(t.PP, m)

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
	m := make(common.Vec, t.PP.N)
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
	pp.Update(t.PP, v.V, m, newVal, index)
	v.values[uint16(index)] = newVal

	// Update last entry with sum
	pp.Update(t.PP, v.V, m, v.sum, len(v.values))

	return v
}

func updateSum(sum, removed, added *math.Zr) *math.Zr {
	return c.ModAdd(sum, c.ModSub(added, removed, c.GroupOrder), c.GroupOrder)
}
