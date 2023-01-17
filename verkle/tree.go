package verkle

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"pol/common"
	"pol/pp"
	"pol/sparse"
	"pol/sum"

	math "github.com/IBM/mathlib"
)

var (
	c          = math.Curves[1]
	GroupOrder = c.GroupOrder
)

type DB interface {
	Get([]byte) []byte
	Put([]byte, []byte)
}

type Tree struct {
	DB    DB
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

type KV struct {
	K []byte
	V []byte
}

type RawVertex struct {
	BlindingFactor []byte
	Values         []KV
	Digests        []KV
	Sum            []byte
	V, W           []byte
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

func (v *Vertex) FromBytes(bytes []byte) {
	rv := &RawVertex{}
	if _, err := asn1.Unmarshal(bytes, rv); err != nil {
		panic(err)
	}

	var err error
	v.BlindingFactor = c.NewZrFromBytes(rv.BlindingFactor)
	v.sum = c.NewZrFromBytes(rv.Sum)

	v.V, err = c.NewG1FromBytes(rv.V)
	if err != nil {
		panic(err)
	}

	if len(rv.W) != 0 {
		v.W, err = c.NewG1FromBytes(rv.W)
		if err != nil {
			panic(err)
		}
	}

	v.Digests = make(map[uint16]*math.Zr)
	v.values = make(map[uint16]*math.Zr)

	for _, kv := range rv.Digests {
		v.Digests[binary.BigEndian.Uint16(kv.K)] = c.NewZrFromBytes(kv.V)
	}

	for _, kv := range rv.Values {
		v.values[binary.BigEndian.Uint16(kv.K)] = c.NewZrFromBytes(kv.V)
	}
}

func (v *Vertex) Bytes() []byte {
	var wBytes []byte
	if v.W != nil {
		wBytes = v.W.Bytes()
	}
	rv := RawVertex{
		V:              v.V.Bytes(),
		W:              wBytes,
		BlindingFactor: v.BlindingFactor.Bytes(),
		Sum:            v.sum.Bytes(),
	}

	for k, v := range v.Digests {
		kBuff := make([]byte, 2)
		binary.BigEndian.PutUint16(kBuff, k)
		rv.Digests = append(rv.Digests, KV{K: kBuff, V: v.Bytes()})
	}

	for k, v := range v.values {
		kBuff := make([]byte, 2)
		binary.BigEndian.PutUint16(kBuff, k)
		rv.Values = append(rv.Values, KV{K: kBuff, V: v.Bytes()})
	}

	bytes, err := asn1.Marshal(rv)
	if err != nil {
		panic(err)
	}

	return bytes
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

func NewVerkleTree(fanOut uint16, id2Path func(string) []uint16, db DB) *Tree {
	t := &Tree{
		DB: db,
		PP: pp.NewPublicParams(int(fanOut + 2)),
		Tree: &sparse.Tree{
			FanOut:  int(fanOut),
			ID2Path: id2Path,
		},
	}

	t.Tree.UpdateInnerVertex = t.updateInnerVertex
	return t

}

func (t *Tree) Serialize(out io.Writer) {
	t.Tree.Root.Serialize(out, "", func(data interface{}) []byte {
		_, isVertex := data.(*Vertex)
		if !isVertex {
			return nil
		}
		return data.(*Vertex).Bytes()
	})
}

func (t *Tree) Get(id string) (int64, []*Vertex, bool) {
	n, path, ok := t.Tree.Get(id)
	if !ok {
		return 0, nil, false
	}

	verticesAlongThePath := make([]*Vertex, len(path))
	for i := 0; i < len(verticesAlongThePath); i++ {
		key := path[i].(*sparse.Vertex).Data.(string)
		bytes := t.DB.Get([]byte(key))
		v := &Vertex{}
		v.FromBytes(bytes)
		verticesAlongThePath[i] = v
	}

	return n.(int64), verticesAlongThePath, true
}

func (t *Tree) Put(id string, data int64) {
	t.Tree.Put(id, data)
}

func (t *Tree) updateInnerVertex(key string, node interface{}, descendants []interface{}, descendantsLeaves bool, index int) interface{} {
	if descendantsLeaves {
		return t.updateLayerAboveLeaves(key, node, descendants, index)
	}
	return t.updateInnerLayer(key, node, descendants, index)
}

func (t *Tree) updateInnerLayer(key string, node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex

	defer func() {
		t.DB.Put([]byte(key), v.Bytes())
	}()

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

			descVertex := t.fetchVertex(desc)

			val := descVertex.sum
			v.sum = v.sum.Plus(val)
			v.values[uint16(i)] = val
			digest := descVertex.Digest()
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

		return key
	}

	v = t.fetchVertex(key)

	oldVal := v.values[uint16(index)]
	if oldVal == nil {
		oldVal = c.NewZrFromInt(0)
	}

	descVertex := t.fetchVertex(descendants[index])

	newVal := descVertex.sum
	newDigest := descVertex.Digest()
	v.Digests[uint16(index)] = newDigest

	//oldSumDec, _ := v.sum.Int()
	v.sum = updateSum(v.sum, oldVal, newVal)

	//newSumDec, _ := v.sum.Int()

	v.values[uint16(index)] = newVal

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
	m[len(m)-2] = v.sum

	// Artificially append the blinding factor
	m[len(m)-1] = v.BlindingFactor

	//pp.Update(t.PP, v.V, m, newVal, index)

	v.V = pp.Commit(t.PP, m)

	// Update last entry with sum
	//pp.Update(t.PP, v.V, m, v.sum, len(v.values))

	// Update the new digest
	v.W = pp.Commit(t.PP, d)
	//pp.Update(t.PP, v.W, d, newDigest, index)

	return key
}

func (t *Tree) fetchVertex(desc interface{}) *Vertex {
	k := desc.(string)
	bytes := t.DB.Get([]byte(k))
	if len(bytes) == 0 {
		panic(fmt.Sprintf("could not find %s in DB", k))
	}
	v := &Vertex{}
	v.FromBytes(bytes)
	return v
}

func (t *Tree) updateLayerAboveLeaves(key string, node interface{}, descendants []interface{}, index int) interface{} {
	var v *Vertex

	defer func() {
		defer func() {
			t.DB.Put([]byte(key), v.Bytes())
		}()
	}()

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

		return key
	}

	v = t.fetchVertex(key)

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

	return key
}

func updateSum(sum, removed, added *math.Zr) *math.Zr {
	return c.ModAdd(sum, c.ModSub(added, removed, c.GroupOrder), c.GroupOrder)
}
