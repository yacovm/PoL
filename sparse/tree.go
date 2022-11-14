package sparse

import (
	"encoding/hex"
	"fmt"
	"math/bits"
)

type Tree struct {
	ID2Path           func(string) []uint16
	UpdateInnerVertex func(node interface{}, descendants []interface{}, descendantsLeaves bool, indexChanged int) interface{}
	FanOut            int
	root              *Vertex
}

func (t *Tree) Get(id string) (interface{}, bool) {
	path := t.ID2Path(id)
	if t.root == nil {
		return nil, false
	}

	v := t.root
	var exists bool
	for _, p := range path {
		v, exists = v.Descendants[p]
		if !exists {
			return nil, false
		}
	}
	return v.Data, true
}

func (t *Tree) Put(id string, data interface{}) {
	path := t.ID2Path(id)

	if t.root == nil {
		t.root = &Vertex{
			Descendants: make(map[uint16]*Vertex),
		}
	}

	v := t.root

	for _, p := range path {
		if len(v.Descendants) == 0 {
			v.Descendants = make(map[uint16]*Vertex, t.FanOut)
		}
		if v.Descendants[p] == nil {
			v.Descendants[p] = &Vertex{
				Parent:      v,
				Descendants: make(map[uint16]*Vertex),
			}
		}
		v = v.Descendants[p]
	}

	v.Data = data

	v = v.Parent

	descendantsLeaves := true
	i := len(path) - 1
	for v != nil {
		v.Data = t.UpdateInnerVertex(v.Data, v.rawData(t.FanOut), descendantsLeaves, int(path[i]))
		v = v.Parent
		descendantsLeaves = false
		i--
	}
}

// Vertex defines a vertex of a graph
type Vertex struct {
	Data        interface{}
	Descendants map[uint16]*Vertex
	Parent      *Vertex
}

func (v *Vertex) AddDescendant(u *Vertex, at uint16) {
	v.Descendants[at] = u
}

func (v *Vertex) rawData(size int) []interface{} {
	res := make([]interface{}, size)
	for at, u := range v.Descendants {
		res[at] = u.Data
	}
	return res
}

func byteArrayToBitArray(in []byte) []byte {
	var out []byte

	for len(in) > 0 {
		firstByte := in[0]
		in = in[1:]

		var c int

		for firstByte > 0 {
			out = append(out, firstByte&1)
			firstByte = firstByte >> 1
			c++
		}

		// Pad with zeroes to fill a 8 sized slice
		for c < 8 {
			out = append(out, 0)
			c++
		}
	}

	return out
}

func HexId2PathForFanout(fanout uint16) func(string) []uint16 {
	bitLen := bits.Len16(fanout) - 1

	return func(s string) []uint16 {
		bytes, err := hex.DecodeString(s)
		if err != nil {
			panic(fmt.Sprintf("%s is not a hexadecimal string", s))
		}

		b := byteArrayToBitArray(bytes)

		// Pad with zeros to ensure 'b' is a multiple of bitLen
		for len(b)%bitLen != 0 {
			b = append(b, 0)
		}

		var res []uint16
		for len(b) > 0 {
			var sum uint16
			for i := 0; i < bitLen; i++ {
				sum += uint16(b[0]) * (uint16(1) << i)
				b = b[1:]
			}
			res = append(res, sum)

		}

		return res
	}
}
