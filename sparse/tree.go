package sparse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"pol/common"
	"strconv"
)

type Tree struct {
	ID2Path           func(string) []uint16
	UpdateInnerVertex func(node interface{}, descendants []interface{}, descendantsLeaves bool, indexChanged int) interface{}
	FanOut            int
	Root              *Vertex
}

func (t *Tree) Get(id string) (interface{}, []interface{}, bool) {
	path := t.ID2Path(id)
	if t.Root == nil {
		return nil, nil, false
	}

	var verticesAlongThePath []interface{}

	v := t.Root
	var exists bool
	for _, p := range path {
		verticesAlongThePath = append(verticesAlongThePath, v)
		v, exists = v.Descendants[p]
		if !exists {
			return nil, nil, false
		}
	}
	return v.Data, verticesAlongThePath, true
}

func (t *Tree) Put(id string, data interface{}) {
	path := t.ID2Path(id)

	if t.Root == nil {
		t.Root = &Vertex{
			Descendants: make(map[uint16]*Vertex),
		}
	}

	v := t.Root

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

func DigitPath(s string) []uint16 {
	if len(s) != 9 {
		panic(fmt.Sprintf("%s is not a 9 digit decimal number", s))
	}
	num, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		panic(fmt.Sprintf("%s is not a valid decimal number", s))
	}

	var res []uint16

	for num > 0 {
		res = append(res, uint16(num%7))
		num /= 7
	}

	if len(res) == 10 {
		res = append(res, 0)
	}

	return res
}

var (
	ExpectedHexPathLengthByFanOut = map[uint16]int{
		3:     162,
		7:     91,
		15:    66,
		31:    52,
		63:    43,
		127:   37,
		255:   32,
		511:   29,
		1023:  26,
		2047:  24,
		4095:  22,
		8191:  20,
		16383: 19,
	}
)

func HexId2PathForFanOut(fanout uint16) func(string) []uint16 {
	if !common.IsPowerOfTwo(fanout + 1) {
		panic(fmt.Sprintf("fanout %d+1 is not a power of two", fanout))
	}

	_, exists := ExpectedHexPathLengthByFanOut[fanout]
	if !exists {
		panic(fmt.Sprintf("a fanout of %d is not supported!", fanout))
	}

	return func(s string) []uint16 {
		expectedPathLen := ExpectedHexPathLengthByFanOut[fanout]

		for {
			path := convertPathWithFanout(s, fanout)
			if len(path) == expectedPathLen {
				return path
			}
			s = hash(s)
		}
	}
}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func convertPathWithFanout(s string, fanOut uint16) []uint16 {
	n, ok := big.NewInt(0).SetString(s, 16)
	if !ok {
		panic(fmt.Sprintf("failed parsing %s as a hexadecimal number", s))
	}

	var res []uint16

	fo := big.NewInt(int64(fanOut))

	for n.Cmp(big.NewInt(0)) != 0 {
		res = append(res, uint16(big.NewInt(0).Mod(n, fo).Int64()))
		n.Div(n, fo)
	}

	return res
}
