package sparse

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"sync"
)

type Tree struct {
	ID2Path           func(string) []uint16
	UpdateInnerVertex func(node interface{}, descendants []interface{}, descendantsLeaves bool, indexChanged int) interface{}
	FanOut            int
	root              *Vertex
	lock              sync.RWMutex
	createRoot        sync.Once
}

func (t *Tree) Get(id string) (interface{}, bool) {
	path := t.ID2Path(id)
	t.lock.RLock()
	if t.root == nil {
		t.lock.RUnlock()
		return nil, false
	}
	t.lock.RUnlock()

	v := t.root
	var exists bool

	releaseLocks := make([]func(), 0, len(path))

	defer func() {
		for i := len(releaseLocks) - 1; i >= 0; i-- {
			releaseLocks[i]()
		}
	}()

	for _, p := range path {
		v.lock.RLock()
		releaseLocks = append(releaseLocks, v.lock.RUnlock)
		v, exists = v.Descendants[p]
		if !exists {
			return nil, false
		}
	}
	return v.Data, true
}

func (t *Tree) Put(id string, data interface{}) {
	path := t.ID2Path(id)

	t.createRoot.Do(func() {
		t.root = &Vertex{
			Descendants: make(map[uint16]*Vertex),
		}
	})

	v := t.createPath(path, t.root)

	v.Data = data
	v.lock.Lock()
	defer v.lock.Unlock()

	v = v.Parent
	descendantsLeaves := true
	i := len(path) - 1
	for v != nil {
		v.lock.Lock()

		unlockDescendants := func() {}
		if !descendantsLeaves {
			unlockDescendants = t.lockDescendants(v)
		}
		v.Data = t.UpdateInnerVertex(v.Data, v.rawData(t.FanOut), descendantsLeaves, int(path[i]))

		unlockDescendants()

		v.lock.Unlock()
		v = v.Parent
		descendantsLeaves = false
		i--
	}
}

func (t *Tree) lockDescendants(v *Vertex) func() {
	unlocks := make([]func(), 0, len(v.Descendants))
	for _, u := range v.Descendants {
		u.lock.Lock()
		unlocks = append(unlocks, u.lock.Unlock)
	}

	return func() {
		for _, unlock := range unlocks {
			unlock()
		}
	}
}

func (t *Tree) createPath(path []uint16, v *Vertex) *Vertex {
	for _, p := range path {
		v.createDescendants.Do(func() {
			v.Descendants = make(map[uint16]*Vertex, t.FanOut)
		})

		v.lock.RLock()
		if v.Descendants[p] == nil {
			v.lock.RUnlock()

			v.lock.Lock()
			if v.Descendants[p] == nil {
				v.Descendants[p] = &Vertex{
					Parent:      v,
					Descendants: make(map[uint16]*Vertex),
				}
			}
			v = v.Descendants[p]
			v.Parent.lock.Unlock()
		} else {
			v = v.Descendants[p]
			v.Parent.lock.RUnlock()
		}
	}
	return v
}

// Vertex defines a vertex of a graph
type Vertex struct {
	Data              interface{}
	Descendants       map[uint16]*Vertex
	Parent            *Vertex
	lock              sync.RWMutex
	createDescendants sync.Once
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
