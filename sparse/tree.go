package sparse

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

	if len(t.root.Descendants) < t.FanOut {
		return nil, false
	}

	v := t.root
	for _, p := range path {
		v = v.Descendants[p]
		if v == nil {
			return nil, false
		}
	}
	return v.Data, true
}

func (t *Tree) Put(id string, data interface{}) {
	path := t.ID2Path(id)

	if t.root == nil {
		t.root = &Vertex{}
	}

	v := t.root

	for _, p := range path {
		if len(v.Descendants) == 0 {
			v.Descendants = make([]*Vertex, t.FanOut)
		}
		if v.Descendants[p] == nil {
			v.Descendants[p] = &Vertex{
				Parent: v,
			}
		}
		v = v.Descendants[p]
	}

	v.Data = data

	v = v.Parent

	descendantsLeaves := true
	i := len(path) - 1
	for v != nil {
		v.Data = t.UpdateInnerVertex(v.Data, v.RawData(), descendantsLeaves, int(path[i]))
		v = v.Parent
		descendantsLeaves = false
		i--
	}
}

// Vertex defines a vertex of a graph
type Vertex struct {
	Data        interface{}
	Descendants []*Vertex
	Parent      *Vertex
}

func (v *Vertex) AddDescendant(u *Vertex) {
	v.Descendants = append(v.Descendants, u)
}

func (v *Vertex) RawData() []interface{} {
	res := make([]interface{}, len(v.Descendants))
	for i := 0; i < len(res); i++ {
		if v.Descendants[i] == nil {
			res[i] = nil
			continue
		}
		res[i] = v.Descendants[i].Data
	}
	return res
}
