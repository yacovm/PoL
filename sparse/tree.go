package sparse

type Tree struct {
	ID2Path           func(string) []uint8
	UpdateInnerVertex func(node interface{}, descendants []interface{}) interface{}
	FanOut            int
	Root              *Vertex
}

func (t *Tree) Get(id string) (interface{}, bool) {
	path := t.ID2Path(id)
	if t.Root == nil {
		return nil, false
	}

	if len(t.Root.Descendants) < t.FanOut {
		return nil, false
	}

	v := t.Root
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

	if t.Root == nil {
		t.Root = &Vertex{}
	}

	v := t.Root

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

	for v != nil {
		v.Data = t.UpdateInnerVertex(v.Data, v.RawData())
		v = v.Parent
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
