package poe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"pol/bp"
	"pol/common"
	"pol/pp"

	math "github.com/IBM/mathlib"
)

var (
	c          = math.Curves[1]
	GroupOrder = c.GroupOrder
)

type PP struct {
	Digest         []byte
	G0, G1, H0, H1 *math.G1
	PP             *pp.PP
}

func NewPublicParams(n int) *PP {
	pp := &PP{
		PP: pp.NewPublicParams(n),
		G0: common.RandGenVec(1, "G0")[0],
		G1: common.RandGenVec(1, "G1")[0],
		H0: common.RandGenVec(1, "H0")[0],
		H1: common.RandGenVec(1, "H1")[0],
	}
	pp.setupDigest()

	return pp
}

func (pp *PP) setupDigest() {
	h := sha256.New()
	h.Write(pp.G0.Bytes())
	h.Write(pp.G1.Bytes())
	h.Write(pp.H0.Bytes())
	h.Write(pp.H1.Bytes())
	h.Write(pp.PP.Digest)
	pp.Digest = h.Sum(nil)
}

type Equalities struct {
	RO   func(U, V, W, A common.G1v, ppDigest []byte) (*math.Zr, *math.Zr, *math.Zr, *math.G1)
	PP   *PP
	V, W common.G1v
	I, J []int
}

// Prove proves equality of 'v[i]' and 'w[j]' for all indices in I,J.
// The last elements in every 'v' and 'w' should be blinding factors.
func (e *Equalities) Prove(v, w []common.Vec) *Proof {
	m := len(e.V)
	// Sanity checks for lengths
	e.validateInputLength(v, w, m)

	uk, ηk, vk := c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader)
}

func (e *Equalities) validateInputLength(v []common.Vec, w []common.Vec, m int) {
	if len(e.W) != m {
		panic(fmt.Sprintf("V is of size %d but W is of size %d", m, len(e.W)))
	}
	if len(v) != m {
		panic(fmt.Sprintf("V is of size %d but v is of size %d", m, len(v)))
	}
	if len(w) != m {
		panic(fmt.Sprintf("V is of size %d but w is of size %d", m, len(w)))
	}
}

type Equality struct {
	RO   func(gs common.G1v, integers []int, ppDigest []byte, n int) []*math.Zr
	PP   *PP
	V, W *math.G1
	I, J int
}

func RO(gs common.G1v, integers []int, ppDigest []byte, n int) []*math.Zr {
	h := sha256.New()
	for _, g := range gs {
		h.Write(g.Bytes())
	}

	for _, n := range integers {
		buff := make([]byte, 2)
		binary.BigEndian.PutUint16(buff, uint16(n))
		h.Write(buff)
	}

	h.Write(ppDigest)

	preDigest := h.Sum(nil)

	scalar := func(i uint16) *math.Zr {
		h = sha256.New()
		h.Write(preDigest)
		buff := make([]byte, 2)
		binary.BigEndian.PutUint16(buff, i)
		h.Write(buff)
		return common.FieldElementFromBytes(h.Sum(nil))
	}

	scalars := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		scalars[i] = scalar(uint16(i))
	}
	return scalars

}

type Proof struct {
	IPP *bp.InnerProductProof
	C   *math.Zr
	V   *math.G1
	W   *math.G1
	Ω   *math.G1
}

func (e *Equality) Verify(Υ *Proof) error {
	x := e.RO(common.G1v{e.V, e.W, Υ.V, Υ.W}, nil, e.PP.Digest, 1)[0]
	g := c.GenG1.Copy()

	ts := e.RO(common.G1v{e.V, e.W, Υ.V.Mul(x), Υ.W.Mul(x), g.Mul(Υ.C)}, []int{e.I, e.J}, e.PP.Digest, 2)
	t0 := ts[0]
	t1 := ts[1]

	VVx := Υ.V.Mul(x)
	VVx.Add(e.V)
	VVx = VVx.Mul(t0)

	WWx := Υ.W.Mul(x)
	WWx.Add(e.W)
	WWx = WWx.Mul(t1)

	r := common.G1v{VVx}.InnerProd(common.G2v{e.PP.PP.G2s[len(e.PP.PP.G2s)-1-e.I]})
	l := common.G1v{WWx}.InnerProd(common.G2v{e.PP.PP.G2s[len(e.PP.PP.G2s)-1-e.J]})

	numerator := r
	r.Mul(l)

	l = common.G1v{Υ.Ω}.InnerProd(common.G2v{c.GenG2.Copy()})
	r = common.G1v{e.PP.PP.G1s[0]}.InnerProd(common.G2v{e.PP.PP.G2s[len(e.PP.PP.G2s)-1]}).Exp(Υ.C.Mul(t0.Plus(t1)))
	l.Mul(r)

	denominator := l

	if !numerator.Equals(denominator) {
		return fmt.Errorf("PoE invalid")
	}

	return nil
}

// Prove proves equality of 'v[i]' and 'w[j]'.
// The last elements in 'v' and 'w' should be blinding factors.
func (e *Equality) Prove(v, w common.Vec) *Proof {
	// Sanity test, in case we're trying to prove something that is incorrect
	if !v[e.I].Equals(w[e.J]) {
		panic(fmt.Sprintf("v[%d] != w[%d]", e.I, e.J))
	}

	if len(v) != len(w) {
		panic("|v| != |w|")
	}

	n := len(v)

	u, η, ν := c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader)

	V := e.PP.PP.G1s[e.I].Mul(u)
	V.Add(e.PP.PP.G1s[n-1].Mul(ν))
	ΩV := e.PP.PP.G1s[len(e.PP.PP.G1s)-1-e.I].Mul(ν)

	W := e.PP.PP.G1s[e.J].Mul(u)
	W.Add(e.PP.PP.G1s[n-1].Mul(η))
	ΩW := e.PP.PP.G1s[len(e.PP.PP.G1s)-1-e.J].Mul(η)

	x := e.RO(common.G1v{e.V, e.W, V, W}, nil, e.PP.Digest, 1)[0]

	g := c.GenG1.Copy()

	c := v[e.I].Plus(u.Mul(x))

	ts := e.RO(common.G1v{e.V, e.W, V.Mul(x), W.Mul(x), g.Mul(c)}, []int{e.I, e.J}, e.PP.Digest, 2)
	t0 := ts[0]
	t1 := ts[1]

	_, ΩVpp := pp.Open(e.PP.PP, e.I, v)
	_, ΩWpp := pp.Open(e.PP.PP, e.J, w)

	ΩV = ΩV.Mul(x)
	ΩV.Add(ΩVpp)
	ΩV = ΩV.Mul(t0)

	ΩW = ΩW.Mul(x)
	ΩW.Add(ΩWpp)
	ΩW = ΩW.Mul(t1)

	Ω := ΩV
	Ω.Add(ΩW)

	return &Proof{
		Ω: Ω,
		V: V,
		W: W,
		C: c,
	}

}
