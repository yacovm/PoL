package poe

import (
	"crypto/hmac"
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
	Digest []byte
	G, H   common.G1v
	F      *math.G1
	PP     *pp.PP
}

func (pp *PP) Size() int {
	return len(pp.G.Bytes()) + len(pp.H.Bytes()) + len(pp.F.Bytes()) + pp.PP.Size()
}

func NewPublicParams(n, m int) *PP {
	pp := &PP{
		PP: pp.NewPublicParams(n),
		G:  common.RandGenVec(m, "POE G"),
		H:  common.RandGenVec(m, "POE H"),
		F:  common.RandGenVec(1, "POE F")[0],
	}
	pp.SetupDigest()

	return pp
}

func (pp *PP) SetupDigest() {
	h := sha256.New()
	h.Write(pp.G.Bytes())
	h.Write(pp.H.Bytes())
	h.Write(pp.F.Bytes())
	h.Write(pp.PP.Digest)
	pp.Digest = h.Sum(nil)
}

type Equalities struct {
	RO   func(gs common.G1v, integers []int, ppDigest []byte, n int) common.Vec
	PP   *PP
	V, W common.G1v
	I, J []int
}

type AggregatedProof struct {
	IPP          *bp.InnerProductProof
	c, ρ         *math.Zr
	U, V, Ω      *math.G1
	Waggr, Vaggr common.G1v
}

func (ap *AggregatedProof) Size() int {
	return ap.IPP.Size() + len(ap.c.Bytes()) + len(ap.ρ.Bytes()) + len(ap.U.Bytes()) + len(ap.V.Bytes()) + len(ap.Ω.Bytes()) + len(ap.Waggr.Bytes()) + len(ap.Vaggr.Bytes())
}

func (e *Equalities) Verify(proof *AggregatedProof) error {
	var groupElements common.G1v
	groupElements = append(groupElements, proof.Vaggr...)
	groupElements = append(groupElements, proof.Waggr...)
	groupElements = append(groupElements, e.V...)
	groupElements = append(groupElements, e.W...)

	x := e.RO(groupElements, nil, e.PP.Digest, 1)[0]

	m := len(e.V)
	n := e.PP.PP.N

	groupElements = append(groupElements, proof.U)
	groupElements = append(groupElements, proof.V)

	ts := e.RO(groupElements, nil, e.PP.Digest, 2*m)

	g2sV := make(common.G2v, m)
	for k := 0; k < m; k++ {
		g2sV[k] = e.PP.PP.G2s[n-1-e.I[k]]
	}

	g2sW := make(common.G2v, m)
	for k := 0; k < m; k++ {
		g2sW[k] = e.PP.PP.G2s[n-1-e.J[k]]
	}

	numerator := e.V.Add(proof.Vaggr.Mul(x)).MulV(ts.Evens()).InnerProd(g2sV)
	numerator.Mul(e.W.Add(proof.Waggr.Mul(x)).MulV(ts.Odds()).InnerProd(g2sW))

	denominator := common.G1v{proof.Ω}.InnerProd(common.G2v{c.GenG2.Copy()})
	denominator.Mul(common.G1v{e.PP.PP.G1s[0].Mul(proof.c)}.InnerProd(common.G2v{e.PP.PP.G2s[len(e.PP.PP.G2s)-1]}))

	if !numerator.Equals(denominator) {
		return fmt.Errorf("PoE invalid: aggregation condition not satisfied")
	}

	b := ts.Evens().Add(ts.Odds())
	P := e.PP.F.Mul(proof.ρ)
	P.Add(proof.U.Mul(x))
	P.Add(proof.V)
	P.Add(e.PP.H.MulV(b).Sum())

	bpPP := &bp.PP{
		U: common.RandGenVec(1, "u")[0],
		G: e.PP.G,
		H: e.PP.H,
	}

	bpPP.RecomputeDigest()

	proof.IPP.C = proof.c
	proof.IPP.P = P

	return proof.IPP.Verify(bpPP)

}

// Prove proves equality of 'v[i]' and 'w[j]' for all indices in I,J.
// The last elements in every 'v' and 'w' should be blinding factors.
func (e *Equalities) Prove(vs, ws []common.Vec) *AggregatedProof {
	m := len(e.V)
	// Sanity checks for lengths
	e.validateInputLength(vs, ws, m)

	n := len(vs[0])

	Vaggr := make(common.G1v, m)
	Waggr := make(common.G1v, m)
	Ωv := make(common.G1v, m)
	Ωw := make(common.G1v, m)

	ΩvPP := make(common.G1v, m)
	ΩwPP := make(common.G1v, m)

	u := make(common.Vec, m)

	for k := 0; k < m; k++ {
		uk, ηk, νk := c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader)

		u[k] = uk

		Vk := e.PP.PP.G1s[e.I[k]].Mul(uk)
		Vk.Add(e.PP.PP.G1s[n-1].Mul(νk))
		Vaggr[k] = Vk

		ΩVk := e.PP.PP.G1s[len(e.PP.PP.G1s)-1-e.I[k]].Mul(νk)
		Ωv[k] = ΩVk

		Wk := e.PP.PP.G1s[e.J[k]].Mul(uk)
		Wk.Add(e.PP.PP.G1s[n-1].Mul(ηk))
		Waggr[k] = Wk
		ΩWk := e.PP.PP.G1s[len(e.PP.PP.G1s)-1-e.J[k]].Mul(ηk)
		Ωw[k] = ΩWk

		_, ΩVppk := pp.Open(e.PP.PP, e.I[k], vs[k])
		_, ΩWppk := pp.Open(e.PP.PP, e.J[k], ws[k])

		ΩvPP[k] = ΩVppk
		ΩwPP[k] = ΩWppk
	}

	var groupElements common.G1v
	groupElements = append(groupElements, Vaggr...)
	groupElements = append(groupElements, Waggr...)
	groupElements = append(groupElements, e.V...)
	groupElements = append(groupElements, e.W...)

	x := e.RO(groupElements, nil, e.PP.Digest, 1)[0]

	r1, r2 := c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader)

	v := make(common.Vec, m)
	for i := 0; i < m; i++ {
		v[i] = vs[i][e.I[i]]
	}

	U := e.PP.F.Mul(r1)
	U.Add(e.PP.G.MulV(u).Sum())

	V := e.PP.F.Mul(r2)
	V.Add(e.PP.G.MulV(v).Sum())

	groupElements = append(groupElements, U)
	groupElements = append(groupElements, V)

	ts := e.RO(groupElements, nil, e.PP.Digest, 2*m)

	Ω := ΩvPP.Add(Ωv.Mul(x)).MulV(ts.Evens()).Sum()
	Ω.Add(ΩwPP.Add(Ωw.Mul(x)).MulV(ts.Odds()).Sum())

	a := u.Mul(x).Add(v)
	b := ts.Evens().Add(ts.Odds())

	ρ := r1.Mul(x).Plus(r2)
	ρ = negZr(ρ)

	P := e.PP.F.Mul(ρ)
	P.Add(U.Mul(x))
	P.Add(V)
	P.Add(e.PP.H.MulV(b).Sum())

	bpPP := &bp.PP{
		U: common.RandGenVec(1, "u")[0],
		G: e.PP.G,
		H: e.PP.H,
	}
	bpPP.RecomputeDigest()

	ipa := bp.NewInnerProdArgument(bpPP, a, b)
	ipa.P = P

	ipp := ipa.Prove()

	return &AggregatedProof{
		IPP:   ipp,
		ρ:     ρ,
		V:     V,
		U:     U,
		Ω:     Ω,
		Vaggr: Vaggr,
		Waggr: Waggr,
		c:     ipp.C,
	}

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
	RO   func(gs common.G1v, integers []int, ppDigest []byte, n int) common.Vec
	PP   *PP
	V, W *math.G1
	I, J int
}

func RO(gs common.G1v, integers []int, ppDigest []byte, n int) common.Vec {
	h := hmac.New(sha256.New, compressParameters(gs, integers, ppDigest))
	scalar := func(i uint16) *math.Zr {
		buff := make([]byte, 2)
		binary.BigEndian.PutUint16(buff, i)
		h.Write(buff)
		digest := h.Sum(nil)
		h.Reset()

		result := common.FieldElementFromBytes(digest)
		result.Mod(GroupOrder)
		return result
	}

	scalars := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		scalars[i] = scalar(uint16(i))
	}
	return scalars

}

func negZr(x *math.Zr) *math.Zr {
	zero := c.NewZrFromInt(0)
	return c.ModSub(zero, x, c.GroupOrder)
}

func compressParameters(gs common.G1v, integers []int, ppDigest []byte) []byte {
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

	return h.Sum(nil)
}

type Proof struct {
	C *math.Zr
	V *math.G1
	W *math.G1
	Ω *math.G1
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
	numerator.Mul(l)

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
