package poe

import (
	"crypto/rand"
	"crypto/sha256"
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

type Equality struct {
	RO   func(U, V, W, A *math.G1, ppDigest []byte) (*math.Zr, *math.Zr, *math.Zr, *math.G1)
	PP   *PP
	V, W *math.G1
	I, J int
}

func RO(U, V, W, A *math.G1, ppDigest []byte) (*math.Zr, *math.Zr, *math.Zr, *math.G1) {
	h := sha256.New()
	h.Write(U.Bytes())
	h.Write(V.Bytes())
	h.Write(A.Bytes())
	h.Write(W.Bytes())
	h.Write(ppDigest)
	preDigest := h.Sum(nil)

	scalar := func(i uint8) *math.Zr {
		h = sha256.New()
		h.Write(preDigest)
		h.Write([]byte{i})
		return common.FieldElementFromBytes(h.Sum(nil))
	}

	group := func() *math.G1 {
		h = sha256.New()
		h.Write(preDigest)
		h.Write([]byte("G"))
		return common.HashToG1(h.Sum(nil))
	}

	return scalar(0), scalar(1), scalar(2), group()

}

type Proof struct {
	IPP *bp.InnerProductProof
	A   *math.G1
	C   *math.Zr
	U   *math.G1
	Ω   *math.G1
}

func (e *Equality) Verify(Υ *Proof) error {
	U := Υ.U
	A := Υ.A

	θ0, θ1, θ2, IPA_U := e.RO(U, e.V, e.W, A, e.PP.Digest)
	θ12 := θ1.Plus(θ2)

	B := common.G1v{e.PP.H0, e.PP.H1}.MulV(common.Vec{θ0, θ12}).Sum()

	// Prepare IPA verification statement
	P := A.Copy()
	P.Add(B)

	// Overwrite P,c in IPP anyway, do not trust what is there from the prover
	Υ.IPP.P = P
	Υ.IPP.C = Υ.C

	if err := Υ.IPP.Verify(&bp.PP{
		G: []*math.G1{e.PP.G0, e.PP.G1},
		H: []*math.G1{e.PP.H0, e.PP.H1},
		U: IPA_U,
	}); err != nil {
		return err
	}

	θ := []*math.Zr{θ0, θ1, θ2}
	ro := func(_ *pp.PP, _ []*math.G1, i int) *math.Zr {
		return θ[i]
	}

	if err := pp.VerifyAggregation(e.PP.PP, []int{0, e.I, e.J}, common.G1v{U, e.V, e.W}, Υ.Ω, Υ.C, ro); err != nil {
		return err
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

	t := c.NewRandomZr(rand.Reader)

	u := make(common.Vec, len(v))
	for i := 1; i < len(u); i++ {
		u[i] = c.NewZrFromInt(0)
	}
	u[0] = c.NewRandomZr(rand.Reader)
	u[len(u)-1] = t

	U := pp.Commit(e.PP.PP, u)

	_, ΩU := pp.Open(e.PP.PP, 0, u)
	_, ΩV := pp.Open(e.PP.PP, e.I, v)
	_, ΩW := pp.Open(e.PP.PP, e.J, w)

	A := common.G1v{e.PP.G0, e.PP.G1}.MulV(common.Vec{u[0], v[e.I]}).Sum()

	θ0, θ1, θ2, IPA_U := e.RO(U, e.V, e.W, A, e.PP.Digest)
	θ12 := θ1.Plus(θ2)

	Ω := common.G1v{ΩU, ΩV, ΩW}.MulV(common.Vec{θ0, θ1, θ2}).Sum()

	c := common.Vec{u[0], v[e.I]}.InnerProd(common.Vec{θ0, θ12})

	ipa := bp.NewInnerProdArgument(&bp.PP{
		G: []*math.G1{e.PP.G0, e.PP.G1},
		H: []*math.G1{e.PP.H0, e.PP.H1},
		U: IPA_U,
	}, common.Vec{u[0], v[e.I]}, common.Vec{θ0, θ12})

	Π := ipa.Prove()

	return &Proof{
		U:   U,
		A:   A,
		C:   c,
		IPP: Π,
		Ω:   Ω,
	}

}
