package sum

import (
	"crypto/sha256"
	"pol/bp"
	"pol/common"

	math "github.com/IBM/mathlib"
)

var (
	curve      = math.Curves[1]
	GroupOrder = curve.GroupOrder
)

type PP struct {
	Digest []byte
	U      *math.G1
	Gs     common.G1v
	G, F   *math.G1
	H      common.G1v
	b      common.Vec
	B      *math.G1
}

func (pp *PP) Size() int {
	return len(pp.U.Bytes()) + len(pp.Gs.Bytes()) + len(pp.G.Bytes()) + len(pp.F.Bytes()) + len(pp.H.Bytes()) + len(pp.B.Bytes())
}

func NewPublicParams(n int) *PP {
	pp := &PP{
		Gs: common.RandGenVec(n, "sum argument Gs"),
		U:  common.RandGenVec(1, "IPA u")[0],
		G:  common.RandGenVec(1, "sum argument G")[0],
		F:  common.RandGenVec(1, "sum argument F")[0],
		H:  common.RandGenVec(n, "sum argument H"),
		b:  make([]*math.Zr, n),
	}

	for i := 0; i < n; i++ {
		pp.b[i] = curve.NewZrFromInt(1)
	}
	pp.b[n-1] = negZr(curve.NewZrFromInt(1))

	pp.B = pp.H.MulV(pp.b).Sum()

	h := sha256.New()
	for i := 0; i < n; i++ {
		h.Write(pp.H[i].Bytes())
	}
	h.Write(pp.B.Bytes())
	h.Write(pp.G.Bytes())
	h.Write(pp.F.Bytes())
	pp.Digest = h.Sum(nil)

	return pp
}

type Argument struct {
	V *math.G1
}

type Proof struct {
	W *math.G1
	c *math.Zr
	ρ *math.Zr
	π *bp.InnerProductProof
}

func NewAggregatedArgument(pp *PP, V common.G1v, v []common.Vec, r common.Vec) *Proof {
	t := createHVZKChallenge(V, len(v))

	vAggr := make(common.Vec, len(v[0]))
	for i := 0; i < len(v[0]); i++ {
		vi := make(common.Vec, len(v))
		for j := 0; j < len(v); j++ {
			vi[j] = v[j][i]
		}
		vAggr[i] = vi.InnerProd(t)
	}

	rAggr := r.InnerProd(t)

	VAggr := V.MulV(t).Sum()

	_, proof := NewArgument(pp, VAggr, vAggr, rAggr)
	return proof
}

func createHVZKChallenge(V common.G1v, m int) common.Vec {
	h := sha256.New()
	h.Write(V.Bytes())
	digest := h.Sum(nil)
	τ := common.FieldElementFromBytes(digest)

	t := make(common.Vec, m)
	nextT := curve.NewZrFromInt(1)
	for i := 0; i < m; i++ {
		t[i] = nextT
		nextT = nextT.Mul(τ)
	}
	return t
}

func (proof *Proof) Size() int {
	return len(proof.c.Bytes()) + len(proof.W.Bytes()) + len(proof.ρ.Bytes())
}

func (proof *Proof) VerifyAggregated(pp *PP, V common.G1v) error {
	t := createHVZKChallenge(V, len(V))
	VAggr := V.MulV(t).Sum()

	return proof.Verify(pp, &Argument{
		V: VAggr,
	})
}

func NewCommitment(pp *PP, v common.Vec, r *math.Zr) *Argument {
	G := pp.Gs
	V := pp.F.Mul(r)
	V.Add(G.MulV(v).Sum())

	// Sanity check of the sum argument
	sum := v[0].Copy()
	n := len(v)
	for i := 1; i < n-1; i++ {
		sum = sum.Plus(v[i])
	}

	if !v[n-1].Equals(sum) {
		panic("v[n-1] != Σv[j] j: 0->n-2")
	}

	return &Argument{V: V}
}

func NewArgument(pp *PP, V *math.G1, v common.Vec, r *math.Zr) (*Argument, *Proof) {
	n := len(v)

	w, rPrime := common.RandVec(n), common.RandVec(1)[0]

	W := pp.F.Mul(rPrime)
	W.Add(pp.Gs.MulV(w).Sum())

	c := w.InnerProd(pp.b)

	x := randomOracleCVW(c, V, W)

	rPrimeX := rPrime.Mul(x)

	ρNeg := r.Plus(rPrimeX)
	ρ := negZr(ρNeg)

	P := pp.F.Mul(ρ)
	P.Add(V)
	P.Add(W.Mul(x))
	P.Add(pp.B)

	ipaPP := &bp.PP{
		G: pp.Gs,
		H: pp.H,
		U: pp.U,
	}

	ipaPP.RecomputeDigest()

	a := v.Add(w.Mul(x))
	b := pp.b

	π := bp.NewInnerProdArgument(ipaPP, a, b).Prove()

	return &Argument{V: V}, &Proof{π: π, W: W, c: c, ρ: ρ}
}

func randomOracleCVW(c *math.Zr, V *math.G1, W *math.G1) *math.Zr {
	h := sha256.New()
	h.Write(c.Bytes())
	h.Write(V.Bytes())
	h.Write(W.Bytes())
	cVW := h.Sum(nil)
	x := common.FieldElementFromBytes(cVW)
	return x
}

func (proof *Proof) Verify(pp *PP, a *Argument) error {
	x := randomOracleCVW(proof.c, a.V, proof.W)

	P := pp.F.Mul(proof.ρ)
	P.Add(a.V)
	P.Add(proof.W.Mul(x))
	P.Add(pp.B)

	ipaPP := &bp.PP{
		G: pp.Gs,
		H: pp.H,
		U: pp.U,
	}

	ipaPP.RecomputeDigest()

	proof.π.C = proof.c.Mul(x)
	proof.π.P = P
	return proof.π.Verify(ipaPP)
}

func negZr(x *math.Zr) *math.Zr {
	zero := curve.NewZrFromInt(0)
	return curve.ModSub(zero, x, curve.GroupOrder)
}
