package bp

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"pol/common"

	math "github.com/IBM/mathlib"
)

type RangeProofPublicParams struct {
	G, H, F    *math.G1
	Gs, Hs, Fs common.G1v
	digest     []byte
}

func NewRangeProofPublicParams(n int) *RangeProofPublicParams {
	m := 63
	rppp := &RangeProofPublicParams{
		G:  common.RandGenVec(1, "range proof G")[0],
		H:  common.RandGenVec(1, "range proof H")[0],
		F:  common.RandGenVec(1, "range proof F")[0],
		Fs: common.RandGenVec(n*(m+1), "range proof Fs"),
		Hs: common.RandGenVec(n*(m+1), "range proof Hs"),
		Gs: common.RandGenVec(n, "range proof Gs"),
	}

	rppp.Digest()

	return rppp
}

func (rppp *RangeProofPublicParams) Size() int {
	return len(rppp.Gs.Bytes()) + len(rppp.Hs.Bytes()) + len(rppp.Fs.Bytes()) + len(rppp.G.Bytes()) + len(rppp.H.Bytes()) + len(rppp.F.Bytes())
}

func (rppp *RangeProofPublicParams) Digest() []byte {
	if len(rppp.digest) != 0 {
		return rppp.digest
	}

	h := sha256.New()
	h.Write(rppp.G.Bytes())
	h.Write(rppp.H.Bytes())
	h.Write(rppp.F.Bytes())
	h.Write(rppp.Gs.Bytes())
	h.Write(rppp.Hs.Bytes())
	h.Write(rppp.Fs.Bytes())
	digest := h.Sum(nil)
	rppp.digest = digest
	return digest
}

type RangeProof struct {
	Δ            [][3]*math.G1
	u            *math.Zr // Γ = (Δ, u)
	W            *math.G1
	γ            *math.Zr
	Π            *InnerProductProof
	c            *math.Zr
	Q, R, C1, C2 *math.G1
	τ, ρ         *math.Zr
}

func (rp *RangeProof) Size() int {
	size := len(rp.τ.Bytes()) + len(rp.ρ.Bytes()) + len(rp.Q.Bytes()) + len(rp.R.Bytes()) + len(rp.C1.Bytes()) + len(rp.C2.Bytes())
	size += len(rp.c.Bytes())
	size += rp.Π.Size()
	size += len(rp.γ.Bytes())
	size += len(rp.W.Bytes())
	size += len(rp.u.Bytes())
	for i := 0; i < len(rp.Δ); i++ {
		size += len(rp.Δ[i][0].Bytes())
		size += len(rp.Δ[i][1].Bytes())
		size += len(rp.Δ[i][2].Bytes())
	}
	return size
}

func VerifyRange(pp *RangeProofPublicParams, rp *RangeProof, V *math.G1) error {
	n := len(pp.Gs)

	x := rangeProofRO1(pp, V, rp.W)

	U := pp.F.Mul(rp.γ)
	U.Add(V)
	U.Add(rp.W.Mul(x))

	ppRdx := &PP{
		G: pp.Gs,
		U: common.RandGenVec(1, "U range proof")[0],
	}
	ppRdx.RecomputeDigest()

	xs, u, err := IterativeVerify(ppRdx, U, rp.Δ, rp.u)
	if err != nil {
		return fmt.Errorf("iterated reduction proof invalid: %v", err)
	}
	xs = xs.Reverse()

	f := make(common.Vec, n)
	for i := uint16(0); i < uint16(n); i++ {
		iBits := bitDecomposition(i, uint16(n)-1)
		f[i] = xs.PowBitVec(iBits).Product()
	}

	m := 63
	d := computeD(n, m, f, x)

	y0Digest := []byte{0}
	y1Digest := []byte{1}
	y0Digest = append(y0Digest, pp.Digest()...)
	y1Digest = append(y1Digest, pp.Digest()...)

	y0, y1 := common.FieldElementFromBytes(randomOracle(rp.Q, rp.R, y0Digest)), common.FieldElementFromBytes(randomOracle(rp.Q, rp.R, y1Digest))
	y0v, y1v := common.PowerSeries(n*m, y0), expand(common.IntToZr(1), n*m).Mul(y1)
	z := computeZ(pp, rp.C1, rp.C2, rp.Q, rp.R)

	y0Inverse := invertZr(y0)
	Fprime := pp.Fs.MulV(common.PowerSeries(len(pp.Fs), y0Inverse))

	ipaPP := &PP{
		U: common.RandGenVec(1, "u")[0],
		G: pp.Hs,
		H: Fprime,
	}
	ipaPP.G = pp.Hs
	ipaPP.H = Fprime
	ipaPP.RecomputeDigest()

	rp.Π.C = rp.c
	rp.Π.P = computeP(pp, rp.ρ, rp.Q, rp.R, z, y1v, n, m, Fprime, d, y1)
	if err := rp.Π.Verify(ipaPP); err != nil {
		return fmt.Errorf("inner product proof invalid: %v", err)
	}

	β1 := expand(common.IntToZr(1), n*m).InnerProd(y0v)
	β2 := expand(common.IntToZr(1), n*m).InnerProd(y0v)
	β3 := expand(common.IntToZr(1), n*m).InnerProd(d[:n*m])

	c0 := β3.Mul(y1.Mul(y1).Mul(y1)).Plus(y1.Mul(y1).Mul(u.Plus(β2))).Plus(β1.Mul(y1))

	left := rp.C1.Mul(z)
	left.Add(rp.C2.Mul(z.Mul(z)))
	left.Add(pp.G.Mul(c0))

	right := pp.G.Mul(rp.c)
	right.Add(pp.H.Mul(rp.τ))

	if !left.Equals(right) {
		return fmt.Errorf("invalid range proof")
	}

	return nil
}

func ProveRange(pp *RangeProofPublicParams, V *math.G1, v common.Vec, r *math.Zr) *RangeProof {
	n := len(pp.Gs)

	w, rPrime := common.RandVec(n), common.RandVec(1)[0]

	W := pp.F.Mul(rPrime)
	W.Add(pp.Gs.MulV(w).Sum())

	x := rangeProofRO1(pp, V, W)

	γ := common.NegZr(r.Plus(x.Mul(rPrime)))

	U := pp.F.Mul(γ)
	U.Add(V)
	U.Add(W.Mul(x))

	ppRdx := &PP{
		G: pp.Gs,
		U: common.RandGenVec(1, "U range proof")[0],
	}
	ppRdx.RecomputeDigest()

	wRdx := v.Add(w.Mul(x))
	Δ, xs, u := IterativeReduce(ppRdx, wRdx, U)
	xs = xs.Reverse()

	f := make(common.Vec, n)
	for i := uint16(0); i < uint16(n); i++ {
		iBits := bitDecomposition(i, uint16(n)-1)
		f[i] = xs.PowBitVec(iBits).Product()
	}

	m := 63
	d := computeD(n, m, f, x)

	vBits := common.IntsToZr(v.Bits(m))
	vBits = append(vBits, w...)

	wCaret := expand(common.IntToZr(1), n*m).Sub(vBits[:n*m])

	ν, η := common.RandVec(1)[0], common.RandVec(1)[0]

	Q := pp.F.Mul(ν)
	Q.Add(pp.Hs.MulV(vBits).Sum())
	Q.Add(pp.Fs[:n*m].MulV(wCaret).Sum())

	s, t := common.RandVec(n*m+n), common.RandVec(n*m)

	R := pp.F.Mul(η)
	R.Add(pp.Hs.MulV(s).Sum())
	R.Add(pp.Fs[:n*m].MulV(t).Sum())

	y0Digest := []byte{0}
	y1Digest := []byte{1}
	y0Digest = append(y0Digest, pp.Digest()...)
	y1Digest = append(y1Digest, pp.Digest()...)

	y0, y1 := common.FieldElementFromBytes(randomOracle(Q, R, y0Digest)), common.FieldElementFromBytes(randomOracle(Q, R, y1Digest))
	y0v, y1v := common.PowerSeries(n*m, y0), expand(common.IntToZr(1), n*m).Mul(y1)

	zeros := expand(common.IntToZr(0), n)
	aPrime := vBits.Add(y1v.Concat(zeros))
	bPrime := d.Mul(y1.Mul(y1)).Add(y0v.Concat(zeros).Mul(y1)).Add(wCaret.HadamardProd(y0v).Concat(zeros))
	c1 := aPrime[:n*m].InnerProd(y0v.HadamardProd(t))
	c1 = c1.Plus(s.InnerProd(bPrime))
	c2 := s[:n*m].InnerProd(y0v.HadamardProd(t))
	τ1, τ2 := common.RandVec(1)[0], common.RandVec(1)[0]
	C1, C2 := pp.G.Mul(c1), pp.G.Mul(c2)
	C1.Add(pp.H.Mul(τ1))
	C2.Add(pp.H.Mul(τ2))

	z := computeZ(pp, C1, C2, Q, R)

	ρ := common.NegZr(ν.Plus(η.Mul(z)))
	τ := τ1.Mul(z).Plus(τ2.Mul(z.Mul(z)))

	y0Inverse := invertZr(y0)
	Fprime := pp.Fs.MulV(common.PowerSeries(len(pp.Fs), y0Inverse))

	a, b := aPrime.Add(s.Mul(z)), bPrime.Add(y0v.HadamardProd(t).Concat(zeros).Mul(z))

	c := a.InnerProd(b)

	ipaPP := &PP{
		U: common.RandGenVec(1, "u")[0],
		G: pp.Hs,
		H: Fprime,
	}
	ipaPP.RecomputeDigest()

	ipa := NewInnerProdArgument(ipaPP, a, b)

	ipp := ipa.Prove()

	if err := ipp.Verify(ipaPP); err != nil {
		panic(err)
	}

	return &RangeProof{
		ρ:  ρ,
		τ:  τ,
		C1: C1,
		C2: C2,
		γ:  γ,
		c:  c,
		Δ:  Δ,
		u:  u,
		Q:  Q,
		R:  R,
		W:  W,
		Π:  ipp,
	}
}

func computeP(pp *RangeProofPublicParams, ρ *math.Zr, Q *math.G1, R *math.G1, z *math.Zr, y1v common.Vec, n int, m int, Fprime common.G1v, d common.Vec, y1 *math.Zr) *math.G1 {
	P := pp.F.Mul(ρ)
	P.Add(Q)
	P.Add(R.Mul(z))
	P.Add(pp.Hs[:n*m].MulV(y1v).Sum())
	P.Add(Fprime.MulV(d.Mul(y1.Mul(y1))).Sum())
	P.Add(pp.Fs[:n*m].MulV(y1v).Sum())

	return P
}

func computeZ(pp *RangeProofPublicParams, C1 *math.G1, C2 *math.G1, Q *math.G1, R *math.G1) *math.Zr {
	var C1C2Digest []byte
	C1C2Digest = append(C1C2Digest, pp.Digest()...)
	C1C2Digest = append(C1C2Digest, C1.Bytes()...)
	C1C2Digest = append(C1C2Digest, C2.Bytes()...)
	z := common.FieldElementFromBytes(randomOracle(Q, R, C1C2Digest))
	return z
}

func computeD(n int, m int, f common.Vec, x *math.Zr) common.Vec {
	var d common.Vec
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			d = append(d, common.Pow2(j).Mul(f[i]))
		}
	}

	d = append(d, f.Mul(x)...)
	return d
}

func expand(x *math.Zr, n int) common.Vec {
	res := make(common.Vec, n)
	for i := 0; i < n; i++ {
		res[i] = x
	}
	return res
}

func bitDecomposition(n, max uint16) []uint8 {
	bitNum := bits.Len16(max)
	result := make([]uint8, bitNum)
	var i int
	for n > 0 {
		result[i] = uint8(n & 1)
		n = n >> 1
		i++
	}

	return result
}

func rangeProofRO1(pp *RangeProofPublicParams, V *math.G1, W *math.G1) *math.Zr {
	h := sha256.New()
	h.Write(pp.Digest())
	h.Write(V.Bytes())
	h.Write(W.Bytes())
	digest := h.Sum(nil)
	return common.FieldElementFromBytes(digest)
}
