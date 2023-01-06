package bp

import (
	"crypto/sha256"
	"math/bits"
	"pol/common"

	math "github.com/IBM/mathlib"
)

type RangeProofPublicParams struct {
	G, H, F    *math.G1
	Gs, Hs, Fs common.G1v
	digest     []byte
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

func ProveRange(pp *RangeProofPublicParams, V *math.G1, v common.Vec, r *math.Zr) *RangeProof {
	n := len(pp.Gs)

	w, rPrime := common.RandVec(n), common.RandVec(1)[0]

	W := pp.F.Mul(rPrime)
	W.Add(pp.Gs.MulV(w).Sum())

	x := rangeProofRO1(pp, V, W)

	γ := r
	γ.Plus(x.Mul(rPrime))
	γ = common.NegZr(γ)

	U := pp.F.Mul(γ)
	U.Add(V)
	U.Add(W.Mul(x))

	ppRdx := &PP{
		G: pp.Gs,
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

	m := 256

	vBits := v.BitsBigEndian(256)
	vBits = append(vBits, w.BitsBigEndian(256)...)

	var d common.Vec
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			d = append(d, common.Pow2(j).Mul(f[i]))
		}
	}

	d = append(d, f.Mul(x)...)

	wCaret := expand(common.IntToZr(1), n*m).Sub(common.IntsToZr(vBits[:n*m]))

	ν, η := common.RandVec(1)[0], common.RandVec(1)[0]

	Q := pp.F.Mul(ν)
	Q.Add(pp.Hs.MulV(common.IntsToZr(vBits)).Sum())
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
	y0v, y1v := common.PowerSeries(n*m-1, y0), expand(common.IntToZr(1), n*m-1).Mul(y1)
	zeros := expand(common.IntToZr(0), n)
	aPrime := common.IntsToZr(vBits).Sub(y1v.Concat(zeros))
	bPrime := d.Mul(y1.Mul(y1)).Add(y0v.Concat(zeros).Mul(y1)).Add(wCaret.HadamardProd(y0v).Concat(zeros))
	c1 := aPrime[:n*m].InnerProd(y0v.HadamardProd(t))
	c2 := s[:n*m].InnerProd(y0v.HadamardProd(t))
	τ1, τ2 := common.RandVec(1)[0], common.RandVec(1)[0]
	C1, C2 := pp.G.Mul(c1), pp.G.Mul(c2)
	C1.Add(pp.H.Mul(τ1))
	C2.Add(pp.H.Mul(τ2))
	var C1C2Digest []byte
	C1C2Digest = append(C1C2Digest, pp.Digest()...)
	C1C2Digest = append(C1C2Digest, C1.Bytes()...)
	C1C2Digest = append(C1C2Digest, C2.Bytes()...)
	z := common.FieldElementFromBytes(randomOracle(Q, R, C1C2Digest))
	ρ := common.NegZr(ν.Plus(η.Mul(z)))
	τ := τ1.Mul(z).Plus(τ2.Mul(z.Mul(z)))

	y0Inverse := invertZr(y0)
	Fprime := pp.Fs.MulV(common.PowerSeries(len(pp.Fs), y0Inverse))

	a, b := aPrime.Add(s.Mul(z)), bPrime.Add(y0v.HadamardProd(t).Concat(zeros).Mul(z))

	P := pp.F.Mul(ρ)
	P.Add(Q)
	P.Add(R.Mul(z))
	minusOnes := expand(common.IntToZr(-1), len(y1v))
	P.Add(pp.Hs[:n*m].MulV(y1v.HadamardProd(minusOnes)).Sum())
	P.Add(Fprime.MulV(d.Mul(y1.Mul(y1))).Sum())
	P.Add(pp.Fs[:n*m].MulV(y1v).Sum())
	c := a.InnerProd(b)
	ipaPP := NewPublicParams(len(a))
	ipa := NewInnerProdArgument(ipaPP, a, b)
	ipp := ipa.Prove()

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
		result[bitNum-1-i] = uint8(n & 1)
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
