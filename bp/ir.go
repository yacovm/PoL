package bp

import (
	"crypto/sha256"
	"fmt"
	"pol/common"

	math "github.com/IBM/mathlib"
)

func IterativeVerify(pp *PP, prevV *math.G1, Δ [][3]*math.G1, vFinal *math.Zr) (common.Vec, *math.Zr, error) {
	n := len(pp.G)
	if !common.IsPowerOfTwo(uint16(n)) {
		panic(fmt.Sprintf("G Public Parameter should be a group vector of length that is power of two but its length is %d", n))
	}

	n /= 2

	G := common.G1v(pp.G)

	var xs []*math.Zr

	var finalV *math.G1

	for n > 0 {
		A, B, V := Δ[0][0], Δ[0][1], Δ[0][2]
		x := common.FieldElementFromBytes(appendVToChallenge(randomOracle(A, B, pp.Digest), prevV))

		Ax := A.Mul(x)
		Bx := B.Mul(invertZr(x))
		shouldBeV := Ax
		shouldBeV.Add(Bx)
		shouldBeV.Add(prevV)

		if !V.Equals(shouldBeV) {
			return nil, nil, fmt.Errorf("V != A^xB^{x^{-1}}V")
		}

		prevV = V

		xs = append(xs, x)
		Δ = Δ[1:]
		finalV = V
		G = G[:n].Add(G[n:].Mul(invertZr(x)))

		n /= 2
	}

	if !G[0].Mul(vFinal).Equals(finalV) {
		return nil, nil, fmt.Errorf("final equation check failed")
	}

	return xs, vFinal, nil

}

func IterativeReduce(pp *PP, v common.Vec, V *math.G1) ([][3]*math.G1, common.Vec, *math.Zr) {
	n := len(pp.G)
	if !common.IsPowerOfTwo(uint16(n)) {
		panic(fmt.Sprintf("G Public Parameter should be a group vector of length that is power of two but its length is %d", n))
	}

	n /= 2

	var Δ [][3]*math.G1
	var xs []*math.Zr
	G := common.G1v(pp.G)

	for n > 0 {
		GL, GR := G[:n], G[n:]
		vL, vR := v[:n], v[n:]
		A := GL.MulV(vR).Sum()
		B := GR.MulV(vL).Sum()
		x := common.FieldElementFromBytes(appendVToChallenge(randomOracle(A, B, pp.Digest), V))
		G = GL.Add(GR.Mul(invertZr(x)))
		v = vL.Add(vR.Mul(x))
		V = G.MulV(v).Sum()

		xs, Δ = append(xs, x), append(Δ, [3]*math.G1{A, B, V})
		n /= 2
	}

	// Sanity check: Ensure v is of size 1
	if len(v) != 1 {
		panic(fmt.Sprintf("final v is of length %d, not 1", len(v)))
	}

	return Δ, xs, v[0]
}

func invertZr(x *math.Zr) *math.Zr {
	xInverse := x.Copy()
	xInverse.InvModP(common.GroupOrder)
	return xInverse
}

func appendVToChallenge(x []byte, V *math.G1) []byte {
	h := sha256.New()
	h.Write(x)
	h.Write(V.Bytes())
	digest := h.Sum(nil)
	return digest
}
