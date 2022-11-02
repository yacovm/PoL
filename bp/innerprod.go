package bp

import (
	"crypto/sha256"
	"fmt"
	math "github.com/IBM/mathlib"
	"pol/common"
)

type InnerProdArgument struct {
	pp   *common.PP
	a, b common.Vec
	P    *math.G1
}

type InnerProductProof struct {
	LRs  []*math.G1
	a, b *math.Zr
	P    *math.G1
}

func NewInnerProdArgument(pp *common.PP, a, b common.Vec) *InnerProdArgument {
	ipa := &InnerProdArgument{
		pp: pp,
		P:  common.Commit(pp, a, b),
		a:  a,
		b:  b,
	}

	return ipa
}

func (ipa *InnerProdArgument) Prove() *InnerProductProof {
	LRs, ab := ipa.prove(ipa.a, ipa.b, ipa.P, ipa.pp.G, ipa.pp.H)
	return &InnerProductProof{
		P:   ipa.P,
		LRs: LRs,
		a:   ab[0],
		b:   ab[1],
	}
}

func (ipp *InnerProductProof) Verify(pp *common.PP) error {
	return ipp.verify(pp, ipp.P, pp.G, pp.H, ipp.LRs, ipp.a, ipp.b)
}

func (ipp *InnerProductProof) verify(pp *common.PP, P *math.G1, g, h common.G1v, LRs []*math.G1, a *math.Zr, b *math.Zr) error {
	if len(g) == 1 {
		expectedP := pp.U.Mul(a.Mul(b))
		expectedP.Add(g[0].Mul(a))
		expectedP.Add(h[0].Mul(b))

		if !expectedP.Equals(P) {
			return fmt.Errorf("P != g^a*h^b*u^c")
		}
		return nil
	}

	L := LRs[0]
	R := LRs[1]
	LRs = LRs[2:]

	nextParams := computeNextParams(L, R, pp, g, h, P)

	g = nextParams.g
	h = nextParams.h
	P = nextParams.P

	return ipp.verify(pp, P, g, h, LRs, a, b)

}

// Returns an array of (L,R) pairs of type *math.G1 and a single (a,b) of type *math.Zr
func (ipa *InnerProdArgument) prove(a, b common.Vec, P *math.G1, g, h common.G1v) ([]*math.G1, []*math.Zr) {
	pp := ipa.pp

	if len(g) != len(h) {
		panic(fmt.Sprintf("g is of length %d but h is of length %d", len(g), len(h)))
	}

	if len(g) == 1 {
		return nil, []*math.Zr{a[0], b[0]}
	}

	n := len(g) / 2
	cL := a[:n].InnerProd(b[n:])
	cR := a[n:].InnerProd(b[:n])

	Lg := a[:n].Exp(g[n:])
	Lh := b[n:].Exp(h[:n])
	L := Lg
	L.Add(Lh)
	L.Add(pp.U.Mul(cL))

	Rg := a[n:].Exp(g[:n])
	Rh := b[:n].Exp(h[n:])
	R := Rg
	R.Add(Rh)
	R.Add(pp.U.Mul(cR))

	nextParams := computeNextParams(L, R, pp, g, h, P)

	x := nextParams.x
	xInverse := nextParams.xInverse
	P = nextParams.P
	g = nextParams.g
	h = nextParams.h

	a = a[:n].Mul(x).Add(a[n:].Mul(xInverse))
	b = b[:n].Mul(xInverse).Add(b[n:].Mul(x))

	LRs, abs := ipa.prove(a, b, P, g, h)

	var res []*math.G1
	res = append([]*math.G1{L, R}, LRs...)
	return res, abs
}

type nextParams struct {
	x, xInverse *math.Zr
	g, h        common.G1v
	P           *math.G1
}

func computeNextParams(L *math.G1, R *math.G1, pp *common.PP, g common.G1v, h common.G1v, P *math.G1) nextParams {
	n := len(g) / 2

	digest := randomOracle(L, R, pp)
	x := common.FieldElementFromBytes(digest)
	xInverse := x.Copy()
	xInverse.InvModP(common.GroupOrder)

	nextG := g[:n].Mul(xInverse).HadamardProd(g[n:].Mul(x))
	nextH := h[:n].Mul(x).HadamardProd(h[n:].Mul(xInverse))

	xSquare := x.Mul(x)
	xSquareInv := xSquare.Copy()
	xSquareInv.InvModP(common.GroupOrder)

	L2 := L.Mul(xSquare)
	R2 := R.Mul(xSquareInv)
	nextP := L2.Copy()
	nextP.Add(P)
	nextP.Add(R2)

	return nextParams{
		x:        x,
		xInverse: xInverse,
		g:        nextG,
		h:        nextH,
		P:        nextP,
	}
}

func randomOracle(L *math.G1, R *math.G1, pp *common.PP) []byte {
	h := sha256.New()
	h.Write(L.Bytes())
	h.Write(R.Bytes())
	h.Write(pp.Digest)
	digest := h.Sum(nil)
	return digest
}
