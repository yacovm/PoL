package bp

import (
	"crypto/sha256"
	"fmt"
	"pol/common"

	math "github.com/IBM/mathlib"
)

type PP struct {
	Digest []byte
	G      common.G1v
	H      common.G1v
	U      *math.G1
}

func NewPublicParams(n int) *PP {
	pp := &PP{
		G: common.RandGenVec(n, "g"),
		H: common.RandGenVec(n, "h"),
		U: common.RandGenVec(1, "u")[0],
	}

	pp.setupDigest()

	return pp
}

func (pp *PP) Size() int {
	return len(pp.G.Bytes()) + len(pp.H.Bytes()) + len(pp.U.Bytes())
}

func (pp *PP) setupDigest() {
	h := sha256.New()
	h.Write(pp.U.Bytes())
	for i := 0; i < len(pp.G); i++ {
		h.Write(pp.G[i].Bytes())
		if len(pp.H) > 0 {
			h.Write(pp.H[i].Bytes())
		}
	}
	pp.Digest = h.Sum(nil)
}

func (pp *PP) RecomputeDigest() {
	pp.setupDigest()
}

type InnerProdArgument struct {
	pp   *PP
	a, b common.Vec
	C    *math.Zr
	P    *math.G1
}

type InnerProductProof struct {
	LRs  []*math.G1
	a, b *math.Zr
	P    *math.G1
	C    *math.Zr
}

func (ipp *InnerProductProof) Size() int {
	return len(common.G1v(ipp.LRs).Bytes()) + len(ipp.a.Bytes()) + len(ipp.b.Bytes()) + len(ipp.P.Bytes()) + len(ipp.C.Bytes())
}

func NewInnerProdArgument(pp *PP, a, b common.Vec) *InnerProdArgument {
	ipa := &InnerProdArgument{
		C:  a.InnerProd(b),
		pp: pp,
		P:  commit(pp, a, b, nil),
		a:  a,
		b:  b,
	}

	return ipa
}

func commit(pp *PP, a, b common.Vec, u *math.G1) *math.G1 {
	if len(a) != len(b) {
		panic(fmt.Sprintf("vector a is of length %d but vector b is of length %d", len(a), len(b)))
	}

	gAcc := pp.G[0].Mul(a[0])
	hAcc := pp.H[0].Mul(b[0])

	for i := 1; i < len(a); i++ {
		gAcc.Add(pp.G[i].Mul(a[i]))
		hAcc.Add(pp.H[i].Mul(b[i]))
	}

	gAcc.Add(hAcc)

	if u != nil {
		gAcc.Add(pp.U.Mul(a.InnerProd(b)))
	}

	return gAcc
}

func computeInstanceSpecificParams(pp *PP, P *math.G1, c *math.Zr) (*PP, *math.G1) {
	var newPP PP
	newPP = *pp
	var hashPreImage []byte
	hashPreImage = append(hashPreImage, P.Bytes()...)
	hashPreImage = append(pp.Digest)

	x := common.FieldElementFromBytes(common.SHA256Digest(string(hashPreImage)))

	P = P.Copy()
	P.Add(pp.U.Mul(x.Mul(c)))

	newPP.U = newPP.U.Mul(x)
	newPP.RecomputeDigest()
	return &newPP, P
}

func (ipa *InnerProdArgument) Prove() *InnerProductProof {
	// We substitute the 'u' and P by applying the verifier's challenge
	// as per protocol 1.
	pp, P := computeInstanceSpecificParams(ipa.pp, ipa.P, ipa.C)
	// Next, we run protocol 2.
	LRs, ab := prove(pp, ipa.a, ipa.b, P, ipa.pp.G, ipa.pp.H)
	return &InnerProductProof{
		C:   ipa.C,
		P:   ipa.P,
		LRs: LRs,
		a:   ab[0],
		b:   ab[1],
	}
}

func (ipp *InnerProductProof) Verify(pp *PP) error {
	pp, P := computeInstanceSpecificParams(pp, ipp.P, ipp.C)
	return verify(pp, P, pp.G, pp.H, ipp.LRs, ipp.a, ipp.b)
}

// verify implements the verifier's side in protocol 2.
func verify(pp *PP, P *math.G1, g, h common.G1v, LRs []*math.G1, a *math.Zr, b *math.Zr) error {
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

	return verify(pp, P, g, h, LRs, a, b)
}

// prove implements the prover's side in protocol 2.
// Returns an array of (L,R) pairs of type *math.G1 and a single (a,b) of type *math.Zr
func prove(pp *PP, a, b common.Vec, P *math.G1, g, h common.G1v) ([]*math.G1, []*math.Zr) {
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

	LRs, abs := prove(pp, a, b, P, g, h)

	var res []*math.G1
	res = append([]*math.G1{L, R}, LRs...)
	return res, abs
}

type nextParams struct {
	x, xInverse *math.Zr
	g, h        common.G1v
	P           *math.G1
}

func computeNextParams(L *math.G1, R *math.G1, pp *PP, g common.G1v, h common.G1v, P *math.G1) nextParams {
	n := len(g) / 2

	digest := randomOracle(L, R, pp.Digest)
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

func randomOracle(L *math.G1, R *math.G1, x []byte) []byte {
	h := sha256.New()
	h.Write(L.Bytes())
	h.Write(R.Bytes())
	h.Write(x)
	digest := h.Sum(nil)
	return digest
}
