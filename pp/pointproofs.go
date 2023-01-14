package pp

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"pol/common"

	math "github.com/IBM/mathlib"
)

var (
	c          = math.Curves[1]
	GroupOrder = c.GroupOrder
)

type PP struct {
	Digest []byte
	N      int
	G1s    common.G1v
	G2s    common.G2v
	Gt     *math.Gt
}

func NewPublicParams(N int) *PP {
	α := c.NewRandomZr(rand.Reader)

	pp := &PP{N: N}

	g1 := c.GenG1.Copy()
	g2 := c.GenG2.Copy()

	g1α := func(i int) *math.G1 {
		return g1.Mul(α.PowMod(c.NewZrFromInt(int64(i))))
	}

	g2α := func(i int) *math.G2 {
		return g2.Mul(α.PowMod(c.NewZrFromInt(int64(i))))
	}

	for i := 1; i <= N; i++ {
		pp.G1s = append(pp.G1s, g1α(i))
	}

	// Artificially put the generator instead of g^{a^{N+1}}
	pp.G1s = append(pp.G1s, c.GenG1.Copy())

	for i := N + 2; i <= 2*N; i++ {
		pp.G1s = append(pp.G1s, g1α(i))
	}

	for i := 1; i <= N; i++ {
		pp.G2s = append(pp.G2s, g2α(i))
	}

	pp.Gt = c.GenGt.Exp(α.PowMod(c.NewZrFromInt(int64(N + 1))))

	pp.SetupDigest()

	return pp
}

func (pp *PP) Size() int {
	return len(pp.G1s.Bytes()) + len(pp.G2s.Bytes()) + len(pp.Gt.Bytes())
}

func (pp *PP) SetupDigest() {
	h := sha256.New()
	for i := 0; i < len(pp.G1s); i++ {
		h.Write(pp.G1s[i].Bytes())
	}
	for i := 0; i < len(pp.G2s); i++ {
		h.Write(pp.G2s[i].Bytes())
	}
	h.Write(pp.Gt.Bytes())
	pp.Digest = h.Sum(nil)
}

func Commit(pp *PP, m common.Vec) *math.G1 {
	if len(m) != pp.N {
		panic(fmt.Sprintf("message should be of size %d but is of size %d", pp.N, len(m)))
	}

	var powersOfAlpha common.G1v
	for i := 0; i < pp.N; i++ {
		powersOfAlpha = append(powersOfAlpha, pp.G1s[i])
	}

	return powersOfAlpha.MulV(m).Sum()
}

func Open(pp *PP, i int, m common.Vec) (mi *math.Zr, π *math.G1) {
	if i >= pp.N {
		panic(fmt.Sprintf("can only open an index in [0,%d]", pp.N-1))
	}

	shift := pp.N - i

	var elements common.G1v
	var exponents common.Vec
	for j := 1; j <= pp.N; j++ {
		if j == i+1 {
			continue
		}
		index := shift + j - 1
		elements = append(elements, pp.G1s[index])
		exponents = append(exponents, m[j-1])
	}

	π = elements.MulV(exponents).Sum()
	mi = m[i]

	return
}

func Verify(pp *PP, mi *math.Zr, π *math.G1, C *math.G1, i int) error {
	left := common.G1v{C}.InnerProd(common.G2v{pp.G2s[pp.N-i-1]})
	right := common.G1v{π}.InnerProd(common.G2v{c.GenG2})
	right.Mul(pp.Gt.Exp(mi))

	if left.Equals(right) {
		return nil
	}
	return fmt.Errorf("%v is not an element in index %d in %v", mi, i, C)
}

func Update(pp *PP, C *math.G1, m common.Vec, mi *math.Zr, i int) {
	prevG := pp.G1s[i].Mul(m[i])
	nextG := pp.G1s[i].Mul(mi)
	C.Sub(prevG)
	C.Add(nextG)
}

func Aggregate(pp *PP, commitments common.G1v, proofs []*math.G1, RO func(*PP, []*math.G1, int) *math.Zr) *math.G1 {
	if len(proofs) != len(commitments) {
		panic(fmt.Sprintf("cannot aggregate %d proofs corresponding to %d commitments", len(proofs), len(commitments)))
	}
	var π common.G1v

	for j := 0; j < len(proofs); j++ {
		π = append(π, proofs[j].Mul(RO(pp, commitments, j)))
	}

	return π.Sum()
}

func VerifyAggregation(pp *PP, indices []int, commitments common.G1v, π *math.G1, Σ *math.Zr, RO func(*PP, []*math.G1, int) *math.Zr) error {
	var exponents []*math.Zr
	for i := 0; i < len(indices); i++ {
		exponents = append(exponents, RO(pp, commitments, i))
	}

	var g2s common.G2v
	for _, i := range indices {
		g2s = append(g2s, pp.G2s[pp.N-i-1])
	}
	left := commitments.InnerProd(g2s.Mulv(exponents))

	πg2 := common.G1v{π}.InnerProd(common.G2v{c.GenG2})
	right := pp.Gt.Exp(Σ)
	right.Mul(πg2)

	if right.Equals(left) {
		return nil
	}

	return fmt.Errorf("invalid aggregation")
}

func RO(pp *PP, cs []*math.G1, i int) *math.Zr {
	h := sha256.New()
	h.Write(pp.Digest)
	h.Write([]byte{byte(i)})
	for j := 0; j < len(cs); j++ {
		h.Write(cs[j].Bytes())
	}
	digest := h.Sum(nil)
	result := common.FieldElementFromBytes(digest)
	return result
}
