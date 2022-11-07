package pp

import (
	"crypto/rand"
	"crypto/sha256"
	"pol/common"
	"testing"

	math "github.com/IBM/mathlib"

	"github.com/stretchr/testify/assert"
)

func TestPointProofCommitment(t *testing.T) {
	N := 8
	pp := NewPublicParams(N)

	var m common.Vec
	for i := 0; i < N; i++ {
		m = append(m, c.NewRandomZr(rand.Reader))
	}

	C := Commit(pp, m)

	for i := 0; i < pp.N; i++ {
		mi, π := Open(pp, i, m)
		err := Verify(pp, mi, π, C, i)
		assert.NoError(t, err)
	}
}

func TestAggregation(t *testing.T) {
	N := 8
	pp := NewPublicParams(N)

	var m1 common.Vec
	var m2 common.Vec
	for i := 0; i < N; i++ {
		m1 = append(m1, c.NewRandomZr(rand.Reader))
		m2 = append(m2, c.NewRandomZr(rand.Reader))
	}

	C1 := Commit(pp, m1)
	C2 := Commit(pp, m2)

	for i := 0; i < 1; i++ {
		m1, π1 := Open(pp, i, m1)
		err := Verify(pp, m1, π1, C1, i)
		assert.NoError(t, err)

		m2, π2 := Open(pp, i, m2)
		err = Verify(pp, m2, π2, C2, i)
		assert.NoError(t, err)

		commitments := common.G1v{C1, C2}
		π := Aggregate(pp, commitments, []*math.G1{π1, π2}, RO)

		Σ := common.Vec{m1, m2}.InnerProd(common.Vec{RO(pp, commitments, 0), RO(pp, commitments, 1)})

		err = VerifyAggregation(pp, []int{i, i}, commitments, π, Σ, RO)
		assert.NoError(t, err)
	}
}

func RO(pp *PP, cs []*math.G1, i int) *math.Zr {
	h := sha256.New()
	h.Write(pp.digest)
	h.Write([]byte{byte(i)})
	for j := 0; j < len(cs); j++ {
		h.Write(cs[j].Bytes())
	}
	digest := h.Sum(nil)
	result := common.FieldElementFromBytes(digest)
	return result
}
