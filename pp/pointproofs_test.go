package pp

import (
	"crypto/rand"
	"pol/common"
	"testing"

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
