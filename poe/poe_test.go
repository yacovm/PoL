package poe

import (
	"crypto/rand"
	"encoding/binary"
	"pol/common"
	"pol/pp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProofOfEquality(t *testing.T) {

	n := 64
	publicParams := NewPublicParams(n)

	v := common.RandVec(n)
	w := common.RandVec(n)

	// Select a random index for each vector
	i := randIndex(t, n)
	j := randIndex(t, n)

	v[i] = w[j]

	V := pp.Commit(publicParams.PP, v)
	W := pp.Commit(publicParams.PP, w)

	eq := &Equality{
		RO: RO,
		PP: publicParams,
		W:  W,
		V:  V,
		I:  i,
		J:  j,
	}

	proof := eq.Prove(v, w)
	err := eq.Verify(proof)
	assert.NoError(t, err)
}

func randIndex(t *testing.T, n int) int {
	buff := make([]byte, 16)
	_, err := rand.Read(buff)
	assert.NoError(t, err)

	return int(binary.BigEndian.Uint16(buff) % uint16(n))
}
