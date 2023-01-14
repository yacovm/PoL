package poe

import (
	"crypto/rand"
	"encoding/binary"
	"pol/common"
	"pol/pp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProofOfEqualities(t *testing.T) {
	n := 32
	m := 128

	publicParams := NewPublicParams(n, m)

	vs := make([]common.Vec, m)
	ws := make([]common.Vec, m)

	Vs := make(common.G1v, m)
	Ws := make(common.G1v, m)

	I := make([]int, m)
	J := make([]int, m)

	for k := 0; k < m; k++ {
		v := common.RandVec(n)
		w := common.RandVec(n)

		// Select a random index for each vector
		i := randIndex(t, n-1)
		j := randIndex(t, n-1)

		I[k] = i
		J[k] = j

		v[i] = w[j]

		vs[k] = v
		ws[k] = w

		V := pp.Commit(publicParams.PP, v)
		W := pp.Commit(publicParams.PP, w)

		Vs[k] = V
		Ws[k] = W
	}

	eq := &Equalities{
		RO: RO,
		PP: publicParams,
		W:  Ws,
		V:  Vs,
		I:  I,
		J:  J,
	}

	proof := eq.Prove(vs, ws)
	err := eq.Verify(proof)
	assert.NoError(t, err)
}

func TestProofOfEquality(t *testing.T) {
	for j := 0; j < 100; j++ {
		n := 64
		publicParams := NewPublicParams(n, 1)

		v := common.RandVec(n)
		w := common.RandVec(n)

		// Select a random index for each vector
		i := randIndex(t, n-1)
		j := randIndex(t, n-1)

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
		assert.NoErrorf(t, err, "i: %d, j: %d\n", i, j)
	}
}

func randIndex(t *testing.T, n int) int {
	buff := make([]byte, 16)
	_, err := rand.Read(buff)
	assert.NoError(t, err)

	return int(binary.BigEndian.Uint16(buff) % uint16(n))
}
