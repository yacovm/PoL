package poe

import (
	"pol/common"
	"pol/pp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProofOfEquality(t *testing.T) {

	publicParams := NewPublicParams(8)

	v := common.RandVec(8)
	w := common.RandVec(8)

	v[1] = w[2]

	V := pp.Commit(publicParams.PP, v)
	W := pp.Commit(publicParams.PP, w)

	eq := &Equality{
		RO: RO,
		PP: publicParams,
		W:  W,
		V:  V,
		I:  1,
		J:  2,
	}

	proof := eq.Prove(v, w)
	err := eq.Verify(proof)
	assert.NoError(t, err)
}
