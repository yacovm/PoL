package bp

import (
	"github.com/stretchr/testify/assert"
	"pol/common"
	"testing"
)

func TestRangeProof(t *testing.T) {
	pp := NewRangeProofPublicParams(8)

	v := common.RandVec(8)
	r := common.RandVec(1)[0]

	V := pp.F.Mul(r)
	V.Add(pp.Gs.MulV(v).Sum())

	rp := ProveRange(pp, V, v, r)
	err := VerifyRange(pp, rp, V)
	assert.NoError(t, err)
}
