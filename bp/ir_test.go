package bp

import (
	"pol/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIterativeReduce(t *testing.T) {
	n := 128
	pp := NewPublicParams(n)
	pp.H = nil
	pp.H = nil
	pp.RecomputeDigest()

	v := common.RandVec(n)
	V := common.G1v(pp.G).MulV(v).Sum()

	Δ, xs, vFinal := IterativeReduce(pp, v, V)
	xs2, vFinal, err := IterativeVerify(pp, V, Δ, vFinal)
	assert.NoError(t, err)
	assert.Equal(t, xs, xs2)
}
