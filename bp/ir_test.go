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

	_, xs, vFinal := IterativeReduce(pp, v, V)
	xs = xs.Reverse()
	/*	xs2, vFinal, err := IterativeVerify(pp, V, Δ, vFinal)
		assert.NoError(t, err)
		assert.Equal(t, xs, xs2)*/
	var xVec common.Vec

	for i := 0; i < 128; i++ {
		xVec = append(xVec, xs.PowBitVec(bitDecomposition(uint16(i), 127)).Product())
	}

	shouldBeV := v.InnerProd(xVec)
	assert.True(t, vFinal.Equals(shouldBeV))
}
