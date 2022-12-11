package sum

import (
	"crypto/rand"
	"pol/common"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestSumArgument(t *testing.T) {
	pp := NewPublicParams(8)
	G := common.RandGenVec(8, "test")

	v := make([]*math.Zr, 8)
	v[7] = curve.NewZrFromInt(0)
	for i := 0; i < 7; i++ {
		v[i] = curve.NewZrFromInt(int64(i))
		v[7] = v[7].Plus(v[i])
	}

	r := curve.NewRandomZr(rand.Reader)

	sa, π := NewSumArgument(pp, G, v, r)

	err := sa.Verify(pp, π)
	assert.NoError(t, err)
}
