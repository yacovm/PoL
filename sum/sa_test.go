package sum

import (
	"crypto/rand"
	"pol/common"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestSumArgument(t *testing.T) {
	n := 64
	pp := NewPublicParams(n)

	v, r, V := randomCommitment(n, pp)

	sa, π := NewArgument(pp, V, v, r)

	err := π.Verify(pp, sa)
	assert.NoError(t, err)
}

func randomCommitment(n int, pp *PP) ([]*math.Zr, *math.Zr, *math.G1) {
	v := make([]*math.Zr, n)
	v[n-1] = curve.NewZrFromInt(0)
	for i := 0; i < n-1; i++ {
		v[i] = curve.NewRandomZr(rand.Reader)
		v[i].Mod(curve.GroupOrder)
		v[n-1] = v[n-1].Plus(v[i])
	}

	r := curve.NewRandomZr(rand.Reader)

	V := NewCommitment(pp, v, r).V
	return v, r, V
}

func TestAggregatedSumArgument(t *testing.T) {
	n := 64

	pp := NewPublicParams(n)

	var Vs common.G1v
	var vs []common.Vec
	var rs common.Vec

	for i := 0; i < 100; i++ {
		v, r, V := randomCommitment(n, pp)
		Vs = append(Vs, V)
		vs = append(vs, v)
		rs = append(rs, r)
	}

	π := NewAggregatedArgument(pp, Vs, vs, rs)

	err := π.VerifyAggregated(pp, Vs)
	assert.NoError(t, err)
}
