package bp

import (
	"fmt"
	"pol/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRangeProof(t *testing.T) {
	pp := NewRangeProofPublicParams(8)

	v := common.Vec{common.IntToZr(100), common.IntToZr(100), common.IntToZr(100), common.IntToZr(100),
		common.IntToZr(100), common.IntToZr(100), common.IntToZr(100), common.IntToZr(100)}
	r := common.RandVec(1)[0]

	V := pp.F.Mul(r)
	V.Add(pp.Gs.MulV(v).Sum())

	rp := ProveRange(pp, V, v, r)
	err := VerifyRange(pp, rp, V)
	assert.NoError(t, err)
}

func TestBits(t *testing.T) {
	fmt.Println(bitDecomposition(3, 7))
	fmt.Println(common.Bits(common.IntToZr(3), 8))
}
