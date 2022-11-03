package bp

import (
	"pol/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInnerProdArgument(t *testing.T) {
	n := 8
	pp := NewPublicParams(n)
	a := common.RandVec(n)
	b := common.RandVec(n)

	ipa := NewInnerProdArgument(pp, a, b)

	proof := ipa.Prove()
	assert.Nil(t, proof.Verify(pp))
}
