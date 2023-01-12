package pol

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"pol/sparse"
	"testing"
)

func TestPol(t *testing.T) {
	fanout := uint16(1024)
	ls := NewLiabilitySet(fanout)

	id := hash("bla bla")
	ls.Set(id, 100)

	hundred, proof, ok := ls.ProveLiability(id)

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(100), hundred)
	assert.True(t, ok)
	err := proof.Verify(ls.tree.PP, id, vRoot, wRoot, sparse.HexId2PathForFanout(fanout))
	assert.NoError(t, err)
}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
