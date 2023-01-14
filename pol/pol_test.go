package pol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"pol/sparse"
	"testing"
	"time"
)

func TestPolSparse(t *testing.T) {
	fanout := uint16(7)
	ls := NewLiabilitySet(fanout, Sparse)

	idBuff := make([]byte, 32)
	_, err := rand.Read(idBuff)

	id := hex.EncodeToString(idBuff)

	ls.Set(id, 100)

	t1 := time.Now()
	hundred, proof, ok := ls.ProveLiability(id)
	fmt.Println("Proof time:", time.Since(t1))

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(100), hundred)
	assert.True(t, ok)
	t1 = time.Now()
	err = proof.Verify(ls.pp, id, vRoot, wRoot, sparse.HexId2PathForFanOut(fanout))
	fmt.Println("Verification time:", time.Since(t1))
	assert.NoError(t, err)
}

func TestPolDense(t *testing.T) {
	ls := NewLiabilitySet(0, Dense)

	id := "123456789"

	ls.Set(id, 100)

	t1 := time.Now()
	hundred, proof, ok := ls.ProveLiability(id)
	fmt.Println("Proof time:", time.Since(t1))

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(100), hundred)
	assert.True(t, ok)
	t1 = time.Now()
	err := proof.Verify(ls.pp, id, vRoot, wRoot, sparse.DigitPath)
	fmt.Println("Verification time:", time.Since(t1))
	assert.NoError(t, err)
}
