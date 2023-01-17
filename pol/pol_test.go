package pol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"pol/sparse"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type MemDB map[string][]byte

func (m MemDB) Get(key []byte) []byte {
	return m[string(key)]
}

func (m MemDB) Put(key []byte, val []byte) {
	m[string(key)] = val
}

func TestPolSparse(t *testing.T) {
	fanout := uint16(7)
	id2Path, pp := GeneratePublicParams(fanout, Sparse)

	ls := NewLiabilitySet(pp, make(MemDB), id2Path)

	idBuff := make([]byte, 32)
	rand.Read(idBuff)

	id := hex.EncodeToString(idBuff)

	ls.Set(id, 100)

	idBuff = make([]byte, 32)
	rand.Read(idBuff)
	id = hex.EncodeToString(idBuff)
	ls.Set(id, 101)

	t1 := time.Now()
	hundred, proof, _, ok := ls.ProveLiability(id)
	fmt.Println("Proof time:", time.Since(t1))

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(101), hundred)
	assert.True(t, ok)
	t1 = time.Now()
	_, err := proof.Verify(pp, id, vRoot, wRoot, id2Path)
	fmt.Println("Verification time:", time.Since(t1))
	assert.NoError(t, err)
}

func TestPolDense(t *testing.T) {
	fanout := uint16(7)
	id2Path, pp := GeneratePublicParams(fanout, Dense)

	ls := NewLiabilitySet(pp, make(MemDB), id2Path)

	id := "987654321"

	ls.Set(id, 100)

	t1 := time.Now()
	hundred, proof, _, ok := ls.ProveLiability(id)
	fmt.Println("Proof time:", time.Since(t1))

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(100), hundred)
	assert.True(t, ok)
	t1 = time.Now()
	_, err := proof.Verify(pp, id, vRoot, wRoot, sparse.DigitPath(fanout))
	fmt.Println("Verification time:", time.Since(t1))
	assert.NoError(t, err)
}

func TestProveTot(t *testing.T) {
	fanout := uint16(7)
	id2Path, pp := GeneratePublicParams(fanout, Sparse)

	ls := NewLiabilitySet(pp, make(MemDB), id2Path)

	idBuff := make([]byte, 32)
	rand.Read(idBuff)

	id := hex.EncodeToString(idBuff)

	ls.Set(id, 50)

	rand.Read(idBuff)
	id = hex.EncodeToString(idBuff)
	ls.Set(id, 50)

	t1 := time.Now()
	totProof := ls.ProveTot()
	fmt.Println(time.Since(t1))
	t1 = time.Now()

	V, _ := ls.Root()

	err := totProof.Verify(pp, V)
	fmt.Println(time.Since(t1))
	assert.NoError(t, err)
}
