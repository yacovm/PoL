package verkle

import (
	"crypto/sha256"
	"encoding/hex"
	"pol/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerkleTree(t *testing.T) {
	tree := NewVerkleTree(1024)

	tree.Put(hash("a"), 5)
	tree.Put(hash("b"), 6)

	five, path, ok := tree.Get(hash("a"))
	assert.Equal(t, int64(5), five)
	assert.True(t, ok)
	assert.Len(t, path, 26)

	six, path, ok := tree.Get(hash("b"))
	assert.Equal(t, int64(6), six)
	assert.True(t, ok)
	assert.Len(t, path, 26)

}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func TestIsPowerOfTwo(t *testing.T) {
	assert.False(t, common.IsPowerOfTwo(1))
	assert.True(t, common.IsPowerOfTwo(2))
	assert.True(t, common.IsPowerOfTwo(4))
	assert.True(t, common.IsPowerOfTwo(8))
	assert.True(t, common.IsPowerOfTwo(16))
	assert.True(t, common.IsPowerOfTwo(64))
	assert.True(t, common.IsPowerOfTwo(128))
	assert.True(t, common.IsPowerOfTwo(256))
	assert.True(t, common.IsPowerOfTwo(512))
	assert.True(t, common.IsPowerOfTwo(1024))

	assert.False(t, common.IsPowerOfTwo(3))
	assert.False(t, common.IsPowerOfTwo(5))
	assert.False(t, common.IsPowerOfTwo(10))
	assert.False(t, common.IsPowerOfTwo(12))
	assert.False(t, common.IsPowerOfTwo(17))
	assert.False(t, common.IsPowerOfTwo(15))
	assert.False(t, common.IsPowerOfTwo(127))
	assert.False(t, common.IsPowerOfTwo(129))
	assert.False(t, common.IsPowerOfTwo(500))
	assert.False(t, common.IsPowerOfTwo(514))
}

func TestUpdateSum(t *testing.T) {
	sum := c.NewZrFromInt(1000)
	x := c.NewZrFromInt(500)
	y := c.NewZrFromInt(300)
	sum2 := updateSum(sum, x, y)
	assert.Equal(t, c.NewZrFromInt(800), sum2)
}
