package verkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerkleTree(t *testing.T) {
	tree := NewVerkleTree(1024)

	tree.Put(hash("a"), 5)
	tree.Put(hash("b"), 6)

	five, ok := tree.Get(hash("a"))
	assert.Equal(t, 5, five)
	assert.True(t, ok)

	six, ok := tree.Get(hash("b"))
	assert.Equal(t, 6, six)
	assert.True(t, ok)
}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func TestIsPowerOfTwo(t *testing.T) {
	assert.False(t, isPowerOfTwo(1))
	assert.True(t, isPowerOfTwo(2))
	assert.True(t, isPowerOfTwo(4))
	assert.True(t, isPowerOfTwo(8))
	assert.True(t, isPowerOfTwo(16))
	assert.True(t, isPowerOfTwo(64))
	assert.True(t, isPowerOfTwo(128))
	assert.True(t, isPowerOfTwo(256))
	assert.True(t, isPowerOfTwo(512))
	assert.True(t, isPowerOfTwo(1024))

	assert.False(t, isPowerOfTwo(3))
	assert.False(t, isPowerOfTwo(5))
	assert.False(t, isPowerOfTwo(10))
	assert.False(t, isPowerOfTwo(12))
	assert.False(t, isPowerOfTwo(17))
	assert.False(t, isPowerOfTwo(15))
	assert.False(t, isPowerOfTwo(127))
	assert.False(t, isPowerOfTwo(129))
	assert.False(t, isPowerOfTwo(500))
	assert.False(t, isPowerOfTwo(514))
}

func TestUpdateSum(t *testing.T) {
	sum := c.NewZrFromInt(1000)
	x := c.NewZrFromInt(500)
	y := c.NewZrFromInt(300)
	sum2 := updateSum(sum, x, y)
	assert.Equal(t, c.NewZrFromInt(800), sum2)
}
