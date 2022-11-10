package verkle

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerkleTree(t *testing.T) {
	tree := NewVerkleTree(8)
	tree.Put("00000000", 5)
	five, ok := tree.Get("00000000")
	assert.Equal(t, 5, five)
	assert.True(t, ok)
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
