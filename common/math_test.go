package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMath(t *testing.T) {
	n := RandVec(1)[0]

	bits := Bits(n, 256)
	n2 := c.NewZrFromInt(0)
	for i := 0; i < len(bits); i++ {
		if bits[i] == 0 {
			continue
		}
		n2 = n2.Plus(c.NewZrFromInt(2).PowMod(c.NewZrFromInt(int64(i))))
	}
	fmt.Println(Bits(n, 256))
	assert.Equal(t, n, n2)
	fmt.Println(c.FieldBytes)

	v1 := Vec{c.NewZrFromInt(1), c.NewZrFromInt(2)}
	v2 := Vec{c.NewZrFromInt(3), c.NewZrFromInt(4)}
	fmt.Println(v1.Concat(v2))
}
