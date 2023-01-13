package pol

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"pol/sparse"
	"testing"
	"time"
)

func TestPol(t *testing.T) {
	fanout := uint16(7)
	ls := NewLiabilitySet(fanout)

	id := hash("bla bla")
	ls.Set(id, 100)

	fmt.Println("Fan-Out:", fanout)

	t1 := time.Now()
	hundred, proof, ok := ls.ProveLiability(id)
	fmt.Println("Proof time:", time.Since(t1))

	vRoot, wRoot := ls.Root()

	assert.Equal(t, int64(100), hundred)
	assert.True(t, ok)
	t1 = time.Now()
	err := proof.Verify(ls.pp, id, vRoot, wRoot, sparse.HexId2PathForFanout(fanout))
	fmt.Println("Verification time:", time.Since(t1))
	assert.NoError(t, err)
}
