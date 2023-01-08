package pol

import (
	"crypto/sha256"
	"fmt"
	math "github.com/IBM/mathlib"
	"pol/common"
	"pol/pp"
	"pol/verkle"
)

type LiabilitySet struct {
	tree *verkle.Tree
}

func NewLiabilitySet(fanout uint16) *LiabilitySet {
	tree := verkle.NewVerkleTree(fanout)

	return &LiabilitySet{
		tree: tree,
	}
}

type LiabilityProof struct {
	V            []*math.G1
	W            []*math.G1
	Digests      []*math.Zr
	DigestProofs []*math.G1
}

func (lp LiabilityProof) Verify(pppp *pp.PP, id string, id2path func(string) []uint16) error {
	path := id2path(id)
	expectedDigestNum := len(path) - 1
	if len(lp.W) != expectedDigestNum || len(lp.Digests) != expectedDigestNum || len(lp.DigestProofs) != expectedDigestNum {
		return fmt.Errorf("expected digest proofs of size %d", expectedDigestNum)
	}

	h := sha256.New()
	for i := 0; i < len(lp.W); i++ {
		if err := pp.Verify(pppp, lp.Digests[i], lp.DigestProofs[i], lp.W[i], int(path[i])); err != nil {
			panic(err)
		}

		if i > 0 {
			h.Write(lp.V[i].Bytes())
			h.Write(lp.W[i].Bytes())
			hash := h.Sum(nil)
			h.Reset()
			expectedPreviousDigest := common.FieldElementFromBytes(hash)
			if !lp.Digests[i-1].Equals(expectedPreviousDigest) {
				return fmt.Errorf("hash path mismatch %d from root", i)
			}
		}
	}

	return nil
}

func (ls *LiabilitySet) Set(id string, liability int64) {
	if liability < 0 {
		panic("Liability cannot be negative")
	}

	ls.tree.Put(id, liability)
}

func (ls *LiabilitySet) Get(id string) (int64, bool) {
	liability, _, ok := ls.tree.Get(id)
	return liability, ok
}

func (ls *LiabilitySet) ProveLiability(id string) (int64, LiabilityProof, bool) {
	path := ls.tree.Tree.ID2Path(id)
	liability, verticesAlongThePath, ok := ls.tree.Get(id)

	var proof LiabilityProof

	if !ok {
		return 0, proof, false
	}

	for i := 0; i < len(path)-1; i++ {
		var digests []*math.Zr
		v := verticesAlongThePath[i]
		for j := 0; j < ls.tree.PP.N; j++ {
			digest, exists := v.Digests[uint16(j)]
			if exists {
				digests = append(digests, digest)
			} else {
				digests = append(digests, common.IntToZr(0))
			}
		}

		digest, π := pp.Open(ls.tree.PP, int(path[i]), digests)
		proof.W = append(proof.W, v.W)
		proof.V = append(proof.V, v.V)
		proof.Digests = append(proof.Digests, digest)
		proof.DigestProofs = append(proof.DigestProofs, π)
	}

	return liability, proof, true
}
