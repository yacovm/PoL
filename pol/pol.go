package pol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	math "github.com/IBM/mathlib"
	"pol/bp"
	"pol/common"
	"pol/poe"
	"pol/pp"
	"pol/sum"
	"pol/verkle"
	"sync"
	"sync/atomic"
)

type LiabilitySet struct {
	tree *verkle.Tree
	pp   *PublicParams
}

type PublicParams struct {
	PPPP   *pp.PP
	SAPP   *sum.PP
	RPPP   *bp.RangeProofPublicParams
	POEPP  *poe.PP
	Fanout int
}

func NewLiabilitySet(fanout uint16) *LiabilitySet {
	tree := verkle.NewVerkleTree(fanout)

	m := len(tree.Tree.ID2Path(hash("bla bla"))) - 1
	for !common.IsPowerOfTwo(uint16(m)) {
		m = m + 1
	}

	poePP := poe.NewPublicParams(int(fanout+2), m)
	tree.PP = poePP.PP

	n := int(fanout + 1)

	pp := &PublicParams{
		Fanout: int(fanout),
		PPPP:   poePP.PP,
		SAPP:   sum.NewPublicParams(n),
		RPPP:   bp.NewRangeProofPublicParams(n),
		POEPP:  poePP,
	}

	pp.SAPP.F = pp.PPPP.G1s[n]
	pp.SAPP.Gs = make(common.G1v, n)
	copy(pp.SAPP.Gs, pp.PPPP.G1s)

	pp.RPPP.Gs = pp.SAPP.Gs
	pp.RPPP.F = pp.SAPP.F

	return &LiabilitySet{
		pp:   pp,
		tree: tree,
	}
}

type LiabilityProof struct {
	PointProofΣ      *math.Zr
	PointProofπ      *math.G1
	SumArgumentProof *sum.Proof
	V                common.G1v
	W                []*math.G1
	Digests          common.Vec
	RangeProofs      []*bp.RangeProof
	EqualityProof    *poe.AggregatedProof
}

func (lp LiabilityProof) Verify(publicParams *PublicParams, id string, V, W *math.G1, id2path func(string) []uint16) error {
	path := id2path(id)
	expectedDigestNum := len(path)
	if len(lp.W) != expectedDigestNum-1 || len(lp.Digests) != expectedDigestNum {
		return fmt.Errorf("expected digest proofs of size %d but got %d", expectedDigestNum, len(lp.W))
	}

	// Check that the root is what is advertised.
	if !lp.V[0].Equals(V) {
		return fmt.Errorf("root V does not match public known V value")
	}
	if !lp.W[0].Equals(W) {
		return fmt.Errorf("root W does not match public known W value")
	}

	var rangeProofsVerification sync.WaitGroup
	rangeProofsVerification.Add(len(path))

	var detectedRangeProofErr atomic.Value

	equalities := &poe.Equalities{
		PP: publicParams.POEPP,
		W:  make(common.G1v, len(path)-1),
		V:  make(common.G1v, len(path)-1),
		I:  make([]int, len(path)-1),
		J:  make([]int, len(path)-1),
		RO: poe.RO,
	}

	for i := 0; i < len(path); i++ {

		if i < len(path)-1 {
			equalities.I[i] = int(path[i])
			equalities.J[i] = publicParams.Fanout
			equalities.V[i] = lp.V[i]
			equalities.W[i] = lp.V[i+1]
		}

		go func(rp *bp.RangeProof, V *math.G1) {
			defer rangeProofsVerification.Done()
			if err := bp.VerifyRange(publicParams.RPPP, rp, V); err != nil {
				detectedRangeProofErr.Store(err)
			}
		}(lp.RangeProofs[i], lp.V[i])

		if i == len(path)-1 {
			// This is the leaf layer, so we have no W.
			// Just check that the leaf matches with the previous digest.

			err := lp.checkCommitmentToLeafVertex(i)
			if err != nil {
				return err
			}

			continue
		}

		if i > 0 {
			err := lp.checkCommitmentToInnerVertex(i)
			if err != nil {
				return err
			}
		}
	}

	if err := pp.VerifyAggregation(publicParams.PPPP, uint16VecToIntVec(path)[:len(path)-1], lp.W, lp.PointProofπ, lp.PointProofΣ, pp.RO); err != nil {
		return fmt.Errorf("hash chain aggregation proof invalid: %v", err)
	}

	if err := lp.SumArgumentProof.VerifyAggregated(publicParams.SAPP, lp.V); err != nil {
		return fmt.Errorf("failed verifying sum argument: %v", err)
	}

	zeroVec := make(common.Vec, publicParams.Fanout+2)
	zeroVec.Zero()
	zeroCommit := pp.Commit(publicParams.PPPP, zeroVec)

	// Pad the equality proof until it's a power of two
	for !common.IsPowerOfTwo(uint16(len(equalities.I))) {
		equalities.I = append(equalities.I, 0)
		equalities.J = append(equalities.J, 0)
		equalities.V = append(equalities.V, zeroCommit)
		equalities.W = append(equalities.W, zeroCommit)
	}

	if err := equalities.Verify(lp.EqualityProof); err != nil {
		return fmt.Errorf("failed verifying equality proof")
	}

	rangeProofsVerification.Wait()
	if detectedRangeProofErr.Load() != nil {
		return detectedRangeProofErr.Load().(error)
	}

	return nil
}

func (lp LiabilityProof) checkCommitmentToInnerVertex(i int) error {
	h := sha256.New()
	h.Write(lp.V[i].Bytes())
	h.Write(lp.W[i].Bytes())
	hash := h.Sum(nil)
	expectedPreviousDigest := common.FieldElementFromBytes(hash)
	if !lp.Digests[i-1].Equals(expectedPreviousDigest) {
		return fmt.Errorf("hash path mismatch %d from root", i)
	}
	return nil
}

func (lp LiabilityProof) checkCommitmentToLeafVertex(i int) error {
	h := sha256.New()
	h.Write(lp.V[i].Bytes())
	hash := h.Sum(nil)
	expectedPreviousDigest := common.FieldElementFromBytes(hash)
	if !lp.Digests[i-1].Equals(expectedPreviousDigest) {
		return fmt.Errorf("hash path mismatch %d from root", i)
	}
	return nil
}

func (ls *LiabilitySet) Root() (V, W *math.G1) {
	if ls.tree == nil || ls.tree.Tree == nil || ls.tree.Tree.Root == nil {
		return nil, nil
	}
	v := ls.tree.Tree.Root.Data.(*verkle.Vertex)
	return v.V, v.W
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

	var vertices verkle.Vertices
	var proof LiabilityProof
	var digestProofs common.G1v

	if !ok {
		return 0, proof, false
	}

	var rangeProofProduction sync.WaitGroup
	rangeProofProduction.Add(len(path))

	var lock sync.Mutex

	proof.RangeProofs = make([]*bp.RangeProof, len(path))

	vEQ := make([]common.Vec, len(path)-1)
	wEQ := make([]common.Vec, len(path)-1)
	equalities := &poe.Equalities{
		PP: ls.pp.POEPP,
		W:  make(common.G1v, len(path)-1),
		V:  make(common.G1v, len(path)-1),
		I:  make([]int, len(path)-1),
		J:  make([]int, len(path)-1),
		RO: poe.RO,
	}

	for i := 0; i < len(path); i++ {
		var digests []*math.Zr
		v := verticesAlongThePath[i]
		for j := 0; j <= ls.tree.Tree.FanOut+1; j++ {
			digest, exists := v.Digests[uint16(j)]
			if exists {
				digests = append(digests, digest)
			} else {
				digests = append(digests, common.IntToZr(0))
			}
		}

		// The last entry in the path points is the liabilities and not to other layers in the tree
		if i < len(path)-1 {
			equalities.I[i] = int(path[i])
			equalities.J[i] = ls.tree.Tree.FanOut
			equalities.V[i] = v.V
			equalities.W[i] = verticesAlongThePath[i+1].V

			vEQ[i] = make(common.Vec, ls.tree.Tree.FanOut+2)
			wEQ[i] = make(common.Vec, ls.tree.Tree.FanOut+2)
			copy(vEQ[i], v.Values(ls.tree.Tree.FanOut+1))
			copy(wEQ[i], verticesAlongThePath[i+1].Values(ls.tree.Tree.FanOut+1))
			vEQ[i][ls.tree.Tree.FanOut+1] = v.BlindingFactor
			wEQ[i][ls.tree.Tree.FanOut+1] = verticesAlongThePath[i+1].BlindingFactor
		}

		go func(i int, pp *bp.RangeProofPublicParams, V *math.G1, v common.Vec, r *math.Zr) {
			defer rangeProofProduction.Done()
			rp := bp.ProveRange(pp, V, v, r)
			lock.Lock()
			proof.RangeProofs[i] = rp
			lock.Unlock()
		}(i, ls.pp.RPPP, v.V, v.Values(ls.tree.Tree.FanOut+1), v.BlindingFactor)

		digest, π := pp.Open(ls.tree.PP, int(path[i]), digests)

		if v.W != nil {
			proof.W = append(proof.W, v.W)
			digestProofs = append(digestProofs, π)
		}
		proof.V = append(proof.V, v.V)
		proof.Digests = append(proof.Digests, digest)
		vertices = append(vertices, v)
	}

	var tPP common.Vec
	for i := 0; i < len(path)-1; i++ {
		tPP = append(tPP, pp.RO(ls.tree.PP, proof.W, i))
	}

	proof.PointProofΣ = proof.Digests[:len(tPP)].InnerProd(tPP)
	proof.PointProofπ = pp.Aggregate(ls.tree.PP, proof.W, digestProofs, pp.RO)
	proof.SumArgumentProof = vertices.SumArgument(ls.pp.SAPP)

	zeroVec := make(common.Vec, ls.tree.Tree.FanOut+2)
	zeroVec.Zero()

	zeroCommit := pp.Commit(ls.pp.PPPP, zeroVec)

	// We need to pad the equality tree up to a power of two
	for !common.IsPowerOfTwo(uint16(len(vEQ))) {

		vEQ = append(vEQ, zeroVec)
		wEQ = append(wEQ, zeroVec)

		equalities.I = append(equalities.I, 0)
		equalities.J = append(equalities.J, 0)
		equalities.V = append(equalities.V, zeroCommit)
		equalities.W = append(equalities.W, zeroCommit)
	}
	proof.EqualityProof = equalities.Prove(vEQ, wEQ)

	rangeProofProduction.Wait()

	return liability, proof, true
}

func uint16VecToIntVec(in []uint16) []int {
	res := make([]int, len(in))
	for i, n := range in {
		res[i] = int(n)
	}
	return res
}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
