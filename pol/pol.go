package pol

import (
	"crypto/sha256"
	"fmt"
	"pol/bp"
	"pol/common"
	"pol/poe"
	"pol/pp"
	"pol/sparse"
	"pol/sum"
	"pol/verkle"
	"sync"
	"sync/atomic"
	"time"

	math "github.com/IBM/mathlib"
)

type TreeType bool

const (
	// Sparse tree type allows referencing liabilities by hexadecimal strings of 64 characters
	Sparse TreeType = false
	// Dense tree type allows referencing liabilities by nine decimal digits
	Dense = true
)

type Parallelism bool

var ParallelismEnabled = true

type LiabilitySet struct {
	DB   verkle.DB
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

func (pp *PublicParams) Size() int {
	return pp.RPPP.Size() + pp.POEPP.Size() + pp.SAPP.Size() - len(pp.SAPP.Gs.Bytes()) - len(pp.SAPP.F.Bytes()) - len(pp.RPPP.Gs.Bytes()) - len(pp.RPPP.F.Bytes()) - pp.PPPP.Size()
}

// NewLiabilitySet creates a liability set with the given fanout and tree type.
// Only a fan-out of the form 2^k - 1 for some natural k is permitted.
func NewLiabilitySet(pp *PublicParams, db verkle.DB, id2Path func(string) []uint16) *LiabilitySet {
	tree := verkle.NewVerkleTree(uint16(pp.Fanout), id2Path, db)
	tree.PP = pp.PPPP

	return &LiabilitySet{
		DB:   &DBMemorizeRoot{DB: db},
		pp:   pp,
		tree: tree,
	}
}

func GeneratePublicParams(fanOut uint16, treeType TreeType) (func(string) []uint16, *PublicParams) {
	var id2Path func(string) []uint16
	var m int

	if treeType == Dense {
		m = sparse.DigitPathLen(fanOut) - 1
		id2Path = sparse.DigitPath(fanOut)
	}

	if treeType == Sparse {
		m = sparse.ExpectedHexPathLengthByFanOut[fanOut] - 1
		id2Path = sparse.HexId2PathForFanOut(fanOut)
	}

	for !common.IsPowerOfTwo(uint16(m)) {
		m = m + 1
	}

	poePP := poe.NewPublicParams(int(fanOut+2), m)

	n := int(fanOut + 1)

	pp := &PublicParams{
		Fanout: int(fanOut),
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
	return id2Path, pp
}

type LiabilityProof struct {
	PointProofΣ      *math.Zr
	PointProofπ      *math.G1
	SumArgumentProof *sum.Proof
	V                common.G1v
	W                common.G1v
	Digests          common.Vec
	RangeProofs      []*bp.RangeProof
	EqualityProof    *poe.AggregatedProof
	LiabilityProof   TotalProof
}

func (lp LiabilityProof) Size() int {
	size := len(lp.PointProofΣ.Bytes()) + len(lp.PointProofπ.Bytes()) + lp.SumArgumentProof.Size() + len(lp.V.Bytes()) + len(lp.W.Bytes()) + lp.Digests.Size()
	for _, rp := range lp.RangeProofs {
		size += rp.Size()
	}
	size += lp.EqualityProof.Size()
	return size
}

func (lp LiabilityProof) Verify(publicParams *PublicParams, id string, V, W *math.G1, id2path func(string) []uint16) ([]time.Duration, error) {
	path := id2path(id)
	expectedDigestNum := len(path)
	if len(lp.W) != expectedDigestNum-1 || len(lp.Digests) != expectedDigestNum {
		return nil, fmt.Errorf("expected digest proofs of size %d but got %d", expectedDigestNum, len(lp.W))
	}

	// Check that the root is what is advertised.
	if !lp.V[0].Equals(V) {
		return nil, fmt.Errorf("root V does not match public known V value")
	}
	if !lp.W[0].Equals(W) {
		return nil, fmt.Errorf("root W does not match public known W value")
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

		verifyRangeProof := func(rp *bp.RangeProof, V *math.G1) {
			defer rangeProofsVerification.Done()
			if err := bp.VerifyRange(publicParams.RPPP, rp, V); err != nil {
				detectedRangeProofErr.Store(err)
			}
		}

		if ParallelismEnabled {
			go verifyRangeProof(lp.RangeProofs[i], lp.V[i])
		} else {
			verifyRangeProof(lp.RangeProofs[i], lp.V[i])
		}

		if i == len(path)-1 {
			// This is the leaf layer, so we have no W.
			// Just check that the leaf matches with the previous digest.

			err := lp.checkCommitmentToLeafVertex(i)
			if err != nil {
				return nil, err
			}

			continue
		}

		if i > 0 {
			err := lp.checkCommitmentToInnerVertex(i)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := pp.VerifyAggregation(publicParams.PPPP, uint16VecToIntVec(path)[:len(path)-1], lp.W, lp.PointProofπ, lp.PointProofΣ, pp.RO); err != nil {
		return nil, fmt.Errorf("hash chain aggregation proof invalid: %v", err)
	}

	saStart := time.Now()
	if err := lp.SumArgumentProof.VerifyAggregated(publicParams.SAPP, lp.V); err != nil {
		return nil, fmt.Errorf("failed verifying sum argument: %v", err)
	}
	saElapsed := time.Since(saStart)

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

	eqStart := time.Now()
	if err := equalities.Verify(lp.EqualityProof); err != nil {
		return nil, fmt.Errorf("failed verifying equality proof")
	}
	eqElapsed := time.Since(eqStart)

	rangeProofsVerification.Wait()
	if detectedRangeProofErr.Load() != nil {
		return nil, detectedRangeProofErr.Load().(error)
	}

	if err := pp.Verify(publicParams.PPPP, common.IntToZr(lp.LiabilityProof.Sum), lp.LiabilityProof.LiabilityProof, lp.V[len(lp.V)-1], int(path[len(path)-1])); err != nil {
		return nil, fmt.Errorf("client liability proof is invalid: %v", err)
	}

	return []time.Duration{saElapsed, eqElapsed}, nil
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
	key := ls.tree.Tree.Root.Data.(string)
	bytes := ls.DB.Get([]byte(key))
	v := &verkle.Vertex{}
	v.FromBytes(bytes)
	return v.V, v.W
}

type TotalProof struct {
	LiabilityProof *math.G1
	Sum            int
}

func (tp TotalProof) Verify(publicParams *PublicParams, V *math.G1) error {
	mi := common.IntToZr(tp.Sum)
	return pp.Verify(publicParams.PPPP, mi, tp.LiabilityProof, V, publicParams.Fanout)
}

func (ls *LiabilitySet) ProveTot() TotalProof {
	cachedRoot := ls.tree.DB.Get(nil)

	v := &verkle.Vertex{}
	v.FromBytes(cachedRoot)

	sum, π := ls.openSumFromVertex(v)

	sumAsInt, err := sum.Int()
	if err != nil {
		panic(err)
	}

	return TotalProof{
		Sum:            int(sumAsInt),
		LiabilityProof: π,
	}
}

func (ls *LiabilitySet) openSumFromVertex(v *verkle.Vertex) (*math.Zr, *math.G1) {
	values := v.Values(ls.pp.PPPP.N - 1)
	m := make(common.Vec, len(values)+1)
	copy(m, values)
	m[len(m)-1] = v.BlindingFactor

	sum, π := pp.Open(ls.pp.PPPP, len(m)-2, m)
	return sum, π
}

func (ls *LiabilitySet) openForClient(v *verkle.Vertex, index int) (*math.Zr, *math.G1) {
	values := v.Values(ls.pp.PPPP.N - 1)
	m := make(common.Vec, len(values)+1)
	copy(m, values)
	m[len(m)-1] = v.BlindingFactor

	sum, π := pp.Open(ls.pp.PPPP, index, m)
	return sum, π
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

func (ls *LiabilitySet) ProveLiability(id string) (int64, LiabilityProof, []time.Duration, bool) {
	path := ls.tree.Tree.ID2Path(id)
	_, verticesAlongThePath, ok := ls.tree.Get(id)

	var vertices verkle.Vertices
	var proof LiabilityProof
	var digestProofs common.G1v

	if !ok {
		return 0, proof, nil, false
	}

	start := time.Now()

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

		values := v.Values(ls.tree.Tree.FanOut + 1)

		// The last entry in the path points is the liabilities and not to other layers in the tree
		if i < len(path)-1 {
			equalities.I[i] = int(path[i])
			equalities.J[i] = ls.tree.Tree.FanOut
			equalities.V[i] = v.V
			equalities.W[i] = verticesAlongThePath[i+1].V

			vEQ[i] = make(common.Vec, ls.tree.Tree.FanOut+2)
			wEQ[i] = make(common.Vec, ls.tree.Tree.FanOut+2)
			copy(vEQ[i], values)
			copy(wEQ[i], verticesAlongThePath[i+1].Values(ls.tree.Tree.FanOut+1))
			vEQ[i][ls.tree.Tree.FanOut+1] = v.BlindingFactor
			wEQ[i][ls.tree.Tree.FanOut+1] = verticesAlongThePath[i+1].BlindingFactor
		}

		createRangeProof := func(i int, pp *bp.RangeProofPublicParams, V *math.G1, v common.Vec, r *math.Zr) {
			defer rangeProofProduction.Done()
			rp := bp.ProveRange(pp, V, v, r)
			lock.Lock()
			proof.RangeProofs[i] = rp
			lock.Unlock()
		}

		if ParallelismEnabled {
			go createRangeProof(i, ls.pp.RPPP, v.V, values, v.BlindingFactor)
		} else {
			createRangeProof(i, ls.pp.RPPP, v.V, values, v.BlindingFactor)
		}

		digest, π := pp.Open(ls.tree.PP, int(path[i]), digests)

		if v.W != nil {
			proof.W = append(proof.W, v.W)
			digestProofs = append(digestProofs, π)
		}
		proof.V = append(proof.V, v.V)
		proof.Digests = append(proof.Digests, digest)
		vertices = append(vertices, v)
	}

	lastVertex := vertices[len(path)-1]
	l, liabilityProof := ls.openForClient(lastVertex, int(path[len(path)-1]))
	liability, err := l.Int()
	if err != nil {
		panic(err)
	}

	proof.LiabilityProof = TotalProof{
		LiabilityProof: liabilityProof,
		Sum:            int(liability),
	}

	var tPP common.Vec
	for i := 0; i < len(path)-1; i++ {
		tPP = append(tPP, pp.RO(ls.tree.PP, proof.W, i))
	}

	saStart := time.Now()
	proof.PointProofΣ = proof.Digests[:len(tPP)].InnerProd(tPP)
	proof.PointProofπ = pp.Aggregate(ls.tree.PP, proof.W, digestProofs, pp.RO)
	proof.SumArgumentProof = vertices.SumArgument(ls.pp.SAPP)
	saElapsed := time.Since(saStart)

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

	eqProofStart := time.Now()
	proof.EqualityProof = equalities.Prove(vEQ, wEQ)
	eqProofElapsed := time.Since(eqProofStart)

	rangeProofProduction.Wait()

	return liability, proof, []time.Duration{saElapsed, eqProofElapsed, time.Since(start)}, true
}

func uint16VecToIntVec(in []uint16) []int {
	res := make([]int, len(in))
	for i, n := range in {
		res[i] = int(n)
	}
	return res
}

type DBMemorizeRoot struct {
	DB   verkle.DB
	root []byte
}

func (db *DBMemorizeRoot) Get(key []byte) []byte {
	if len(key) == 0 && len(db.root) != 0 {
		return db.root
	}

	val := db.DB.Get(key)

	if len(key) == 0 {
		db.root = val
	}

	return val
}

func (db *DBMemorizeRoot) Put(key []byte, val []byte) {
	if len(key) == 0 {
		db.root = val
	}
	db.DB.Put(key, val)
}
