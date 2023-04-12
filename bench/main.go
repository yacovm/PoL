package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"pol/pol"
	"strconv"
	"time"

	math "github.com/IBM/mathlib"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
// totalPopulation = 10 * 1000
)

var (
	fanouts = []uint16{3, 7, 15, 31, 63, 127, 255, 511}
	//fanouts = []uint16{7, 15}
	totalPopulation = 1000
)

type sizes []int

func (s sizes) Avg() int {
	var sum int
	for _, size := range s {
		sum += size
	}
	return sum / len(s)
}

type durations []time.Duration

func (d durations) Avg() time.Duration {
	var sum time.Duration
	for _, duration := range d {
		sum += duration
	}
	return sum / time.Duration(len(d))
}

type measurementByFanOut map[uint16]*measurement

func (m measurementByFanOut) ppGenTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].ppGenTime.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) proveTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].proofTime.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) proveEqualityTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].equalityTimeProve.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) proveSumTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].sumTimeProve.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) verifySumTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].sumTimeVerify.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) verifyEqTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].equalityTimeVerify.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) verifyTime() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].verifyTime.Avg().Milliseconds()))
	}
	return bb.String()
}

func (m measurementByFanOut) ppSizes() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].ppSize.Avg()))
	}
	return bb.String()
}

func (m measurementByFanOut) proofSizes() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].proofSize.Avg()))
	}
	return bb.String()
}

func (m measurementByFanOut) proofSizesWithBatchedRangeProofs() string {
	bb := bytes.Buffer{}
	for _, fanOut := range fanouts {
		bb.WriteString(fmt.Sprintf("(%d, %d)", fanOut, m[fanOut].proofSize.Avg()))
	}
	return bb.String()
}

type measurement struct {
	ppGenTime          durations
	proofTime          durations
	verifyTime         durations
	equalityTimeProve  durations
	sumTimeProve       durations
	equalityTimeVerify durations
	sumTimeVerify      durations
	ppSize             sizes
	proofSize          sizes
	proofSizeBatchedRP sizes
	constTime          time.Duration
}

type measurements struct {
	iterations int
	sparse     measurementByFanOut
	dense      measurementByFanOut
}

func main() {
	setParallelism()

	m := &measurements{
		iterations: getIterations(),
		dense:      make(measurementByFanOut),
		sparse:     make(measurementByFanOut),
	}

	pop := os.Getenv("POPULATION")
	if pop != "" {
		n, err := strconv.ParseInt(pop, 10, 32)
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("Failed parsing POPULATION (%s) environment variable: %v", pop, err))
			os.Exit(2)
		}
		totalPopulation = int(n)
	}

	fmt.Println("Population:", totalPopulation)

	//measurePPGen(m)

	for _, fanOut := range fanouts {
		m.dense[fanOut] = &measurement{}
	}

	var spaceSize *big.Int

	treeType := setTreeType()

	var idGen idFromRandBytes

	if treeType == pol.Sparse {
		fmt.Println("Benchmarking sparse liablity set...")
		idGen = func(buff []byte) string {
			return hex.EncodeToString(buff)
		}
	} else {
		spaceSize = big.NewInt(0).Exp(big.NewInt(10), big.NewInt(9), nil)
		spaceTxt := os.Getenv("SPACE")
		if spaceTxt != "" {
			space, err := strconv.ParseInt(spaceTxt, 10, 64)
			if err != nil {
				os.Stderr.WriteString(fmt.Sprintf("Failed parsing SPACE (%s) environment variable: %v", spaceTxt, err))
				os.Exit(2)
			}
			spaceSize = big.NewInt(space)
		}

		fmt.Println("Benchmarking dense liability set with space size of", spaceSize.Text(10))

		idGen = func(buff []byte) string {
			n := big.NewInt(0).SetBytes(buff)
			n.Mod(n, spaceSize)
			if n.Cmp(spaceSize) < 0 {
				n.Add(n, spaceSize)
			}
			return n.String()
		}
	}

	if treeType == pol.Sparse {
		measureConstructProofVerify(m.iterations, m.sparse, totalPopulation, treeType, idGen, nil)
		fmt.Println("proof times:", m.sparse.proveTime())
		fmt.Println("verify times:", m.sparse.verifyTime())
		fmt.Println("Proof sizes:", m.dense.proofSizes())

		fmt.Println("equality proof times:", m.sparse.proveEqualityTime())
		fmt.Println("sum proof times:", m.sparse.proveSumTime())
		fmt.Println("verify equality times:", m.sparse.verifyEqTime())
		fmt.Println("verify sum times:", m.sparse.verifySumTime())
	} else {
		measureConstructProofVerify(m.iterations, m.dense, totalPopulation, treeType, idGen, spaceSize)
		fmt.Println("proof times:", m.dense.proveTime())
		fmt.Println("verify times:", m.dense.verifyTime())
		fmt.Println("Proof sizes:", m.dense.proofSizes())

		fmt.Println("equality proof times:", m.dense.proveEqualityTime())
		fmt.Println("sum proof times:", m.dense.proveSumTime())
		fmt.Println("verify equality times:", m.dense.verifyEqTime())
		fmt.Println("verify sum times:", m.dense.verifySumTime())
	}
}

func setTreeType() pol.TreeType {
	treeType := os.Getenv("TREETYPE")
	if treeType == "" {
		fmt.Println("Tree type is set to Sparse. Use TREETYPE=DENSE to use a dense type")
		return pol.Sparse
	}

	if treeType == "SPARSE" {
		fmt.Println("Tree type is set to Sparse")
		return pol.Sparse
	}

	if treeType == "DENSE" {
		fmt.Println("Tree type is set to Dense")
		return pol.Dense
	}

	fmt.Println("TREETYPE must be either SPARSE or DENSE")
	os.Exit(2)
	return pol.Dense
}

func setParallelism() {
	parallelism := os.Getenv("PARALLELISM")

	if parallelism == "0" {
		fmt.Println("Running with parallelism disabled")
		pol.ParallelismEnabled = false
	} else if parallelism == "1" || parallelism == "" {
		fmt.Println("Running with parallelism enabled (Use PARALLELISM=0 to turn it off)")
		pol.ParallelismEnabled = true
	} else {
		fmt.Println("PARALLELISM environment variable can either be 0 or 1")
		os.Exit(2)
	}
}

type idFromRandBytes func([]byte) string

func measureConstructProofVerify(iterations int, measurementsByFanout map[uint16]*measurement, population int, treeType pol.TreeType, genID idFromRandBytes, spaceSize *big.Int) {
	for _, fanOut := range fanouts {
		benchmarkFanout(iterations, measurementsByFanout, population, treeType, genID, fanOut, spaceSize)
	}
}

func benchmarkFanout(iterations int, measurementsByFanout map[uint16]*measurement, population int, treeType pol.TreeType, genID idFromRandBytes, fanOut uint16, spaceSize *big.Int) {
	fmt.Println("Benchmarking fanout", fanOut, "...")
	id2Path, pp := pol.GeneratePublicParams(fanOut, treeType, spaceSize)

	db := make(MemDB)

	ls := pol.NewLiabilitySet(pp, db, id2Path)

	constructionTime := populateLiabilitySet(population, ls, genID)
	measurementsByFanout[fanOut].constTime = constructionTime

	idBuffs := make([]string, iterations)

	for {

		success := true

		for iteration := 0; iteration < iterations; iteration++ {
			buff := make([]byte, 32)
			_, err := rand.Read(buff)
			if err != nil {
				panic(err)
			}
			id := genID(buff)
			idBuffs[iteration] = id
			ls.Set(id, 666)
		}

		V, W := ls.Root()

		// Dry run: Prove and verify on iterations without measuring time

		for iteration := 0; iteration < iterations; iteration++ {
			_, π, _, ok := ls.ProveLiability(idBuffs[iteration])
			if !ok {
				panic("liability not found!!")
			}

			_, err := π.Verify(pp, idBuffs[iteration], V, W, id2Path)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed verifying: %v", err))
				success = false
			}
		}

		if success {
			break
		} else {
			idBuffs = make([]string, iterations)
			ls = pol.NewLiabilitySet(pp, db, id2Path)
		}

	}

	V, W := ls.Root()

	for iteration := 0; iteration < iterations; iteration++ {
		fmt.Println("iteration", iteration)
		_, π, elapsedTimes, ok := ls.ProveLiability(idBuffs[iteration])
		if !ok {
			panic("liability not found!!")
		}

		start := time.Now()
		verifyTimes, err := π.Verify(pp, idBuffs[iteration], V, W, id2Path)
		if err != nil {
			panic(err)
		}

		measurementsByFanout[fanOut].proofTime = append(measurementsByFanout[fanOut].proofTime, elapsedTimes[2])
		measurementsByFanout[fanOut].equalityTimeProve = append(measurementsByFanout[fanOut].equalityTimeProve, elapsedTimes[1])
		measurementsByFanout[fanOut].sumTimeProve = append(measurementsByFanout[fanOut].sumTimeProve, elapsedTimes[0])

		saElapsed, eqElapsed := verifyTimes[0], verifyTimes[1]
		elapsed := time.Since(start)
		measurementsByFanout[fanOut].verifyTime = append(measurementsByFanout[fanOut].verifyTime, elapsed)
		measurementsByFanout[fanOut].equalityTimeVerify = append(measurementsByFanout[fanOut].equalityTimeVerify, eqElapsed)
		measurementsByFanout[fanOut].sumTimeVerify = append(measurementsByFanout[fanOut].sumTimeVerify, saElapsed)
		measurementsByFanout[fanOut].proofSize = append(measurementsByFanout[fanOut].proofSize, π.Size()/1024)
	}

	benchmarkVerifyTot(iterations, ls, pp, V)
}

func benchmarkVerifyTot(iterations int, ls *pol.LiabilitySet, pp *pol.PublicParams, V *math.G1) {
	var proveTots durations
	var verifyTots durations

	for iteration := 0; iteration < iterations; iteration++ {
		t1 := time.Now()
		totProof := ls.ProveTot()
		elapsed := time.Since(t1)
		proveTots = append(proveTots, elapsed)

		t1 = time.Now()
		if err := totProof.Verify(pp, V); err != nil {
			panic(err)
		}
		elapsed = time.Since(t1)
		verifyTots = append(verifyTots, elapsed)
	}

	fmt.Println("ProveTot time:", proveTots.Avg())
	fmt.Println("VerifyTot time:", verifyTots.Avg())
}

func populateLiabilitySet(population int, ls *pol.LiabilitySet, genID idFromRandBytes) time.Duration {
	var constructionTime time.Duration

	fmt.Println("Populating liability set...")

	for i := 0; i < population; i++ {
		buff := make([]byte, 32)
		_, err := rand.Read(buff)
		if err != nil {
			panic(err)
		}
		start := time.Now()
		ls.Set(genID(buff), int64(i))
		elapsed := time.Since(start)
		constructionTime += elapsed
	}

	fmt.Println("populated", population, "liabilities in", constructionTime)

	return constructionTime
}

func measurePPGen(m *measurements, spaceSize *big.Int) {
	fmt.Println("Measuring dense public parameter generation time")
	// First measure dense tree public parameter generation
	for _, fanOut := range fanouts {
		m.dense[fanOut] = &measurement{}
		for iteration := 0; iteration < m.iterations; iteration++ {
			start := time.Now()
			_, pp := pol.GeneratePublicParams(fanOut, pol.Dense, spaceSize)
			elapsed := time.Since(start)
			m.dense[fanOut].ppGenTime = append(m.dense[fanOut].ppGenTime, elapsed)
			m.dense[fanOut].ppSize = append(m.dense[fanOut].ppSize, pp.Size()/1024)
		}
	}

	fmt.Println("Measuring sparse public parameter generation time")
	// Then measure sparse tree public parameter generation
	for _, fanOut := range fanouts {
		m.sparse[fanOut] = &measurement{}
		for iteration := 0; iteration < m.iterations; iteration++ {
			start := time.Now()
			_, pp := pol.GeneratePublicParams(fanOut, pol.Sparse, spaceSize)
			elapsed := time.Since(start)
			m.sparse[fanOut].ppGenTime = append(m.sparse[fanOut].ppGenTime, elapsed)
			m.sparse[fanOut].ppSize = append(m.sparse[fanOut].ppSize, pp.Size()/1024)
		}
	}
}

func getIterations() int {
	var err error
	iterationsString := os.Getenv("ITERATIONS")
	iterations := int64(10)
	if iterationsString != "" {
		iterations, err = strconv.ParseInt(iterationsString, 10, 32)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Will amortize over", iterations, "iterations")

	return int(iterations)
}

type DB struct {
	levelDB *leveldb.DB
}

func NewDB() *DB {
	db, err := leveldb.OpenFile("levelDB", nil)
	if err != nil {
		panic(err)
	}
	return &DB{levelDB: db}
}

func (db *DB) Get(key []byte) []byte {
	data, err := db.levelDB.Get(key, nil)
	if err != nil && err != leveldb.ErrNotFound {
		panic(err)
	}
	if err == leveldb.ErrNotFound {
		return nil
	}
	return data
}

func (db *DB) Put(key []byte, val []byte) {
	if err := db.levelDB.Put(key, val, nil); err != nil {
		panic(err)
	}
}

func (db *DB) Destroy() {
	db.levelDB.Close()
	os.RemoveAll("levelDB")
}

type MemDB map[string][]byte

func (m MemDB) Get(key []byte) []byte {
	return m[string(key)]
}

func (m MemDB) Put(key []byte, val []byte) {
	m[string(key)] = val
}
