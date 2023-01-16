package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"math/big"
	"os"
	"pol/pol"
	"pol/verkle"
	"strconv"
	"time"
)

const (
	//totalPopulation = 1000 * 1000
	totalPopulation = 1000
)

var (
	//fanouts = []uint16{3, 7, 15, 31, 63, 127, 255, 511}
	fanouts = []uint16{3, 7}
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

type measurement struct {
	ppGenTime  durations
	proofTime  durations
	verifyTime durations
	ppSize     sizes
	proofSize  sizes
	constTime  time.Duration
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

	fmt.Println("Population:", totalPopulation)

	measurePPGen(m)

	treeType := setTreeType()

	var idGen idFromRandBytes

	if treeType == pol.Sparse {
		fmt.Println("Benchmarking sparse liablity set...")
		idGen = func(buff []byte) string {
			return hex.EncodeToString(buff)
		}
	} else {
		fmt.Println("Benchmarking dense liablity set...")
		idGen = func(buff []byte) string {
			n := big.NewInt(0).SetBytes(buff)
			n.Mod(n, big.NewInt(1000*1000*1000))
			if n.Cmp(big.NewInt(100*1000*1000)) < 0 {
				n.Add(n, big.NewInt(1000*1000*100))
			}
			return n.String()
		}
	}

	db := NewDB()

	measureConstructProofVerify(db, m.iterations, m.sparse, totalPopulation, pol.Sparse, idGen)

	fmt.Println("PP sizes:", m.sparse.ppSizes())
	fmt.Println("Proof sizes:", m.sparse.proofSizes())

	fmt.Println("PP gen times:", m.sparse.ppGenTime())
	fmt.Println("proof times:", m.sparse.proveTime())
	fmt.Println("verify times:", m.sparse.verifyTime())

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

func measureConstructProofVerify(db verkle.DB, iterations int, measurementsByFanout map[uint16]*measurement, population int, treeType pol.TreeType, genID idFromRandBytes) {
	for _, fanOut := range fanouts {
		fmt.Println("Benchmarking fanout", fanOut, "...")
		id2Path, pp := pol.GeneratePublicParams(fanOut, treeType)

		ls := pol.NewLiabilitySet(pp, db, id2Path)

		constructionTime := populateLiabilitySet(population, ls, genID)
		measurementsByFanout[fanOut].constTime = constructionTime

		idBuffs := make([]string, iterations)
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

		for iteration := 0; iteration < iterations; iteration++ {
			fmt.Println("iteration", iteration)
			start := time.Now()
			_, π, ok := ls.ProveLiability(idBuffs[iteration])
			if !ok {
				panic("liability not found!!")
			}
			elapsed := time.Since(start)
			measurementsByFanout[fanOut].proofTime = append(measurementsByFanout[fanOut].proofTime, elapsed)

			start = time.Now()
			if err := π.Verify(pp, idBuffs[iteration], V, W, id2Path); err != nil {
				panic(err)
			}
			elapsed = time.Since(start)
			measurementsByFanout[fanOut].verifyTime = append(measurementsByFanout[fanOut].verifyTime, elapsed)
			measurementsByFanout[fanOut].proofSize = append(measurementsByFanout[fanOut].proofSize, π.Size())
		}

	}
}

func populateLiabilitySet(population int, ls *pol.LiabilitySet, genID idFromRandBytes) time.Duration {
	var constructionTime time.Duration

	fmt.Println("Populating liability set...")

	for i := 0; i < population/1000; i++ {
		idBuffs := make([]string, 1000)
		for j := 0; j < 1000; j++ {
			buff := make([]byte, 32)
			_, err := rand.Read(buff)
			if err != nil {
				panic(err)
			}
			idBuffs[j] = genID(buff)
		}

		start := time.Now()
		for j := 0; j < 1000; j++ {
			ls.Set(idBuffs[j], int64(j))
		}
		elapsed := time.Since(start)
		constructionTime += elapsed
	}

	fmt.Println("populated", population, "liabilities in", constructionTime)

	return constructionTime
}

func measurePPGen(m *measurements) {
	fmt.Println("Measuring dense public parameter generation time")
	// First measure dense tree public parameter generation
	for _, fanOut := range fanouts {
		m.dense[fanOut] = &measurement{}
		for iteration := 0; iteration < m.iterations; iteration++ {
			start := time.Now()
			_, pp := pol.GeneratePublicParams(fanOut, pol.Dense)
			elapsed := time.Since(start)
			m.dense[fanOut].ppGenTime = append(m.dense[fanOut].ppGenTime, elapsed)
			m.dense[fanOut].ppSize = append(m.dense[fanOut].ppSize, pp.Size())
		}
	}

	fmt.Println("Measuring sparse public parameter generation time")
	// Then measure sparse tree public parameter generation
	for _, fanOut := range fanouts {
		m.sparse[fanOut] = &measurement{}
		for iteration := 0; iteration < m.iterations; iteration++ {
			start := time.Now()
			_, pp := pol.GeneratePublicParams(fanOut, pol.Sparse)
			elapsed := time.Since(start)
			m.sparse[fanOut].ppGenTime = append(m.sparse[fanOut].ppGenTime, elapsed)
			m.sparse[fanOut].ppSize = append(m.sparse[fanOut].ppSize, pp.Size())
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
	if err != nil {
		panic(err)
	}
	return data
}

func (db *DB) Put(key []byte, val []byte) {
	if err := db.levelDB.Put(key, val, nil); err != nil {
		panic(err)
	}
}
