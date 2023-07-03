Short Privacy-Preserving Proofs of Liabilities
===============================================================================

This project contains an implementation of the paper.

The folder/package structure is as follows:

- `bench`: Contains a `main.go` that benchmarks the paper.
- `bp`: Implements the Inner Product Argument from Bulletproofs and the iterated reduction and range proof from the paper.
- `common`: Contains common (mostly math) functions used by the rest of the packages.
- `poe`: Implements the Opening Equality Argument from the paper
- `pol`: Implements the Proof of Liability scheme of the paper
- `pp`: Implements the vector commitment scheme of PointProofs
- `sparse`: Implements the sparse tree
- `sum`: Implements the Sum Argument from the paper
- `verkle`: Implements the Verkle tree construction using the `sparse` package.

How to run the tests? 
------------------------
Run `go test ./...` from the top level folder.


How to build and run the benchmark?
--------------------------------------
From the top level folder, execute:
```
cd bench
go build
./bench
```
