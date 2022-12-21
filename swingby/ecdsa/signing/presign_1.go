// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *presign1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 1. sample k and gamma
	ki := common.GetRandomPositiveInt(round.EC().Params().N)
	𝛾i := common.GetRandomPositiveInt(round.EC().Params().N)
	Ki, 𝜌i, err := round.key.PaillierSK.EncryptAndReturnRandomness(ki)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"))
	}
	Gi, 𝜈i, err := round.key.PaillierSK.EncryptAndReturnRandomness(𝛾i)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"))
	}

	// Fig 7. Round 1. create proof enc
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			proof, err := zkpenc.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, Ki, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], ki, 𝜌i)
			if err != nil {
				errChs <- round.WrapError(fmt.Errorf("ProofEnc failed: %v", err), Pj)
				return
			}
			r1msg := NewPreSignRound1Message(Pj, round.PartyID(), Ki, Gi, proof)
			round.out <- r1msg
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	round.temp.ki = ki
	round.temp.𝛾i = 𝛾i
	round.temp.G = Gi
	round.temp.K = Ki
	round.temp.𝜌i = 𝜌i
	round.temp.𝜈i = 𝜈i
	// retire unused variables
	round.temp.keyDerivationDelta = nil

	return nil
}

func (round *presign1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r1msgK {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *presign1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound1Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign1) NextRound() tss.Round {
	round.started = false
	// if round.runToDump {
	// 	return nil
	// }
	return &presign2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *presign1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	BigXs := round.key.BigXj

	// adding the key derivation delta to the xi's
	// Suppose x has shamir shares x_0,     x_1,     ..., x_n
	// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
	mod := common.ModInt(round.Params().EC().Params().N)
	xi = mod.Add(round.temp.keyDerivationDelta, xi)
	round.key.Xi = xi

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	if wi, BigWs, err := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs); err != nil {
		return err
	} else {
		round.temp.w = wi
		round.temp.BigWs = BigWs
	}

	return nil
}
