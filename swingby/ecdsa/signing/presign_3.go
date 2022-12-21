// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound3(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}
}

func (round *presign3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 3.1 verify proofs received and decrypt alpha share of MtA output
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		Γj := round.temp.r2msgBigGammaShare[j]

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			DeltaD := round.temp.r2msgDeltaD[j]
			DeltaF := round.temp.r2msgDeltaF[j]
			proofAffgDelta := round.temp.r2msgDeltaProof[j]
			ok := proofAffgDelta.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, DeltaD, DeltaF, Γj)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg delta"))
				return
			}
			AlphaDelta, err := round.key.PaillierSK.Decrypt(DeltaD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.DeltaShareAlphas[j] = AlphaDelta
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ChiD := round.temp.r2msgChiD[j]
			ChiF := round.temp.r2msgChiF[j]
			proofAffgChi := round.temp.r2msgChiProof[j]
			ok := proofAffgChi.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, ChiD, ChiF, round.temp.BigWs[j])
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg chi"))
				return
			}
			AlphaChi, err := round.key.PaillierSK.Decrypt(ChiD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.ChiShareAlphas[j] = AlphaChi
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ψʹij := round.temp.r2msgProofLogstar[j]
			Gj := round.temp.r1msgG[j]
			ok := ψʹij.Verify(round.EC(), round.key.PaillierPKs[j], Gj, Γj, g, round.key.NTildei, round.key.H1i, round.key.H2i)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify logstar"))
				return
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round3: failed to verify proofs"), culprits...)
	}

	// Fig 7. Round 3.2 accumulate results from MtA
	Γ := round.temp.Γi
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		BigGammaShare := round.temp.r2msgBigGammaShare[j]
		var err error
		Γ, err = Γ.Add(BigGammaShare)
		if err != nil {
			return round.WrapError(errors.New("round3: failed to collect Γ"))
		}
	}
	Δi := Γ.ScalarMult(round.temp.ki)

	modN := common.ModInt(round.EC().Params().N)
	𝛿i := modN.Mul(round.temp.ki, round.temp.𝛾i)
	𝜒i := modN.Mul(round.temp.ki, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		𝛿i = modN.Add(𝛿i, round.temp.DeltaShareAlphas[j])
		𝛿i = modN.Add(𝛿i, round.temp.DeltaShareBetas[j])

		𝜒i = modN.Add(𝜒i, round.temp.ChiShareAlphas[j])
		𝜒i = modN.Add(𝜒i, round.temp.ChiShareBetas[j])
	}

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg = sync.WaitGroup{}
	round.temp.𝛿i = 𝛿i
	round.temp.𝜒i = 𝜒i
	round.temp.Δi = Δi
	round.temp.Γ = Γ

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ProofOut := make(chan *zkplogstar.ProofLogstar, 1)
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ψDoublePrimeji, err := zkplogstar.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, Δi, Γ, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.ki, round.temp.𝜌i)
			if err != nil {
				errChs <- round.WrapError(errors.New("proof generation failed"))
			}
			ProofOut <- ψDoublePrimeji
		}(j, Pj)

		ψDoublePrimeji := <-ProofOut
		r3msg := NewPreSignRound3Message(Pj, round.PartyID(), 𝛿i, Δi, ψDoublePrimeji)
		common.Logger.Debugf("party %v r3, NewPreSignRound3Message is going out to Pj %v", round.PartyID(), Pj)
		round.out <- r3msg
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	// retire unused variables
	round.temp.w = nil
	round.temp.BigWs = nil
	round.temp.Γi = nil

	round.temp.ChiShareBetas = nil
	round.temp.DeltaShareAlphas = nil
	round.temp.ChiShareAlphas = nil
	//
	round.temp.r2msgChiD = make([]*big.Int, round.PartyCount())
	round.temp.r2msgChiF = make([]*big.Int, round.PartyCount())
	round.temp.r2msgDeltaProof = make([]*zkpaffg.ProofAffg, round.PartyCount())
	round.temp.r2msgChiProof = make([]*zkpaffg.ProofAffg, round.PartyCount())
	round.temp.r2msgProofLogstar = make([]*zkplogstar.ProofLogstar, round.PartyCount())

	return nil
}

func (round *presign3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msg𝛿j {
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

func (round *presign3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign3) NextRound() tss.Round {
	round.started = false
	return &sign4{round, false}
}
