// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpfac "github.com/binance-chain/tss-lib/crypto/zkp/fac"

	// cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	zkpmod "github.com/binance-chain/tss-lib/crypto/zkp/mod"
	zkpprm "github.com/binance-chain/tss-lib/crypto/zkp/prm"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- LocalPartySaveData
	}

	localTempData struct {
		// temp data (thrown away after keygen)
		ui     *big.Int // used for tests
		ridi   *big.Int // used for tests
		rid    *big.Int
		shares vss.Shares
		vs     vss.Vs
		Ai     *crypto.ECPoint
		Xi     *crypto.ECPoint
		τ      *big.Int
		𝜓i     *zkpprm.ProofPrm

		r1msgVHashs []*big.Int
		r2msgVss    [][]*crypto.ECPoint
		r2msgAj     []*crypto.ECPoint
		r2msgXj     []*crypto.ECPoint
		r2msgRidj   []*big.Int
		r2msg𝜓j     []*zkpprm.ProofPrm
		r3msgxij    []*big.Int
		r3msgpfmod  []*zkpmod.ProofMod
		r3msgpffac  []*zkpfac.ProofFac
		r3msgpfsch  []*zkpsch.ProofSch
		r4msgpf     []*zkpsch.ProofSch
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
	optionalPreParams ...LocalPreParams,
) tss.Party {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
	if 0 < len(optionalPreParams) {
		if 1 < len(optionalPreParams) {
			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
		}
		if !optionalPreParams[0].Validate() {
			panic(errors.New("keygen.NewLocalParty: `optionalPreParams` failed to validate"))
		}
		data.LocalPreParams = optionalPreParams[0]
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs data init
	p.temp.r1msgVHashs = make([]*big.Int, partyCount)
	p.temp.r2msgVss = make([][]*crypto.ECPoint, partyCount)
	p.temp.r2msgAj = make([]*crypto.ECPoint, partyCount)
	p.temp.r2msgXj = make([]*crypto.ECPoint, partyCount)
	p.temp.r2msgRidj = make([]*big.Int, partyCount)
	p.temp.r2msg𝜓j = make([]*zkpprm.ProofPrm, partyCount)
	p.temp.r3msgxij = make([]*big.Int, partyCount)
	p.temp.r3msgpfmod = make([]*zkpmod.ProofMod, partyCount)
	p.temp.r3msgpffac = make([]*zkpfac.ProofFac, partyCount)
	p.temp.r3msgpfsch = make([]*zkpsch.ProofSch, partyCount)
	p.temp.r4msgpf = make([]*zkpsch.ProofSch, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *KGRound1Message:
		//p.temp.kgRound1Messages[fromPIdx] = msg // TODO remove
		r1msg := msg.Content().(*KGRound1Message)
		p.temp.r1msgVHashs[fromPIdx] = r1msg.UnmarshalVHash()
	case *KGRound2Message:
		//p.temp.kgRound2Messages[fromPIdx] = msg
		r2msg := msg.Content().(*KGRound2Message)
		p.data.PaillierPKs[fromPIdx] = r2msg.UnmarshalPaillierPK() // used in round 4
		p.data.NTildej[fromPIdx] = r2msg.UnmarshalNTilde()
		p.data.H1j[fromPIdx], p.data.H2j[fromPIdx] = r2msg.UnmarshalH1(), r2msg.UnmarshalH2()
		var err error
		p.temp.r2msgVss[fromPIdx], err = r2msg.UnmarshalVs(p.params.EC())
		p.temp.r2msgAj[fromPIdx], err = r2msg.UnmarshalAi(p.params.EC())
		p.temp.r2msgXj[fromPIdx], err = r2msg.UnmarshalXi(p.params.EC())
		if err != nil {
			return false, p.WrapError(err)
		}
		p.temp.r2msgRidj[fromPIdx] = r2msg.UnmarshalRidi()
		p.temp.r2msg𝜓j[fromPIdx], err = r2msg.UnmarshalProofPrm()
		if err != nil {
			return false, p.WrapError(err)
		}
	case *KGRound3Message:
		//p.temp.kgRound3Messages[fromPIdx] = msg
		r3msg := msg.Content().(*KGRound3Message)
		xij, err := p.data.PaillierSK.Decrypt(r3msg.UnmarshalShare())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgxij[fromPIdx] = xij
		proofMod, err := r3msg.UnmarshalProofMod()
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgpfmod[fromPIdx] = proofMod
		// if ok := proofMod.Verify(p.data.NTildej[fromPIdx]); !ok {
		// 	return false, p.WrapError(errors.New("proofMod verify failed"), p.params.Parties().IDs()[fromPIdx])
		// }

		proofFac, err := r3msg.UnmarshalProofFac()
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		// if ok := proofPrm.Verify(p.data.H1j[fromPIdx], p.data.H2j[fromPIdx], p.data.NTildej[fromPIdx]); !ok {
		// 	return false, p.WrapError(errors.New("proofPrm verify failed"), p.params.Parties().IDs()[fromPIdx])
		// }
		p.temp.r3msgpffac[fromPIdx] = proofFac

		proofSch, err := r3msg.UnmarshalProofSch(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgpfsch[fromPIdx] = proofSch
	case *KGRound4Message:
		//p.temp.kgRound4Messages[fromPIdx] = msg
		r4msg := msg.Content().(*KGRound4Message)
		proof, err := r4msg.UnmarshalProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r4msgpf[fromPIdx] = proof

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
