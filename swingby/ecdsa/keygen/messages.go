// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	zkpfac "github.com/binance-chain/tss-lib/crypto/zkp/fac"
	zkpmod "github.com/binance-chain/tss-lib/crypto/zkp/mod"
	zkpprm "github.com/binance-chain/tss-lib/crypto/zkp/prm"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message)(nil),
		(*KGRound3Message)(nil),
		(*KGRound4Message)(nil),
	}
)

// ----- //

func NewKGRound1Message(
	from *tss.PartyID,
	VHash *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		VHash: VHash.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetVHash())
}

func (m *KGRound1Message) UnmarshalVHash() *big.Int {
	return new(big.Int).SetBytes(m.GetVHash())
}

// ----- //

func NewKGRound2Message(
	from *tss.PartyID,
	vs vss.Vs,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I, ridi *big.Int,
	Ai, Xi *crypto.ECPoint,
	𝜓i *zkpprm.ProofPrm,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	vs_flat, _ := crypto.FlattenECPoints(vs)
	vsbzs := make([][]byte, len(vs_flat))
	for i, item := range vs_flat {
		vsbzs[i] = item.Bytes()
	}
	aiBytes := Ai.Bytes()
	XiBytes := Xi.Bytes()
	𝜓iBytes := 𝜓i.Bytes()
	content := &KGRound2Message{
		Vs:        vsbzs[:],
		PaillierN: paillierPK.N.Bytes(),
		NTilde:    nTildeI.Bytes(),
		H1:        h1I.Bytes(),
		H2:        h2I.Bytes(),
		Ridi:      ridi.Bytes(),
		Ai:        aiBytes[:],
		Xi:        XiBytes[:],
		PrmProof:  𝜓iBytes[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		common.NonEmptyMultiBytes(m.GetAi()) &&
		common.NonEmptyMultiBytes(m.GetXi())
}

func (m *KGRound2Message) UnmarshalVs(ec elliptic.Curve) ([]*crypto.ECPoint, error) {
	bzs := m.GetVs()
	vs_points := make([]*big.Int, len(bzs))
	for i, item := range m.GetVs() {
		vs_points[i] = new(big.Int).SetBytes(item)
	}
	vs, err := crypto.UnFlattenECPoints(ec, vs_points)
	if err != nil {
		return nil, err
	}
	return vs, nil
}

func (m *KGRound2Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound2Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound2Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound2Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound2Message) UnmarshalAi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetAi())
}

func (m *KGRound2Message) UnmarshalXi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetXi())
}

func (m *KGRound2Message) UnmarshalRidi() *big.Int {
	return new(big.Int).SetBytes(m.GetRidi())
}

func (m *KGRound2Message) UnmarshalProofPrm() (*zkpprm.ProofPrm, error) {
	return zkpprm.NewProofFromBytes(m.PrmProof)
}

// ----- //

func NewKGRound3Message(
	to, from *tss.PartyID,
	share *big.Int,
	𝜓i *zkpmod.ProofMod,
	𝜙ji *zkpfac.ProofFac,
	𝜓ij *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	proofModBzs := 𝜓i.Bytes()
	proofFacBzs := 𝜙ji.Bytes()
	proofPsiiBzs := 𝜓ij.Bytes()
	content := &KGRound3Message{
		Share:     share.Bytes(),
		ModProof:  proofModBzs[:],
		FacProof:  proofFacBzs[:],
		PsiiProof: proofPsiiBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare()) &&
		common.AnyNonEmptyMultiByte(m.GetModProof(), zkpmod.ProofModBytesParts) &&
		common.NonEmptyMultiBytes(m.GetFacProof()) &&
		common.NonEmptyMultiBytes(m.GetPsiiProof(), zkpsch.ProofSchBytesParts)
}

func (m *KGRound3Message) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

func (m *KGRound3Message) UnmarshalProofMod() (*zkpmod.ProofMod, error) {
	return zkpmod.NewProofFromBytes(m.GetModProof())
}

func (m *KGRound3Message) UnmarshalProofFac() (*zkpfac.ProofFac, error) {
	return zkpfac.NewProofFromBytes(m.GetFacProof())
}

func (m *KGRound3Message) UnmarshalProofSch(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetPsiiProof())
}

// ----- //

func NewKGRound4Message(
	from *tss.PartyID,
	proof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := proof.Bytes()
	content := &KGRound4Message{
		Proof: pfBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetProof(), zkpsch.ProofSchBytesParts)
}

func (m *KGRound4Message) UnmarshalProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProof())
}
