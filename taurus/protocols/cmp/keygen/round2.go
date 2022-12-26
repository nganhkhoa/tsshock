package keygen

import (
	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"

	"encoding/hex"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	zkprm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
	"github.com/taurusgroup/multi-party-sig/verichains"
	"log"
	"math/big"
	"sync"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	ElGamalPublic map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// NModulus[j] = Nⱼ
	NModulus map[party.ID]*safenum.Modulus
	// S[j], T[j] = sⱼ, tⱼ
	S, T map[party.ID]*safenum.Nat

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *safenum.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ

	cond      *sync.Cond
	collected []types.RID
	es        []bool
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}
	r.Commitments[msg.From] = body.Commitment
	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send the message we created in Round1 to all
	err := r.BroadcastMessage(out, &broadcast3{
		RID:                r.RIDs[r.SelfID()],
		C:                  r.ChainKeys[r.SelfID()],
		VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		ElGamalPublic:      r.ElGamalPublic[r.SelfID()],
		N:                  r.NModulus[r.SelfID()],
		S:                  r.S[r.SelfID()],
		T:                  r.T[r.SelfID()],
		Decommitment:       r.Decommitment,
	})
	if err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{},
	}, nil
}

// PreviousRound implements round.Round.
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

type MaliciousRound2 interface {
	ReceiveRound2Message(msg *protocol.Message)
	Process(msg *protocol.Message) bool
}

func (r *round2) ReceiveRound2Message(msg *protocol.Message) {
	if !r.Malicious() {
		return
	}
	content := broadcast3{
		VSSPolynomial:      polynomial.EmptyExponent(curve.Secp256k1{}),
		SchnorrCommitments: zksch.EmptyCommitment(curve.Secp256k1{}),
		ElGamalPublic:      curve.Secp256k1{}.NewPoint(),
	}
	if err := cbor.Unmarshal(msg.Data, &content); err != nil {
		log.Fatal(err)
	}
	log.Printf("[%s] RID of %s: %s\n", r.SelfID(), msg.From, hex.EncodeToString(content.RID))

	r.cond.L.Lock()
	defer r.cond.L.Unlock()
	r.collected = append(r.collected, content.RID)
	if len(r.collected) == r.N() {
		r.cond.Signal()
	}
}

func (r *round2) Process(msg *protocol.Message) bool {
	if !r.Malicious() {
		return false
	}
	r.cond.L.Lock()
	defer r.cond.L.Unlock()
	for len(r.collected) != r.N() {
		log.Printf("[%s] Waiting for enough RIDs...\n", r.SelfID())
		r.cond.Wait()
		log.Printf("[%s] Done waiting for enough RIDs...\n", r.SelfID())
	}

	if r.es != nil { // 2nd pass
		return false
	}

	rid := types.EmptyRID()
	for _, j := range r.collected {
		rid.XOR(j)
	}
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	maliciousParams := verichains.DefaultMaliciousParams()
	public := zkprm.Public{
		N: arith.ModulusFromFactors(maliciousParams.P, maliciousParams.Q).Modulus,
		S: maliciousParams.H1,
		T: maliciousParams.H2,
	}
	var alphas [params.StatParam]*big.Int
	for i := 0; i < params.StatParam; i++ {
		alphas[i] = maliciousParams.Alpha0.Big()
	}
	countOfOne := 0
	for ; countOfOne <= params.StatParam; countOfOne++ {
		if countOfOne > 0 {
			alphas[countOfOne-1] = maliciousParams.Alpha1.Big()
		}
		es, _ := zkprm.Challenge(h.Clone(), public, alphas)

		actualCountOfOne := 0
		for j := 0; j < params.StatParam; j++ {
			if es[j] {
				actualCountOfOne += 1
			}
		}
		if countOfOne == actualCountOfOne {
			r.es = es
			break
		}
	}

	if r.es != nil {
		log.Printf("[%s] PROOF CAN BE FORGED!!!\n", r.SelfID())
		r.S[r.SelfID()] = maliciousParams.H1
		r.T[r.SelfID()] = maliciousParams.H2
		newData, err := cbor.Marshal(&broadcast3{
			RID:                r.RIDs[r.SelfID()],
			C:                  r.ChainKeys[r.SelfID()],
			VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
			SchnorrCommitments: r.SchnorrRand.Commitment(),
			ElGamalPublic:      r.ElGamalPublic[r.SelfID()],
			N:                  r.NModulus[r.SelfID()],
			S:                  r.S[r.SelfID()],
			T:                  r.T[r.SelfID()],
			Decommitment:       r.Decommitment,
		})
		if err != nil {
			log.Fatal(err)
		}
		msg.Data = newData
		return true
	} else {
		log.Printf("[%s] Proof could not be forged.\n", r.SelfID())
		return false
	}
}
