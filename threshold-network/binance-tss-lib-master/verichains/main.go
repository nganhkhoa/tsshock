package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"reflect"
	"strings"

	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	ecdsasigning "github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

func genPaillierKey(path string) {
	preParams, err := ecdsakeygen.GeneratePreParamsWithContext(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	tmp, err := json.Marshal(preParams)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, tmp, 0666); err != nil {
		log.Fatal(err)
	}
}

func loadPaillierKey(path string) *ecdsakeygen.LocalPreParams {
	data, err := os.ReadFile(path)
	if err != nil {
		// generate a new Paillier key at this path then retry
		genPaillierKey(path)
		if data, err = os.ReadFile(path); err != nil {
			log.Fatal(err)
		}
	}
	var result ecdsakeygen.LocalPreParams
	if err := json.Unmarshal(data, &result); err != nil {
		log.Fatal(err)
	}
	return &result
}

func prepare(n, t int) []*tss.Parameters {
	parties := make([]*tss.PartyID, n)

	// n-1 honest parties
	for i := 1; i < n; i++ {
		parties[i-1] = &tss.PartyID{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      fmt.Sprintf("%d", i),
				Moniker: fmt.Sprintf("party-%d", i),
				Key:     big.NewInt(int64(i)).Bytes(),
			},
		}
	}

	// the malicious party
	parties[n-1] = &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      "1337",
			Moniker: "party-1337",
			Key:     []byte{1337 >> 8, 1337 & 255},
		},
	}

	peerCtx := tss.NewPeerContext(tss.SortPartyIDs(parties, 0))
	params := make([]*tss.Parameters, n)
	for i := 0; i < n; i++ {
		params[i] = tss.NewParameters(tss.S256(), peerCtx, parties[i], n, t)
	}
	return params
}

func forwardMsg(parties []tss.Party, msg tss.Message) {
	data, routing, err := msg.WireBytes()
	if err != nil {
		log.Fatal(err)
	}
	if routing.IsBroadcast {
		routing.To = make([]*tss.PartyID, 0)
		for _, party := range parties {
			partyId := party.PartyID()
			if strings.Compare(partyId.Id, routing.From.Id) == 0 {
				continue
			}
			routing.To = append(routing.To, partyId)
		}
	}
	for _, recipient := range routing.To {
		go func(to *tss.PartyID) {
			ok, err := parties[to.Index].UpdateFromBytes(data, routing.From, routing.IsBroadcast)
			if !ok || err != nil {
				log.Fatal(err)
			}
		}(recipient)
	}
}

func keygen(params []*tss.Parameters) []ecdsakeygen.LocalPartySaveData {
	// create the parties
	n := len(params)
	outChs := make([]chan tss.Message, n)
	endChs := make([]chan ecdsakeygen.LocalPartySaveData, n)
	parties := make([]tss.Party, n)
	for i := 0; i < n; i++ {
		outChs[i] = make(chan tss.Message)
		endChs[i] = make(chan ecdsakeygen.LocalPartySaveData)
		parties[i] = ecdsakeygen.NewLocalParty(params[i], outChs[i], endChs[i],
			*loadPaillierKey(fmt.Sprintf("valid_key_%d.json", i)))
		go func(idx int) {
			if err := parties[idx].Start(); err != nil {
				log.Fatal(err)
			}
		}(i)
	}

	// simulate the keygen protocol
	ended := 0
	saveData := make([]ecdsakeygen.LocalPartySaveData, n)
	cases := make([]reflect.SelectCase, n*2)
	for i := 0; i < n; i++ {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(outChs[i])}
		cases[n+i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(endChs[i])}
	}
	for {
		chosen, value, ok := reflect.Select(cases)
		if !ok {
			log.Fatal("channel unexpectedly closed")
		}
		if chosen < n { // an `out` channel
			msg := value.Interface().(tss.Message)
			forwardMsg(parties, msg)
		} else { // an `end` channel
			ended += 1
			saveData[chosen-n] = value.Interface().(ecdsakeygen.LocalPartySaveData)
			if ended == n {
				break
			}
		}
	}
	return saveData
}

func sign(params []*tss.Parameters, partiesData []ecdsakeygen.LocalPartySaveData, msg string) {
	toBeSigned := new(big.Int).SetBytes([]byte(msg))

	// create the parties
	n := len(params)
	outChs := make([]chan tss.Message, n)
	endChs := make([]chan common.SignatureData, n)
	parties := make([]tss.Party, n)
	for i := 0; i < n; i++ {
		outChs[i] = make(chan tss.Message)
		endChs[i] = make(chan common.SignatureData)
		parties[i] = ecdsasigning.NewLocalParty(toBeSigned, params[i], partiesData[i], outChs[i], endChs[i])
		go func(idx int) {
			if err := parties[idx].Start(); err != nil {
				log.Fatal(err)
			}
		}(i)
	}

	// simulate the signing protocol
	ended := 0
	cases := make([]reflect.SelectCase, n*2)
	for i := 0; i < n; i++ {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(outChs[i])}
		cases[n+i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(endChs[i])}
	}
	for {
		chosen, value, ok := reflect.Select(cases)
		if !ok {
			log.Fatal("channel unexpectedly closed")
		}
		if chosen < n { // an `out` channel
			msg := value.Interface().(tss.Message)
			forwardMsg(parties, msg)
		} else { // an `end` channel
			ended += 1
			if ended == n {
				break
			}
		}
	}
}

func main() {
	n := 5
	fmt.Printf("Total parties: %d.\n", n)
	params := prepare(n, n-1)

	fmt.Println("Running tss-ecdsa-keygen protocol...")
	saveData := keygen(params)
	fmt.Println("Secret shares:")
	for _, data := range saveData {
		fmt.Printf("(%d, %d)\n", data.ShareID, data.Xi)
	}
	publicKey := saveData[0].ECDSAPub
	fmt.Printf("Public key: (%d, %d)\n", publicKey.X(), publicKey.Y())

	fmt.Println("Running tss-ecdsa-signing protocol...")
	sign(params, saveData, "sign me!")
	fmt.Println("Done!")
}
