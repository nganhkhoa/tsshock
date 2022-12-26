package test

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"

	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			go func() {
				if mh, ok := h.(*protocol.MultiHandler); ok && msg.RoundNumber == 3 && msg.Protocol == "cmp/keygen-threshold" {
					mr := mh.GetRound(2).(keygen.MaliciousRound2)
					if mr.Process(msg) {
						mh.ReplaceBroadcastMsg(msg)
					}
				}
				network.Send(msg)
			}()

		// incoming messages
		case msg := <-network.Next(id):
			if mh, ok := h.(*protocol.MultiHandler); ok && msg.RoundNumber == 3 && msg.Protocol == "cmp/keygen-threshold" {
				mr := mh.GetRound(2).(keygen.MaliciousRound2)
				mr.ReceiveRound2Message(msg)
			}
			h.Accept(msg)
		}
	}
}
