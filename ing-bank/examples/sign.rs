use anyhow::{bail};
use ecdsa_mpc::ecdsa::signature::{
    Phase1, SignedMessage
};

use crossbeam_channel::{Receiver, Sender};
use ecdsa_mpc::ecdsa::keygen::MultiPartyInfo;

use ecdsa_mpc::ecdsa::messages::signing::{InMsg, OutMsg};


use ecdsa_mpc::state_machine::sync_channels::StateMachine;


use ecdsa_mpc::protocol::{Address, InputMessage, PartyIndex};

use curv::elliptic::curves::traits::{ECScalar};
use sha2::{Sha256, Digest};
use curv::{BigInt, FE};


use std::thread::JoinHandle;
use std::{fs, env, thread, format};


fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    if args.len() < 2 {
        println!("usage: {} num-signers messagefile",args[0]);
        bail!("too few arguments")
    }

    let nsigner = args[1].parse::<usize>().unwrap();
    let msg = fs::read_to_string(args[2].clone()).unwrap();

    let parties = (0..nsigner)
        .map(|i| PartyIndex::from(i))
        .collect::<Vec<_>>();


    let mut hasher = Sha256::new();
    hasher.input(&msg);
    let msg_hash: FE = ECScalar::from(&BigInt::from(hasher.result().as_slice()));

    let mut nodes = Vec::new();
    let mut node_results = Vec::new();

    for i in 0..nsigner {
        let (protocol_sink, protocol_stream) = crossbeam_channel::unbounded();
        let (state_machine_sink, state_machine_stream) = crossbeam_channel::unbounded();

        let parties = parties.clone();
        let join_handle = thread::spawn(move || {
            let keys = fs::read_to_string(&format!("key.{}.json", i)).unwrap();
            let multi_party_shared_info: MultiPartyInfo = serde_json::from_str(&keys).unwrap();
            let start_phase = Box::new(Phase1::new(
                    msg_hash,
                    multi_party_shared_info,
                    &parties,
                    None,
                ).unwrap());
            let mut main_machine =
                StateMachine::new(start_phase, &protocol_stream, &state_machine_sink);
            // let machine_result = main_machine.execute();
            // let outcome = machine_result.transpose().unwrap().unwrap();
            match main_machine.execute() {
                Some(Ok(fs)) => Ok(fs),
                Some(Err(e)) => bail!("error {:?}", e),
                None => bail!("error in the machine"),
            }

            // let outcome = match machine_result.transpose() {
            //     Ok(Some(fs)) => Outcome::Signature(Ok(fs)),
            //     Ok(None) => {
            //         Outcome::Signature(Err(ErrorState::new(vec![SigningError::GeneralError("bug lmao".into())])))
            //     }
            //     Err(err) => Outcome::Signature(Err(err)),
            // };
            // outcome

            // println!("signature {} {:?}", i, outcome);
        });

        nodes.push(Node {
            party: PartyIndex::from(i),
            egress: state_machine_stream,
            ingress: protocol_sink,
        });
        node_results.push(NodeResult {
            index: i,
            join_handle,
        })
    }

    let _mx_thread = thread::spawn(move || {
        loop {
            let mut output_messages = Vec::new();
            // collect output from nodes
            for node in nodes.iter() {
                if let Ok(out_msg) = node.egress.try_recv() {
                    output_messages.push(OutputMessageWithSource {
                        msg: out_msg,
                        source: node.party,
                    });
                }
            }
            // forward collected messages
            output_messages
                .iter()
                .for_each(|mm| match &mm.msg.recipient {
                    Address::Broadcast => {
                        log::trace!(
                            "broadcast from {} to parties {:?}",
                            mm.source,
                            nodes
                                .iter()
                                .filter(|node| node.party != mm.source)
                                .map(|node| node.party)
                                .collect::<Vec<_>>()
                        );
                        nodes
                            .iter()
                            .filter(|node| node.party != mm.source)
                            .for_each(|node| {
                                let message_to_deliver = InputMessage {
                                    sender: mm.source,
                                    body: mm.msg.body.clone(),
                                };
                                node.ingress.send(message_to_deliver).unwrap();
                            });
                    }
                    Address::Peer(peer) => {
                        if let Some(node) = nodes.iter().find(|node| (*node).party == *peer) {
                            node.ingress
                                .send(InputMessage {
                                    sender: mm.source,
                                    body: mm.msg.body.clone(),
                                })
                                .unwrap();
                        }
                    }
                })
        }
    });


    let results = node_results
        .into_iter()
        .map(|h| (h.index, h.join_handle.join()))
        .collect::<Vec<_>>();


    for (index, result) in results.into_iter() {
        // safe to unwrap because results with errors cause the early exit
        let final_state = result.unwrap().unwrap();
        println!("state: {} {:?}", index, final_state);
    }

    Ok(())
}

struct Node {
    party: PartyIndex,
    egress: Receiver<OutMsg>,
    ingress: Sender<InMsg>,
}

struct NodeResult {
    index: usize,
    join_handle: JoinHandle<anyhow::Result<SignedMessage>>,
}

struct OutputMessageWithSource {
    msg: OutMsg,
    source: PartyIndex,
}

