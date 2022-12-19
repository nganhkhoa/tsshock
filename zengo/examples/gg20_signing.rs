use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt, TryStreamExt};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

use serde_json::json;
use reqwest::Url;
use reqwest::Client as HttpClient;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
    #[structopt(short, long)]
    local_share: PathBuf,

    #[structopt(short, long, use_delimiter(true))]
    parties: Vec<u16>,
    #[structopt(short, long)]
    data_to_sign: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
    let number_of_parties = args.parties.len();

    let (i, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (i, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let leaked = completed_offline_stage.leaked.clone();
    let (mut signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(args.data_to_sign.as_bytes()),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    let signature = serde_json::to_string(&signature).context("serialize signature")?;

    println!("{}", signature);



    let host = "localhost";
    let port = 1337;
    let root = Url::parse(&format!("http://{}:{}", host, port)).unwrap();
    let client = HttpClient::new();

    client
        .post(root.join("create-session").unwrap())
        .body(json!({"sess_id": i, "i": i}).to_string())
        .send()
        .await
        .unwrap();

    let leaked_read = leaked.lock().unwrap().clone();
    let m = leaked_read.m.unwrap().to_string();
    let rx = leaked_read.rx.unwrap().to_string();
    let ry = leaked_read.ry.unwrap().to_string();
    let s = leaked_read.s.unwrap().to_string();
    let k_i = leaked_read.k_i.unwrap().to_string();
    let h1_pow_k_j = leaked_read.h1_pow_k_j.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let tosend = json!({
        "sess_id": i,
        "m": m,
        "rx": rx,
        "ry": ry,
        "s": s,
        "k_i": k_i,
        "h1_pow_k_j": h1_pow_k_j,
    });

    println!("{}", tosend.to_string());
    client
        .post(root.join("submit-data").unwrap())
        .body(tosend.to_string())
        .send()
        .await
        .unwrap();

    Ok(())
}
