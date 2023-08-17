
## The PoC include:


A malicious bnb-chain/tss-lib which allows us to poison and capture the group’s private key.

A Main.sol to mock keepnetwork’s RandomBacon, SortitionPool smart contracts to simplify the selection and staking flow.

A hardhat config.js script to deploy the smart contracts and generate config for PoC nodes.

A hardhat invoke.js script to invoke new wallet (DKG flow)

A hardhat heartbeat.js script to simulate a heartbeat event which requires tbtcv2 nodes to jointly sign a heartbeat message. During the signing, the malicious node is going to recover the private key.

## Steps:

1. Download the v2.0.0-m3 source code from https://github.com/keep-network/keep-core/releases

3. For honest tbtc nodes  compile v2.0.0-m3  source code.

2. For malicious tbtc node: Add github.com/bnb-chain/tss-lib => ../binance-tss-lib-master into go.mod to replace normal binance tss lib to our malicious lib. Compile into one malicious tbtc node.


4. Run hardhat config.js to deploy smart contracts and generate config.toml to run nodes

5. Run both malicious node and honest node with the generated config.toml. 

6. Start the computing HTTP server at binance-tss-lib-master/verichains/scripts/app.py

6. Run hardhat invoke.js to request a new wallet. In the malicious console display a message “Generate malicious params for party-1”. It successfully poisoned other nodes. Record the wallet’s publickey and publickeyhash for next step

7. Run hardhat heartbeat.js against the last wallet publickeyhash to simulate a heartbeat event. In the malicious console displays a message “Secret Recover: {"private_key": "0xf9d6513d5f…” . It successfully recover the wallet privatekey. Verify the privatekey with the wallet publickey.

8. Use the private key to sign bitcoin transactions to drain the wallet’s fund.