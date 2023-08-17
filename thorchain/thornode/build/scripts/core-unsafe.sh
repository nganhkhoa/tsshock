#!/bin/sh

set -o pipefail

add_account() {
  jq --arg ADDRESS "$1" --arg ASSET "$2" --arg AMOUNT "$3" '.app_state.auth.accounts += [{
        "@type": "/cosmos.auth.v1beta1.BaseAccount",
        "address": $ADDRESS,
        "pub_key": null,
        "account_number": "0",
        "sequence": "0"
    }]' <~/.thornode/config/genesis.json >/tmp/genesis.json
  mv /tmp/genesis.json ~/.thornode/config/genesis.json

  jq --arg ADDRESS "$1" --arg ASSET "$2" --arg AMOUNT "$3" '.app_state.bank.balances += [{
        "address": $ADDRESS,
        "coins": [ { "denom": $ASSET, "amount": $AMOUNT } ],
    }]' <~/.thornode/config/genesis.json >/tmp/genesis.json
  mv /tmp/genesis.json ~/.thornode/config/genesis.json
}

deploy_eth_contract() {
  echo "Deploying eth contracts"
  until curl -s "$1" 1>/dev/null 2>&1; do
    echo "Waiting for ETH node to be available ($1)"
    sleep 1
  done
  python3 scripts/eth/eth-tool.py --ethereum "$1" deploy --from_address 0x3fd2d4ce97b082d4bce3f9fee2a3d60668d2f473 >/tmp/contract.log 2>&1
  cat /tmp/contract.log
  CONTRACT=$(grep </tmp/contract.log "Vault Contract Address" | awk '{print $NF}')
  echo "Contract Address: $CONTRACT"

  set_eth_contract "$CONTRACT"
}

deploy_avax_contract() {
  echo "Deploying AVAX contracts"
  echo "$1/ext/bc/C/rpc"
  until curl -s "$1/ext/bc/C/rpc" 1>/dev/null 2>&1; do
    echo "Waiting for AVAX node to be available ($1)"
    sleep 1
  done
  python3 scripts/avax/avax-tool.py --avalanche "$1" deploy >/tmp/avax_contract.log 2>&1
  cat /tmp/avax_contract.log
  AVAX_CONTRACT=$(grep </tmp/avax_contract.log "AVAX Router Contract Address" | awk '{print $NF}')
  echo "AVAX Contract Address: $AVAX_CONTRACT"

  set_avax_contract "$AVAX_CONTRACT"
}

# If the AVAX Contract Needs to be manually set (if using a Local EVM fork for example), use this func
set_manual_avax_contract() {
  jq '.app_state.thorchain.chain_contracts += [{"chain": "AVAX", "router": "0xcbEAF3BDe82155F56486Fb5a1072cb8baAf547cc"}]' ~/.thornode/config/genesis.json >/tmp/genesis.json
  mv /tmp/genesis.json ~/.thornode/config/genesis.json
}

gen_bnb_address() {
  if [ ! -f ~/.bond/private_key.txt ]; then
    echo "Generating BNB address"
    mkdir -p ~/.bond
    # because the generate command can get API rate limited, THORNode may need to retry
    n=0
    until [ $n -ge 60 ]; do
      generate >/tmp/bnb && break
      n=$((n + 1))
      sleep 1
    done
    ADDRESS=$(grep </tmp/bnb MASTER= | awk -F= '{print $NF}')
    echo "$ADDRESS" >~/.bond/address.txt
    BINANCE_PRIVATE_KEY=$(grep </tmp/bnb MASTER_KEY= | awk -F= '{print $NF}')
    echo "$BINANCE_PRIVATE_KEY" >/root/.bond/private_key.txt
    PUBKEY=$(grep </tmp/bnb MASTER_PUBKEY= | awk -F= '{print $NF}')
    echo "$PUBKEY" >/root/.bond/pubkey.txt
    MNEMONIC=$(grep </tmp/bnb MASTER_MNEMONIC= | awk -F= '{print $NF}')
    echo "$MNEMONIC" >/root/.bond/mnemonic.txt
  fi
}
