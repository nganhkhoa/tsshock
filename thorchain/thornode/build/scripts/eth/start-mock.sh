#!/bin/sh

ETH_BLOCK_TIME="${ETH_BLOCK_TIME:=5}"

exec geth --dev --dev.period "$ETH_BLOCK_TIME" --verbosity 3 --networkid 15 --datadir "data" -mine --miner.threads 1 -http --http.addr 0.0.0.0 --http.port 8545 --allow-insecure-unlock --http.api "eth,net,web3,miner,personal,txpool,debug" --http.corsdomain "*" -nodiscover --http.vhosts="*"
