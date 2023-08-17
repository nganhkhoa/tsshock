# THORNode Docker

## Fullnode

The default image will start a fullnode:

```bash
docker run -e CHAIN_ID=thorchain-mainnet-v1 -e NET=mainnet registry.gitlab.com/thorchain/thornode:chaosnet-multichain
```

The above command will result in syncing chain state to ephemeral storage within the container, in order to persist data across restarts simply mount a local volume:

```bash
mkdir thornode-data
docker run -v $(pwd)/thornode-data:/root/.thornode -e CHAIN_ID=thorchain-mainnet-v1 -e NET=mainnet registry.gitlab.com/thorchain/thornode:chaosnet-multichain
```

Nine Realms provides snapshots taken from a statesync recovery which can be rsync'd without need for a high memory (80G at time of writing) machine to recover the statesync snapshot. Ensure `gsutil` is installed, and pull the latest statesync snapshot via:

```bash
mkdir -p thornode-data/data
HEIGHT=$(
  curl -s 'https://storage.googleapis.com/storage/v1/b/public-snapshots-ninerealms/o?delimiter=%2F&prefix=thornode/pruned/' |
  jq -r '.prefixes | map(match("thornode/pruned/([0-9]+)/").captures[0].string) | map(tonumber) | sort | reverse[0]'
)
gsutil -m rsync -r -d "gs://public-snapshots-ninerealms/thornode/pruned/$HEIGHT/" thornode-data/data
docker run -v $(pwd)/thornode-data:/root/.thornode -e CHAIN_ID=thorchain-mainnet-v1 -e NET=mainnet registry.gitlab.com/thorchain/thornode:chaosnet-multichain
```

Since this image tag contains the latest version of THORNode, the node can auto update by simply placing this in a loop to re-pull the image on exit:

```bash
while true; do
  docker pull registry.gitlab.com/thorchain/thornode:chaosnet-multichain
  docker run -v $(pwd)/thornode-data:/root/.thornode -e NET=mainnet registry.gitlab.com/thorchain/thornode:chaosnet-multichain
do
```

The above commands also apply to `testnet` and `stagenet` by simply using the respective image (in these cases `-e NET=...` is not required):

```code
testnet  => registry.gitlab.com/thorchain/thornode:testnet
stagenet => registry.gitlab.com/thorchain/thornode:stagenet
```

## Validator

Officially supported deployments of THORNode validators require a working understanding of Kubernetes and related infrastructure. See the [Cluster Launcher](https://gitlab.com/thorchain/devops/cluster-launcher) repo for cluster Terraform resources, and the [Node Launcher](https://gitlab.com/thorchain/devops/node-launcher) repo for deployment utilities which internally leveraging Helm.

## Mocknet

The development environment leverages Docker Compose V2 to create a mock network - this is included in the latest version of Docker Desktop for Mac and Windows, and can be added as a plugin on Linux by following the instructions [here](https://docs.docker.com/compose/cli-command/#installing-compose-v2).

The mocknet configuration is vanilla, leveraging Docker Compose profiles which can be combined at user discretion. The following profiles exist:

```code
thornode => thornode only
bifrost  => bifrost and thornode dependency
midgard  => midgard and thornode dependency
mocknet  => all mocknet dependencies
```

### Keys

We leverage the following keys for testing and local mocknet setup, created with a simplified mnemonic for ease of reference. We refer to these keys by the name of the animal used:

```text
cat => cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat crawl
dog => dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog fossil
fox => fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox filter
pig => pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig quick
```

### Examples

Example commands are provided below for those less familiar with Docker Compose features:

```bash
# start a mocknet with all dependencies
docker compose --profile mocknet up -d

# multiple profiles are supported, start a mocknet and midgard
docker compose --profile mocknet --profile midgard up -d

# check running services
docker compose ps

# tail the logs of all services
docker compose logs -f

# tail the logs of only thornode and bifrost
docker compose logs -f thornode bifrost

# enter a shell in the thornode container
docker compose exec thornode sh

# copy a file from the thornode container
docker compose cp thornode:/root/.thornode/config/genesis.json .

# rebuild all buildable services (thornode and bifrost)
docker compose build

# export thornode genesis
docker compose stop thornode
docker compose run thornode -- thornode export
docker compose start thornode

# hard fork thornode
docker compose stop thornode
docker compose run /docker/scripts/hard-fork.sh

# stop mocknet services
docker compose --profile mocknet down

# clear mocknet docker volumes
docker compose --profile mocknet down -v
```

## Multi-Node Mocknet

The Docker Compose configuration has been extended to support a multi-node local network. Starting the multinode network requires the `mocknet-cluster` profile:

```bash
docker compose --profile mocknet-cluster up -d
```

Once the mocknet is running, you can open open a shell in the `cli` service to access CLIs for interacting with the mocknet:

```bash
docker compose run cli

# increase default 60 block churn (keyring password is "password")
thornode tx thorchain mimir CHURNINTERVAL 1000 --from dog $TX_FLAGS

# set limit to 1 new node per churn (keyring password is "password")
thornode tx thorchain mimir NUMBEROFNEWNODESPERCHURN 1 --from dog $TX_FLAGS
```

## Local Mainnet Fork of EVM Chain

Using hardhat, you can run a mainnet fork locally of any EVM chain and use it the mocknet stack. This allows you to interact with all of the DEXes, smart contracts
and Liquidity Pools deployed mainnet in your local mocknet environment. This simplifies testing EVM chain clients, routers, and aggregators.

This guide will go over how to fork AVAX C-Chain locally, and use it in the mocknet stack.

1. Spin up the local mocknet fork from your hardhat repo: (e.g. https://gitlab.com/thorchain/chains/avalanche)
2.

```bash
npx hardhat node --fork https://api.avax.network/ext/bc/C/rpc
```

2. Deploy any Router/Aggregator Contracts to your local mocknet fork using hardhat
3.
4. Point Bifröst at your local EVM node, and be sure to pass in a starting block height close to the tip, otherwise Bifröst will scan every block from 0:

```bash
AVAX_HOST=http://host.docker.internal:8545/ext/bc/C/rpc AVAX_START_BLOCK_HEIGHT=16467608 make reset-mocknet
```

## Bootstrap Mocknet Data

You can leverage the smoke tests to bootstrap local vaults with a subset of test data. Run:

```bash
make bootstrap-mocknet
```
