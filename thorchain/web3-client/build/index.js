"use strict";
var import_xchain_thorchain_query = require("@xchainjs/xchain-thorchain-query");
var import_xchain_client = require("@xchainjs/xchain-client");
var import_xchain_thorchain = require("@xchainjs/xchain-thorchain");
var import_xchain_thornode = require("@xchainjs/xchain-thornode");
const util = require("util");
const MIDGARD_URL = "http://192.168.1.151:8080";
const THORNODE_API_URL = "http://192.168.1.151:1317";
const THORNODE_RPC_URL = "http://192.168.1.151:26657";
const SEEDPHRASE = {
  cat: "cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat cat crawl",
  dog: "dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog dog fossil",
  fox: "fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox fox filter",
  pig: "pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig pig quick"
};
const midgardConf = {
  apiRetries: 3,
  midgardBaseUrls: [MIDGARD_URL]
};
const thornodeConf = {
  apiRetries: 3,
  thornodeBaseUrls: [THORNODE_API_URL]
};
const clientUrl = {
  mainnet: { node: THORNODE_API_URL, rpc: THORNODE_RPC_URL },
  stagenet: { node: THORNODE_API_URL, rpc: THORNODE_RPC_URL },
  testnet: { node: THORNODE_API_URL, rpc: THORNODE_RPC_URL }
};
const midgard = new import_xchain_thorchain_query.Midgard(import_xchain_client.Network.Testnet, midgardConf);
const thornode = new import_xchain_thorchain_query.Thornode(import_xchain_client.Network.Testnet, thornodeConf);
const thorchainQuery = new import_xchain_thorchain_query.ThorchainQuery(new import_xchain_thorchain_query.ThorchainCache(midgard, thornode));
const vaultApi = new import_xchain_thornode.VaultsApi(new import_xchain_thornode.Configuration({ basePath: THORNODE_API_URL }));
function printObj(obj) {
  console.log(util.inspect(obj, { colors: true, depth: 10 }));
}
function printBalance(allBalance) {
  const assets = [];
  for (const { asset, amount } of allBalance) {
    assets.push({
      asset: `${asset.chain}.${asset.symbol}`,
      amount: amount.amount().toString()
    });
  }
  printObj(assets);
}
const main = async () => {
  const thorClient = new import_xchain_thorchain.Client({ network: import_xchain_client.Network.Testnet, clientUrl });
  thorClient.setChainId("thorchain", import_xchain_client.Network.Testnet);
  const balance = await thorClient.getBalance("tthor1dcx60m4dxx7jcy97l26rk7j86hjjy900r9976h");
  printBalance(balance);
};
main().then(() => process.exit(0)).catch((err) => console.error(err));
//# sourceMappingURL=index.js.map
