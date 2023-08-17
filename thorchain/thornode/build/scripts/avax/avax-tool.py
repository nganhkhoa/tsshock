import argparse
import json
import logging
import os
import socket
import sys
import time
from contextlib import closing
from urllib.parse import urlparse

import requests
from web3 import HTTPProvider, Web3
from web3.middleware import geth_poa_middleware

logging.basicConfig(level=logging.INFO)


class TestAvalanche:
    """
    An client implementation for a localnet Avalanche network
    """

    default_gas = 65000
    name = "Avalanche"
    gas_per_byte = 68
    chain = "AVAX"
    passphrase = "the-passphrase"
    tokens = dict()
    zero_address = "0x0000000000000000000000000000000000000000"

    # local network
    local_address = "0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"
    local_pk = "56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027"
    router_address = "0x17aB05351fC94a1a67Bf3f56DdbB941aE6c63E25"

    # local fork
    # local_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    # local_pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    # router_address = "0xcbEAF3BDe82155F56486Fb5a1072cb8baAf547cc"
    agg_address = "0x1429859428C0aBc9C2C47C8Ee9FBaf82cFA0F20f"

    private_keys = [
        "56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url):
        self.rpc_url = base_url + "/ext/bc/C/rpc"
        self.keystore_url = base_url + "/ext/keystore"
        self.avax_url = base_url + "/ext/bc/C/avax"
        self.web3 = Web3(HTTPProvider(self.rpc_url))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        headers = {"content-type": "application/json", "cache-control": "no-cache"}

        # Create local wallet
        createUserPayload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "keystore.createUser",
                "params": {"username": "thorchain", "password": "yggdrasil123!"},
            }
        )

        try:
            requests.request(
                "POST", self.keystore_url, data=createUserPayload, headers=headers
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"{e}")

        # Fund local wallet
        fundUserPayload = json.dumps(
            {
                "method": "avax.importKey",
                "params": {
                    "username": "thorchain",
                    "password": "yggdrasil123!",
                    "privateKey": "PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN",
                },
                "jsonrpc": "2.0",
                "id": 1,
            }
        )

        try:
            requests.request(
                "POST", self.avax_url, data=fundUserPayload, headers=headers
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"{e}")

        # fund mocknet/smoke test keys
        for key in self.private_keys:
            payload = json.dumps(
                {"method": "personal_importRawKey", "params": [key, self.passphrase]}
            )
            headers = {"content-type": "application/json", "cache-control": "no-cache"}
            try:
                requests.request("POST", self.rpc_url, data=payload, headers=headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"{e}")

        self.accounts = self.web3.geth.personal.list_accounts()
        self.web3.eth.defaultAccount = self.accounts[0]
        self.web3.geth.personal.unlock_account(self.accounts[0], self.passphrase)

        logging.info(f"balance: {self.web3.eth.getBalance(self.accounts[0])}")
        for x in range(1, len(self.accounts)):
            self.fund_account(
                self.accounts[0], self.accounts[1], 9200000000000000000, x == 1
            )

        self.web3.eth.defaultAccount = self.accounts[1]
        self.web3.geth.personal.unlock_account(
            self.web3.eth.defaultAccount, self.passphrase
        )

    def fund_account(self, from_address, to_address, amount, wait_for_commit):
        tx = {
            "from": Web3.toChecksumAddress(from_address),
            "to": Web3.toChecksumAddress(to_address),
            "value": amount,
            "gas": self.calculate_gas(""),
        }
        if wait_for_commit:
            # wait for the transaction to be mined
            tx_hash = self.web3.geth.personal.sendTransaction(tx, self.passphrase)
            self.web3.eth.waitForTransactionReceipt(tx_hash)

    def calculate_gas(self, msg):
        return self.default_gas + self.gas_per_byte * len(msg)

    def deploy_init_contracts(self):
        self.vault = self.deploy_vault()
        token = self.deploy_token()
        symbol = token.functions.symbol().call()
        logging.info(f"AVAX Token Symbol: {symbol}")
        self.tokens[symbol] = token

    def get_token_balance(self, symbol, address):
        token_abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "data_token.json"))
        )
        token = self.web3.eth.contract(
            address="0x333c3310824b7c685133F2BeDb2CA4b8b4DF633d", abi=token_abi
        )
        balance = token.functions.balanceOf(Web3.toChecksumAddress(address)).call()
        logging.info(f"TKN Token Balance: {balance}")

    def deploy_token(self, abi_file="data_token.json", bytecode_file="data_token.txt"):
        abi = json.load(open(os.path.join(os.path.dirname(__file__), abi_file)))
        bytecode = open(
            os.path.join(os.path.dirname(__file__), bytecode_file), "r"
        ).read()
        token = self.web3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = token.constructor().transact()
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        logging.info(f"AVAX Token Contract Address: {receipt.contractAddress}")
        return self.web3.eth.contract(address=receipt.contractAddress, abi=abi)

    def deploy_vault(self):
        abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "router-abi.json"))
        )
        bytecode = open(
            os.path.join(os.path.dirname(__file__), "router-bytecode.txt"), "r"
        ).read()
        vault = self.web3.eth.contract(abi=abi, bytecode=bytecode)

        try:
            deploy_tx = vault.constructor().buildTransaction(
                {
                    "chainId": 43112,
                    "from": Web3.toChecksumAddress(self.local_address),
                    "nonce": 1,
                }
            )

            signed_txn = self.web3.eth.account.sign_transaction(
                deploy_tx, private_key=self.local_pk
            )
            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)

            receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
            logging.info(f"AVAX Router Contract Address: {receipt.contractAddress}")
            logging.info(f"tx receipt: {receipt}")
            return self.web3.eth.contract(address=receipt.contractAddress, abi=abi)
        except requests.exceptions.RequestException as e:
            logging.error(f"{e}")

    def get_vault(self):
        url = "http://localhost:1317/thorchain/inbound_addresses"
        resp = requests.get(url)
        data = resp.json()

        for vault in data:
            if vault["chain"] == "AVAX":
                return vault["address"]

        raise ValueError("Could not find AVAX vault")

    def get_router(self):
        url = "http://localhost:1317/thorchain/inbound_addresses"
        resp = requests.get(url)
        data = resp.json()

        for vault in data:
            if vault["chain"] == "AVAX":
                return vault["router"]

        raise ValueError("Could not find AVAX router")

    def swap_in(self):
        abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "aggregator-abi.json"))
        )
        aggregator = self.web3.eth.contract(address=self.agg_address, abi=abi)

        vaultAddr = self.get_vault()
        router = self.get_router()

        # approve spending
        amount = 1000000000
        token_abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "data_token.json"))
        )
        token = self.web3.eth.contract(
            address="0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664", abi=token_abi
        )
        approve_tx_hash = token.functions.approve(
            Web3.toChecksumAddress(aggregator.address), amount
        ).transact()
        approve_receipt = self.web3.eth.waitForTransactionReceipt(approve_tx_hash)
        logging.info(f"Approve spending: {approve_receipt}")

        # add_liq_memo = "ADD:AVAX.AVAX:tthor1uuds8pd92qnnq0udw0rpg0szpgcslc9p8lluej"
        swap_memo = "SWAP:THOR.RUNE:tthor1uuds8pd92qnnq0udw0rpg0szpgcslc9p8lluej"
        swap_in_tx = aggregator.functions.swapIn(
            Web3.toChecksumAddress(vaultAddr),
            Web3.toChecksumAddress(router),
            swap_memo,
            "0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664",
            amount,
            0,
            1656540955,
        ).buildTransaction(
            {
                "from": Web3.toChecksumAddress(self.local_address),
                "nonce": self.web3.eth.get_transaction_count(
                    Web3.toChecksumAddress(self.local_address)
                ),
            }
        )
        signed_txn = self.web3.eth.account.sign_transaction(
            swap_in_tx, private_key=self.local_pk
        )
        tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)

        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        logging.info(f"Swap in result: {receipt}")

    def deposit_avax(self):
        abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "router-abi.json"))
        )
        router = self.web3.eth.contract(address=self.router_address, abi=abi)
        vaultAddr = self.get_vault()

        add_liq_memo = "ADD:AVAX.AVAX:tthor1uuds8pd92qnnq0udw0rpg0szpgcslc9p8lluej"
        # swap_memo = "SWAP:THOR.RUNE:tthor1uuds8pd92qnnq0udw0rpg0szpgcslc9p8lluej"

        tx_hash = router.functions.deposit(
            Web3.toChecksumAddress(vaultAddr),
            Web3.toChecksumAddress(self.zero_address),
            0,
            add_liq_memo,
        ).transact(
            {
                "value": 2000000000000000000,
            }
        )

        logging.info(f"deposit AVAX tx_hash {tx_hash}")

        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        logging.info(f"deposit AVAX receipt {receipt}")

    def deposit_tkn(self, amount, memo):
        abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "router-abi.json"))
        )
        router = self.web3.eth.contract(address=self.router_address, abi=abi)
        token_abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "data_token.json"))
        )
        token = self.web3.eth.contract(
            address="0x333c3310824b7c685133F2BeDb2CA4b8b4DF633d", abi=token_abi
        )
        routerAddr = self.get_router()
        vaultAddr = self.get_vault()

        tx_hash = token.functions.approve(
            Web3.toChecksumAddress(routerAddr), amount
        ).transact()
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        logging.info(f"approve receipt {receipt}")

        tx_hash = router.functions.deposit(
            Web3.toChecksumAddress(vaultAddr),
            "0x333c3310824b7c685133F2BeDb2CA4b8b4DF633d",
            amount,
            memo,
        ).transact()
        logging.info(f"deposit TKN tx_hash {tx_hash}")
        dep_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        logging.info(f"deposit receipt {dep_receipt}")

    def vault_allowance(self):
        abi = json.load(
            open(os.path.join(os.path.dirname(__file__), "router-abi.json"))
        )
        vault = self.web3.eth.contract(address=self.router_address, abi=abi)

        result = vault.functions.vaultAllowance(
            Web3.toChecksumAddress("0x4e69a32cadca96d05b216577d2a4fe2fb14fbf57"),
            self.zero_address,
        ).call()
        logging.info(f"Vault allowance result: {result}")


def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


def main():
    parser = argparse.ArgumentParser()
    # avalanche daemon address
    parser.add_argument(
        "--avalanche",
        default="",
        help="avalanche daemon address",
    )

    parser.add_argument(
        "--action",
        default="",
        help="deposit action",
    )

    subparsers = parser.add_subparsers()

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.set_defaults(name="deploy")

    deposit_parser = subparsers.add_parser("deposit")
    deposit_parser.set_defaults(name="deposit")

    swap_in_parser = subparsers.add_parser("swap_in")
    swap_in_parser.set_defaults(name="swap_in")

    balance_parser = subparsers.add_parser("balance")
    balance_parser.set_defaults(name="balance")

    deposit_tkn_parser = subparsers.add_parser("deposit_tkn")
    deposit_tkn_parser.set_defaults(name="deposit_tkn")

    args = parser.parse_args()
    defaultAVAX = "http://127.0.0.1:9650"
    if "CI" in os.environ:
        defaultAVAX = "http://127.0.0.1:9650"
    if args.avalanche is None or args.avalanche == "":
        args.avalanche = defaultAVAX

    logging.info(f"AVAX endpoint: {args.avalanche}")

    # check that the port is open
    t = urlparse(args.avalanche)
    for i in range(1, 30):
        if check_socket(t.hostname, t.port):
            time.sleep(5)
            break
        if i == 30:
            logging.info("Avalanche node does not appear to be running... exiting")
            sys.exit(1)
        time.sleep(1)

    test_avalanche = TestAvalanche(args.avalanche)

    if args.name == "deploy":
        logging.info("Deploying contracts...")
        test_avalanche.deploy_init_contracts()
    if args.name == "deposit":
        logging.info("Depositing to AVAX Router")
        test_avalanche.deposit_avax()
    if args.name == "swap_in":
        logging.info("Swapping in")
        test_avalanche.swap_in()
    if args.name == "allowance":
        logging.info("Checking vault allowance")
        test_avalanche.vault_allowance()
    if args.name == "balance":
        logging.info("Checking token balance for address")
        test_avalanche.get_token_balance(
            "TKN", "0xf6da288748ec4c77642f6c5543717539b3ae001b"
        )
    if args.name == "deposit_tkn":
        logging.info("Depositing tkn")
        test_avalanche.deposit_tkn(
            1000000000000000000,
            "ADD:AVAX.TKN-0X333C3310824B7C685133F2BEDB2CA4B8B4DF633D:tthor1uuds8pd92qnnq0udw0rpg0szpgcslc9p8lluej",
        )

    logging.info("Done.")


if __name__ == "__main__":
    main()
