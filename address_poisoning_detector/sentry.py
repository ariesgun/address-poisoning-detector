import pathlib
import requests
import time
import uuid

from typing import List


from sentinel.definitions import BLOCKCHAIN
from sentinel.sentry.v2.block_tx import BlockTxDetector
from sentinel.models.database import Database
from sentinel.models.event import Event, Blockchain
from sentinel.models.transaction import Transaction
from sentinel.db.contract.abi.erc20 import ERC20 as ERC20_ABI
from sentinel.utils.web3 import get_async_web3
from sentinel.utils.transaction import filter_events
from sentinel.db.contract.abi.static import ABI_EVENT_TRANSFER
from sentinel.db.label_db.local import LabelDB


class V2LabelDB(LabelDB):
    
    def __init__(
        self,
        path: pathlib.Path,
        update_tags: List[str] = [],
        update_interval: int = 120,
        **kwargs,
    ) -> None:
        """
        Label DB Init
        """
        super().__init__(path, update_tags, update_interval, **kwargs)
    
    @classmethod
    def from_settings(cls, settings: Database, **kwargs):
        path = settings.parameters.pop("path")
        # cls.logger.info(f"Init ... {path}")
        kwargs.update(settings.parameters)
        return cls(path=path, **kwargs)
    

class AddressPoisoningDetector(BlockTxDetector):
    name = "BalanceMonitor"
    description = "Monitors Account/Contract balance (native token)"

    async def on_init(self):
        self.logger.info("init")
        # addresses: list = self.databases.address.all()
        addresses = []

        rpc_url = self.parameters.get("rpc")
        self.w3 = get_async_web3(rpc_url)

        self.native = self.parameters.get("native", "ETH")
        self.balances = {a: 0 for a in addresses}
        self.erc20_balances = {a: 0 for a in addresses}

        self.decimals = 10 ** self.parameters.get("decimals", 18)
        # self.threshold = self.parameters.get("balance_threshold")
        self.logger.info(self.parameters)
        # self.erc20_addr = self.parameters.get("erc20_addr").lower()
        # self.erc20_decimals = 10 ** self.parameters.get("erc20_decimals", 18)
        # self.erc20_balance_threshold = self.parameters.get("erc20_balance_threshold", 0)
        # Change to 0.14 when new FrontEnd UI is ready
        self.severity = self.parameters.get("severity", 0.15)

        # await self.databases.label.add("0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5", ["whale"], "")
        self._whale_wallets = await self.databases.label.search_by_tag(["whale"])
        self._whale_wallet_map = {}
        for _whale in self._whale_wallets:
            self._whale_wallet_map[_whale.address] = {
                "balance": 0,
                "to": [],
                "poisoned_address": []
            }

        self.retrieve_tokens()
        await self.calculate_address_balance("0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5")

        # self.erc20_contract = self.w3.eth.contract(address=self.w3.to_checksum_address(self.erc20_addr), abi=ERC20_ABI)

        # self.erc20_token = await self.erc20_contract.functions.symbol().call()

        # self.logger.info(
        #     f"Native ({self.native}) balance threshold: {self.threshold} ({self.threshold / self.decimals})"
        # )
        # self.logger.info(
        #     f"ERC20 ({self.erc20_token}/{self.erc20_addr}): balance threshold: {self.erc20_balance_threshold} ({self.erc20_balance_threshold / self.erc20_decimals})"
        # )

        self.balances = {a: await self.check_addr(a, None) for a in addresses}
        # self.erc20_balances = {a: await self.check_erc20_addr(a, None) for a in addresses}

        for addr, bal in self.balances.items():
            self.logger.info(f"Initial Native ({self.native}) balance: {addr}: {bal} ({bal / self.decimals})")

        # for addr, bal in self.erc20_balances.items():
        #     self.logger.info(f"Initial ERC20 ({self.erc20_token}) balance: {addr}: {bal} ({bal / self.erc20_decimals})")


    def retrieve_tokens(self):
        self.erc20_token_address_map = {}

        url = 'https://api.coingecko.com/api/v3/coins/markets'
        params = {  
            'order': 'market_cap_desc',
            'vs_currency': 'usd',
            'category': 'ethereum-ecosystem',
            'per_page': '8'
        }
        headers = { 
            'x-cg-demo-api-key': 'CG-KMa6FtrxFXynowqRYUzWyK2T',
            'accept': 'application/json' 
        }

        try:
            response = requests.get(url, params = params, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            print ("OOps: Something Else",err)

        # self.logger.info(f"........ {response.json()}")
        for token in response.json():
            self.logger.info(f"id: {token['id']}")

            try:
                coin_resp = requests.get(
                    f"https://api.coingecko.com/api/v3/coins/{token['id']}",
                    params = {
                        'localization': 'false',
                        'tickers': 'false',
                        'market_data': 'true',
                        'community_data': 'false',
                        'developer_data': 'false',
                        'sparkline': 'false'
                    },
                    headers = {
                        'x-cg-demo-api-key': 'CG-KMa6FtrxFXynowqRYUzWyK2T',
                        'accept': 'application/json' 
                    }
                )
                coin_resp.raise_for_status()

                payload = coin_resp.json()
                if ("ethereum" in payload["detail_platforms"]):
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]] = payload["detail_platforms"]["ethereum"]
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["id"] = token["id"]
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["price"] = token["current_price"]
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["symbol"] = token["symbol"]
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["name"] = token["name"]
                    self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["contract"] = \
                        self.w3.eth.contract(address=self.w3.to_checksum_address(self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]["contract_address"]), abi=ERC20_ABI)
            
                    self.logger.info(f'{self.erc20_token_address_map[payload["detail_platforms"]["ethereum"]["contract_address"]]}')
                else:
                    self.eth_price = token["current_price"]

            except requests.exceptions.HTTPError as errh:
                print ("Http Error:",errh)
            except requests.exceptions.ConnectionError as errc:
                print ("Error Connecting:",errc)
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error:",errt)
            except requests.exceptions.RequestException as err:
                print ("OOps: Something Else",err)

    async def calculate_address_balance(self, addr: str) -> int:
        total_usd = 0

        # Native token ETH
        balance = await self.ask_balance(addr)
        total_usd += ((balance * self.eth_price) / self.decimals)        
        
        # ERC-20s
        for erc_20 in self.erc20_token_address_map.values():
            balance = await self.ask_erc20_balance(addr, erc_20["contract"], erc_20["symbol"])
            total_usd += ((balance * erc_20["price"]) / (10 ** erc_20["decimal_place"]))

        self.logger.info(f"Total balance USD {total_usd}")

        return total_usd
    
    async def calculate_transaction_value(self, balance) -> int:
        return (balance * self.eth_price) / self.decimals
    
    async def calculate_erc20_value(self, contract_address, value) -> int:
        if contract_address in self.erc20_token_address_map:
            return ((value * self.erc20_token_address_map[contract_address]["price"]) / (10 ** self.erc20_token_address_map[contract_address]["decimal_place"]))
        else:
            return 0

    # Native -------------------------------------------------------------------------------------
    async def ask_balance(self, addr: str) -> int:
        balance = await self.w3.eth.get_balance(self.w3.to_checksum_address(addr))
        # cache
        self.balances[addr] = balance
        self.logger.debug("Balance: %s: %d (%.4f)", addr, balance, balance)
        return balance

    def get_balance(self, addr):
        return self.balances[addr]

    # ERC20 -------------------------------------------------------------------------------------
    async def ask_erc20_balance(self, addr: str, erc20_contract: any, erc20_symbol: str) -> int:
        # erc20_contract = self.w3.eth.contract(address=self.w3.to_checksum_address(erc20_addr), abi=ERC20_ABI)
        balance = await erc20_contract.functions.balanceOf(self.w3.to_checksum_address(addr)).call()
        # cache
        self.erc20_balances[addr] = balance
        self.logger.debug("ERC20 Balance: %s: %s=%d (%.4f)", addr, erc20_symbol, balance, balance)
        return balance

    def get_erc20_balance(self, addr):
        return self.erc20_balances[addr]

    async def on_block(self, transactions: List[Transaction]) -> None:
        
        if len(transactions) <= 0:
            return
        
        self.logger.info("Block: %s", transactions[0].block.number)

        for tx in transactions:
            # Check if account is a whale or not based on the tx.value 
            if tx.input == '0x' and await self.calculate_transaction_value(tx.value) > 100000:
                # self.logger.info(f"Update DB {tx.from_address}")
                if tx.from_address not in self._whale_wallet_map:
                    await self.databases.label.add(tx.from_address, ["whale"], "native")
                    self._whale_wallet_map[tx.from_address] = {
                        "balance": 0,
                        "to": []
                    }

                if tx.to_address not in self._whale_wallet_map:
                    await self.databases.label.add(tx.to_address, ["whale"], "native")
                    self._whale_wallet_map[tx.to_address] = {
                        "balance": 0,
                        "to": []
                    }

            # Check if account is a whale or not based on the tx events value
            for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
                if await self.calculate_erc20_value(tx_event.address, tx_event.fields["value"]) > 100000:
                    self.logger.info(f"Update DB ERC-20 {tx.from_address}")

                    if tx_event.fields["from"] not in self._whale_wallet_map:
                        await self.databases.label.add(tx_event.fields["from"], ["whale"], "native")
                        self._whale_wallet_map[tx_event.fields["from"]] = {
                            "balance": 0,
                            "to": [],
                            "poisoned_address": []
                        }

                    if tx_event.fields["to"] not in self._whale_wallet_map:
                        await self.databases.label.add(tx_event.fields["to"], ["whale"], "native")
                        self._whale_wallet_map[tx_event.fields["to"]] = {
                            "balance": 0,
                            "to": [],
                            "poisoned_address": []
                        }

            # Store addresses the whale sends tokens to (ignore contract interaction)
            if tx.from_address in self._whale_wallet_map and tx.input == "0x":
                # self.logger.info(f"Adding {tx.to_address} from {tx.from_address}")
                self._whale_wallet_map[tx.from_address]["to"].append(tx.to_address)

            # Check any big ERC-20 token transfer
            for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
                if tx_event.fields["from"] in self._whale_wallet_map:
                    event_to = tx_event.fields["to"]
                    # self.logger.info(f"Comparing {_to_addr} with {tx_event.fields['to']}")
                    self._whale_wallet_map[tx_event.fields["from"]]["to"].append(event_to)
            
                
            # Check transaction to whale and see verify the from_address
            if tx.input == "0x" and tx.to_address in self._whale_wallet_map:
                for _to_addr in self._whale_wallet_map[tx.to_address]["to"]:
                    # self.logger.info(f"Comparing {_to_addr} with {tx.from_address}")
                    if (_to_addr.startswith(tx.from_address[:4]) or _to_addr.startswith(tx.from_address[:5]) or _to_addr.startswith(tx.from_address[:3])):
                        if (_to_addr.endswith(tx.from_address[-4:]) or _to_addr.endswith(tx.from_address[-5:]) or _to_addr.endswith(tx.from_address[-3:])):
                            self.logger.info(f"Phising suspect found {tx.hash}. From Addr {tx.from_address} mimes {_to_addr}")
                            self._whale_wallet_map[tx.to_address]["poisoned_address"].append(tx.from_address)
                            # await self.send_notification(tx.from_address, self.native, tx.value, tx)
                
            # Check fake events
            for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
                if tx_event.fields["from"] in self._whale_wallet_map:
                    for _to_addr in self._whale_wallet_map[tx_event.fields["from"]]["to"]:
                        event_to = tx_event.fields["to"]
                        # self.logger.info(f"Comparing {_to_addr} with {tx_event.fields['to']}")
                        if (_to_addr != event_to):
                            if (_to_addr.startswith(event_to[:4]) or _to_addr.startswith(event_to[:5]) or _to_addr.startswith(event_to[:3])):
                                if (_to_addr.endswith(event_to[-4:]) or _to_addr.endswith(event_to[-5:]) or _to_addr.endswith(event_to[-3:])):
                                    self.logger.info(f"Phising suspect found events {tx.hash}. From Addr {event_to} mimes {_to_addr}")
                                    self._whale_wallet_map[tx_event.fields["from"]]["poisoned_address"].append(tx_event.fields['to'])
                                    # await self.send_notification(event_to, self.native, tx_event.fields['value'], tx)

            # Detect if phising attack succeed
            if tx.hash == "0x3374abc5a9c766ba709651399b6e6162de97ca986abc23f423a9d893c8f5f570":
                self.logger.info(f"Should be OK {tx.from_address} {tx.to_address} ")
                if tx.from_address in self._whale_wallet_map and tx.to_address in self._whale_wallet_map[tx.from_address]["poisoned_address"] and tx.input == "0x":
                    self.logger.info(f"Poisoned Attack succeed .... {tx.to_address} from {tx.from_address}")
                else:
                    # Check fake events
                    for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
                        # self.logger.info(f"Should be OK {self._whale_wallet_map[tx_event.fields['from']]}")
                        if tx_event.fields["from"] in self._whale_wallet_map and tx_event.fields["to"] in self._whale_wallet_map[tx_event.fields["from"]]["poisoned_address"]:
                            self.logger.info(f"Poisoned Attack succeed .... {event_to} from {tx.from_address}")


    async def send_notification(self, addr: str, token: str, balance: int, tx: Transaction) -> None:
        if tx is not None:
            tx_ts = tx.block.timestamp
            tx_hash = tx.hash
            tx_from = tx.from_address
            tx_to = tx.to_address
            tx_value = tx.value
        else:
            tx_ts = int(time.time() * 1000)
            tx_hash = ""
            tx_from = ""
            tx_to = ""
            tx_value = balance

        self.logger.info(f"--> Event: {tx_ts}: {addr}, {balance}, {tx}")

        await self.outputs.outbound_file_channel.send(
            Event(
                did=f"{self.name}-{token}",
                eid=uuid.uuid4().hex,
                type="balance_threshold",
                severity=self.severity,
                sid="ext:sentinel",
                ts=tx_ts,
                blockchain=Blockchain(
                    network=self.parameters["network"],
                    chain_id=str(BLOCKCHAIN.get(self.parameters["network"]).chain_id),
                ),
                metadata={
                    "tx_hash": tx_hash,
                    "tx_from": tx_from,
                    "tx_to": tx_to,
                    "token": token,
                    "value": tx_value,
                    "monitored_contract": addr,
                    "balance": balance,
                    "desc": f"Address poisoning has been detected.",
                },
            )
        )
