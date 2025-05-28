"""
Handles communication with an Ethereum client, including sending transactions
and making custom RPC calls relevant to fuzzing.
"""
import requests
import json
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxParams

from . import config as core_config
from .tx import FuzzTx
from .accounts import AccountManager


class EthereumClient:
    """
    Provides an interface to interact with an Ethereum client (e.g., Geth node).
    Wraps web3.py for standard operations and allows custom JSON-RPC calls.
    """
    def __init__(self,
                 rpc_url: str = core_config.DEFAULT_TARGET_URL,
                 chain_id: int = core_config.DEFAULT_CHAIN_ID
                ):
        """
        Initializes the EthereumClient.

        :param rpc_url: The URL of the Ethereum client's JSON-RPC endpoint.
        :param chain_id: The chain ID for transactions.
        """
        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = chain_id

        if not self.w3.is_connected():
            print(f"CRITICAL: Failed to connect to Ethereum client at {rpc_url}. Ensure the client is running and accessible.")
            raise ConnectionError(f"Failed to connect to Ethereum client at {rpc_url}")
        else:
            print(f"INFO: EthereumClient connected to {rpc_url}")

    def get_current_gas_prices(self) -> Dict[str, int]:
        """
        Fetches the current recommended gas prices from the connected Ethereum client.
        Returns a dictionary with 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas',
        and 'maxFeePerBlobGas' (if available).
        """
        gas_prices: Dict[str, int] = {}
        try:
            gas_prices['gasPrice'] = self.w3.eth.gas_price
        except Exception as e:
            print(f"WARN: Could not fetch legacy gas price: {e}")
            gas_prices['gasPrice'] = 0

        try:
            latest_block = self.w3.eth.get_block('latest')
            base_fee_per_gas = latest_block.get('baseFeePerGas', 0)
            gas_prices['maxFeePerGas'] = base_fee_per_gas + self.w3.eth.max_priority_fee
            gas_prices['maxPriorityFeePerGas'] = self.w3.eth.max_priority_fee
        except Exception as e:
            print(f"WARN: Could not fetch EIP-1559 gas prices: {e}")
            gas_prices['maxFeePerGas'] = gas_prices['gasPrice']
            gas_prices['maxPriorityFeePerGas'] = 0

        try:
            if hasattr(self.w3.eth, 'get_block_blob_gas_price'):
                gas_prices['maxFeePerBlobGas'] = self.w3.eth.get_block_blob_gas_price()
            else:
                gas_prices['maxFeePerBlobGas'] = gas_prices['maxFeePerGas'] * 2 if gas_prices['maxFeePerGas'] > 0 else 1000000000
                print(f"INFO: get_block_blob_gas_price not available. Using heuristic for maxFeePerBlobGas: {gas_prices['maxFeePerBlobGas']}")
        except Exception as e:
            print(f"WARN: Could not fetch EIP-4844 blob gas price: {e}")
            gas_prices['maxFeePerBlobGas'] = 1000000000

        return gas_prices


    def _make_rpc_request(self, method: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Helper function to make JSON-RPC requests. Useful for custom Geth methods.
        Returns the JSON response as a dictionary.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }
        try:
            response = requests.post(self.rpc_url, json=payload, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            json_response = response.json()
            if 'error' in json_response:
                print(f"WARN: RPC Error for method {method}: {json_response['error']}")
            return json_response
        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout during RPC request for method {method} to {self.rpc_url}")
            return {"error": {"code": -32000 - 1, "message": "RPC request timeout"}}
        except requests.exceptions.RequestException as e:
            print(f"ERROR: RequestException for method {method}: {e}")
            return {"error": {"code": -32000 - 2, "message": f"RPC request failed: {e}"}}
        except json.JSONDecodeError as e:
            print(f"ERROR: JSONDecodeError for method {method} (response: {response.text[:200]}...): {e}")
            return {"error": {"code": -32000 - 3, "message": f"Failed to decode JSON response: {e}"}}


    def sign_and_send_transfer(self,
                               fuzz_tx_intent: FuzzTx,
                               recipient_address: str,
                               account_manager: AccountManager
                              ) -> Optional[str]:
        """
        Constructs, signs, and sends a transaction based on a FuzzTx object.
        Supports Legacy, EIP-1559, and EIP-4844 transaction types.

        :param fuzz_tx_intent: The FuzzTx object with parameters for the transaction.
        :param recipient_address: The checksummed address of the recipient.
        :param account_manager: The AccountManager instance to fetch the private key.
        :return: The transaction hash (hex string) if successful, None otherwise.
        """
        sender_priv_key = account_manager.get_private_key(fuzz_tx_intent.sender_address)
        if not sender_priv_key:
            print(f"ERROR: No private key found for sender {fuzz_tx_intent.sender_address} in AccountManager.")
            return None

        transaction_parameters: TxParams = {
            'to': recipient_address,
            'from': fuzz_tx_intent.sender_address,
            'value': fuzz_tx_intent.value,
            'gas': core_config.DEFAULT_GAS_LIMIT,
            'nonce': fuzz_tx_intent.nonce,
            'chainId': self.chain_id
        }

        if fuzz_tx_intent.tx_type == 3:
            if fuzz_tx_intent.max_fee_per_blob_gas is None or fuzz_tx_intent.blob_versioned_hashes is None:
                print(f"ERROR: EIP-4844 transaction missing required blob parameters for {fuzz_tx_intent.sender_address}.")
                return None

            transaction_parameters['type'] = 3
            transaction_parameters['maxFeePerGas'] = fuzz_tx_intent.price
            transaction_parameters['maxPriorityFeePerGas'] = fuzz_tx_intent.max_priority_fee_per_gas or 0
            transaction_parameters['maxFeePerBlobGas'] = fuzz_tx_intent.max_fee_per_blob_gas
            transaction_parameters['blobVersionedHashes'] = fuzz_tx_intent.blob_versioned_hashes

        elif fuzz_tx_intent.tx_type == 2:
            transaction_parameters['type'] = 2
            transaction_parameters['maxFeePerGas'] = fuzz_tx_intent.price
            transaction_parameters['maxPriorityFeePerGas'] = fuzz_tx_intent.max_priority_fee_per_gas or 0

        else:
            transaction_parameters['gasPrice'] = fuzz_tx_intent.price
            if fuzz_tx_intent.tx_type == 1:
                transaction_parameters['type'] = 1
                transaction_parameters['accessList'] = []

        try:
            signed_transaction = self.w3.eth.account.sign_transaction(transaction_parameters, sender_priv_key)
            tx_hash_bytes = self.w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
            return tx_hash_bytes.hex()
        except ValueError as e:
            print(f"WARN: ValueError sending tx from {fuzz_tx_intent.sender_address} (Nonce: {fuzz_tx_intent.nonce}, Type: {fuzz_tx_intent.tx_type}): {e}")
            return None
        except Exception as e:
            print(f"ERROR: Unexpected error sending tx from {fuzz_tx_intent.sender_address} (Nonce: {fuzz_tx_intent.nonce}, Type: {fuzz_tx_intent.tx_type}): {e}")
            return None

    def get_transaction_receipt(self, tx_hash_hex: str) -> Optional[Dict[str, Any]]:
        """Retrieves the transaction receipt for a given transaction hash."""
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hash_hex)
            return dict(receipt)
        except TransactionNotFound:
            return None
        except Exception as e:
            print(f"ERROR: Error getting receipt for tx hash {tx_hash_hex}: {e}")
            return None

    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Fetches the content of the transaction pool (pending and queued transactions).
        Tries standard web3.py Geth module first, then falls back to direct RPC.
        """
        try:
            if hasattr(self.w3, 'geth') and hasattr(self.w3.geth.txpool) and hasattr(self.w3.geth.txpool, 'content'):
                return self.w3.geth.txpool.content()
        except Exception as e:
            print(f"INFO: w3.geth.txpool.content() failed or not available: {e}. Falling back to direct RPC call.")

        response = self._make_rpc_request("txpool_content")
        return response.get('result', {"pending": {}, "queued": {}})

    def clear_txpool_custom(self) -> bool:
        """Custom RPC: Clears the transaction pool via 'eth_clearTxpool'."""
        response = self._make_rpc_request("eth_clearTxpool")
        if 'error' in response and response['error'] is not None:
            print(f"ERROR: clear_txpool_custom failed: {response['error']}")
            return False
        return 'result' in response

    def check_tx_in_pool_custom(self, tx_hash_hex: str) -> Optional[bool]:
        """Custom RPC: Checks if a transaction is in the pool via 'eth_checkTxinpool'."""
        response = self._make_rpc_request("eth_checkTxinpool", [tx_hash_hex])
        if 'error' in response and response['error'] is not None:
            print(f"ERROR: check_tx_in_pool_custom for {tx_hash_hex} failed: {response['error']}")
            return None
        if 'result' in response:
            return response['result']
        return None

    def generic_custom_rpc_call(self, method_name: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Allows calling arbitrary custom JSON-RPC methods.
        Returns the full JSON response dictionary.
        """
        return self._make_rpc_request(method_name, params)
