# eth_txpool_fuzzer_core/client_comms.py
"""
Handles communication with an Ethereum client, including sending transactions
and making custom RPC calls relevant to fuzzing.
"""
import requests
import json
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.exceptions import TransactionNotFound # For specific error handling
from web3.types import TxParams # For transaction parameters and blob hashes

from . import config as core_config
from .tx import FuzzTx # Using the type alias for clarity
from .accounts import AccountManager

# TODO: Set up a proper logger for this module
# import logging
# logger = logging.getLogger(__name__)

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
            # TODO: Use logging and raise a custom connection error
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
            # Legacy gas price
            gas_prices['gasPrice'] = self.w3.eth.gas_price
        except Exception as e:
            print(f"WARN: Could not fetch legacy gas price: {e}")
            gas_prices['gasPrice'] = 0 # Fallback

        try:
            # EIP-1559 baseFeePerGas and maxPriorityFeePerGas
            latest_block = self.w3.eth.get_block('latest')
            base_fee_per_gas = latest_block.get('baseFeePerGas', 0)
            gas_prices['maxFeePerGas'] = base_fee_per_gas + self.w3.eth.max_priority_fee
            gas_prices['maxPriorityFeePerGas'] = self.w3.eth.max_priority_fee
        except Exception as e:
            print(f"WARN: Could not fetch EIP-1559 gas prices: {e}")
            gas_prices['maxFeePerGas'] = gas_prices['gasPrice'] # Fallback to legacy
            gas_prices['maxPriorityFeePerGas'] = 0 # Fallback

        try:
            # EIP-4844 maxFeePerBlobGas
            # This RPC method might not be available on all clients or web3.py versions
            if hasattr(self.w3.eth, 'get_block_blob_gas_price'):
                gas_prices['maxFeePerBlobGas'] = self.w3.eth.get_block_blob_gas_price()
            else:
                # Fallback heuristic: baseFeePerGas * 2 or a fixed value
                gas_prices['maxFeePerBlobGas'] = gas_prices['maxFeePerGas'] * 2 if gas_prices['maxFeePerGas'] > 0 else 1000000000 # 1 Gwei
                print(f"INFO: get_block_blob_gas_price not available. Using heuristic for maxFeePerBlobGas: {gas_prices['maxFeePerBlobGas']}")
        except Exception as e:
            print(f"WARN: Could not fetch EIP-4844 blob gas price: {e}")
            gas_prices['maxFeePerBlobGas'] = 1000000000 # Fallback to 1 Gwei

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
            "id": 1, # Standard ID, can be dynamic if needed
        }
        try:
            response = requests.post(self.rpc_url, json=payload, headers={"Content-Type": "application/json"})
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            json_response = response.json()
            if 'error' in json_response:
                # TODO: Use logging
                print(f"WARN: RPC Error for method {method}: {json_response['error']}")
            return json_response
        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout during RPC request for method {method} to {self.rpc_url}")
            return {"error": {"code": -32000 - 1, "message": "RPC request timeout"}} # Custom error code
        except requests.exceptions.RequestException as e:
            # TODO: Use logging
            print(f"ERROR: RequestException for method {method}: {e}")
            return {"error": {"code": -32000 - 2, "message": f"RPC request failed: {e}"}}
        except json.JSONDecodeError as e:
            # TODO: Use logging
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
            # TODO: Use logging
            print(f"ERROR: No private key found for sender {fuzz_tx_intent.sender_address} in AccountManager.")
            return None

        transaction_parameters: TxParams = {
            'to': recipient_address,
            'from': fuzz_tx_intent.sender_address,
            'value': fuzz_tx_intent.value,
            'gas': core_config.DEFAULT_GAS_LIMIT, # Default gas limit for simple transfers
            'nonce': fuzz_tx_intent.nonce,
            'chainId': self.chain_id
        }

        if fuzz_tx_intent.tx_type == 3: # EIP-4844 Blob Transaction
            if fuzz_tx_intent.max_fee_per_blob_gas is None or fuzz_tx_intent.blob_versioned_hashes is None:
                print(f"ERROR: EIP-4844 transaction missing required blob parameters for {fuzz_tx_intent.sender_address}.")
                return None

            transaction_parameters['type'] = 3
            transaction_parameters['maxFeePerGas'] = fuzz_tx_intent.price # price is maxFeePerGas for EIP-1559/4844
            transaction_parameters['maxPriorityFeePerGas'] = fuzz_tx_intent.max_priority_fee_per_gas or 0
            transaction_parameters['maxFeePerBlobGas'] = fuzz_tx_intent.max_fee_per_blob_gas
            transaction_parameters['blobVersionedHashes'] = fuzz_tx_intent.blob_versioned_hashes
            # Note: web3.py handles the `blobs` field internally if `blobVersionedHashes` is provided.
            # The actual blob data is not part of the transaction parameters sent to `sign_transaction`.
            # It's assumed to be available to the client via other means (e.g., P2P gossip)
            # or that the hashes are sufficient for txpool validation.
            # For fuzzing, we generate dummy hashes.

        elif fuzz_tx_intent.tx_type == 2: # EIP-1559 Transaction
            transaction_parameters['type'] = 2
            transaction_parameters['maxFeePerGas'] = fuzz_tx_intent.price
            transaction_parameters['maxPriorityFeePerGas'] = fuzz_tx_intent.max_priority_fee_per_gas or 0
            # 'gasPrice' is not used for EIP-1559

        else: # Legacy (type 0) or EIP-2930 (type 1)
            # For type 0, 'gasPrice' is used. For type 1, 'gasPrice' is also used.
            # The 'price' field in FuzzTx serves as 'gasPrice' for these types.
            transaction_parameters['gasPrice'] = fuzz_tx_intent.price
            if fuzz_tx_intent.tx_type == 1:
                transaction_parameters['type'] = 1
                # EIP-2930 also has 'accessList', which is not currently in FuzzTx.
                # For simplicity, we'll omit it for now or assume empty.
                transaction_parameters['accessList'] = [] # Default empty access list

        try:
            signed_transaction = self.w3.eth.account.sign_transaction(transaction_parameters, sender_priv_key)
            tx_hash_bytes = self.w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
            # TODO: Use logging
            # print(f"DEBUG: Tx sent: {fuzz_tx_intent.sender_address} N:{fuzz_tx_intent.nonce} P:{fuzz_tx_intent.price} V:{fuzz_tx_intent.value} -> {recipient_address}, Hash: {tx_hash_bytes.hex()}")
            return tx_hash_bytes.hex()
        except ValueError as e:
            # Geth often returns ValueError for issues like nonce too low, insufficient funds, known transaction.
            # TODO: Use logging. More specific error parsing could be done if essential for fuzz logic.
            print(f"WARN: ValueError sending tx from {fuzz_tx_intent.sender_address} (Nonce: {fuzz_tx_intent.nonce}, Type: {fuzz_tx_intent.tx_type}): {e}")
            # The original scripts sometimes tried to parse the hash from these errors.
            # For a library, it's safer to just report failure here.
            return None
        except Exception as e: # Catch any other unexpected errors during signing or sending
            # TODO: Use logging
            print(f"ERROR: Unexpected error sending tx from {fuzz_tx_intent.sender_address} (Nonce: {fuzz_tx_intent.nonce}, Type: {fuzz_tx_intent.tx_type}): {e}")
            return None

    def get_transaction_receipt(self, tx_hash_hex: str) -> Optional[Dict[str, Any]]:
        """Retrieves the transaction receipt for a given transaction hash."""
        try:
            # Convert hex string to bytes if web3.py version requires it, or use HexBytes
            # For simplicity, assuming tx_hash_hex is the correct format.
            receipt = self.w3.eth.get_transaction_receipt(tx_hash_hex)
            return dict(receipt) # Convert AttributeDict to dict for easier handling
        except TransactionNotFound:
            # TODO: Use logging - this is an expected case for txs not yet mined.
            # print(f"DEBUG: Transaction receipt not found for hash {tx_hash_hex}.")
            return None
        except Exception as e:
            # TODO: Use logging
            print(f"ERROR: Error getting receipt for tx hash {tx_hash_hex}: {e}")
            return None

    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Fetches the content of the transaction pool (pending and queued transactions).
        Tries standard web3.py Geth module first, then falls back to direct RPC.
        """
        try:
            # For web3.py v5.x with Geth personal/admin APIs enabled via middleware
            if hasattr(self.w3, 'geth') and hasattr(self.w3.geth, 'txpool') and hasattr(self.w3.geth.txpool, 'content'):
                return self.w3.geth.txpool.content()
        except Exception as e:
            # TODO: Use logging
            print(f"INFO: w3.geth.txpool.content() failed or not available: {e}. Falling back to direct RPC call.")

        # Fallback for web3.py v6.x or if Geth module isn't attached/working as expected
        # In web3.py v6.x, it might be: self.w3.provider.make_request("txpool_content", [])
        # Using our _make_rpc_request for consistency:
        response = self._make_rpc_request("txpool_content")
        return response.get('result', {"pending": {}, "queued": {}}) # Default to empty if 'result' is missing or error

    # --- Custom RPC Methods (examples based on original helper.py) ---

    def clear_txpool_custom(self) -> bool:
        """Custom RPC: Clears the transaction pool via 'eth_clearTxpool'."""
        response = self._make_rpc_request("eth_clearTxpool")
        # Assuming success if 'result' is present and not an error object.
        # The actual success condition might depend on the specific Geth modification.
        if 'error' in response and response['error'] is not None:
            print(f"ERROR: clear_txpool_custom failed: {response['error']}")
            return False
        return 'result' in response # Or check response['result'] for a specific success value

    def check_tx_in_pool_custom(self, tx_hash_hex: str) -> Optional[bool]:
        """Custom RPC: Checks if a transaction is in the pool via 'eth_checkTxinpool'."""
        response = self._make_rpc_request("eth_checkTxinpool", [tx_hash_hex])
        if 'error' in response and response['error'] is not None:
            print(f"ERROR: check_tx_in_pool_custom for {tx_hash_hex} failed: {response['error']}")
            return None
        if 'result' in response:
            return response['result'] # Expecting a boolean result
        return None # Unexpected response format

    def generic_custom_rpc_call(self, method_name: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Allows calling arbitrary custom JSON-RPC methods.
        Returns the full JSON response dictionary.
        """
        # TODO: Use logging
        # print(f"DEBUG: Making generic custom RPC call: {method_name}, Params: {params}")
        return self._make_rpc_request(method_name, params)
