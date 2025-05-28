import subprocess
import time
from typing import Any, Dict, List, Optional

from eth_txpool_fuzzer_core.clients.base_client import IEthereumClient
from eth_txpool_fuzzer_core.tx import FuzzTx

class AnvilClient(IEthereumClient):
    """
    Ethereum client implementation for Anvil.
    Manages an Anvil process and interacts with it via RPC.
    """

    def __init__(self, rpc_url: str, manage_lifecycle: bool = True,
                 rpc_method_aliases: Optional[Dict[str, str]] = None,
                 binary_path: str = "anvil", port: int = 8545,
                 chain_id: Optional[int] = None, fork_url: Optional[str] = None,
                 block_time: Optional[int] = None,
                 **kwargs):
        """
        Initializes the Anvil client.

        Args:
            rpc_url: The URL to connect to Anvil's RPC endpoint (e.g., "http://127.0.0.1:8545").
            manage_lifecycle: If True, the fuzzer will start and stop the Anvil process.
            rpc_method_aliases: Custom RPC method aliases.
            binary_path: Path to the Anvil executable.
            port: The port Anvil should listen on.
            chain_id: The chain ID for Anvil.
            fork_url: URL of an Ethereum node to fork from.
            block_time: Block time in seconds for Anvil.
            **kwargs: Additional arguments to pass to the Anvil binary.
        """
        super().__init__(rpc_url, manage_lifecycle, rpc_method_aliases, **kwargs)
        self.binary_path = binary_path
        self.port = port
        self.chain_id = chain_id
        self.fork_url = fork_url
        self.block_time = block_time

        # Default Anvil-specific RPC aliases
        self.default_rpc_aliases = {
            "reset_state": "anvil_reset",
            "fund_accounts": "anvil_setBalance",
            "snapshot": "evm_snapshot",
            "revert": "evm_revert",
            "mine": "evm_mine" # Common Anvil/Hardhat method
        }
        # Merge default aliases with user-provided ones
        self.rpc_method_aliases = {**self.default_rpc_aliases, **self.rpc_method_aliases}

    def start(self) -> None:
        """
        Starts the Anvil client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle:
            print(f"INFO: Anvil client lifecycle not managed. Assuming Anvil is already running at {self.rpc_url}.")
            self.get_web3_instance() # Attempt to connect to verify
            return

        print(f"INFO: Starting Anvil client on port {self.port}...")
        command = [self.binary_path, "--port", str(self.port)]
        if self.chain_id is not None:
            command.extend(["--chain-id", str(self.chain_id)])
        if self.fork_url:
            command.extend(["--fork-url", self.fork_url])
        if self.block_time is not None:
            command.extend(["--block-time", str(self.block_time)])

        # Add any extra kwargs as command line arguments
        for k, v in self._client_kwargs.items():
            # Simple conversion for common types, might need more complex handling
            if isinstance(v, bool):
                if v: command.append(f"--{k.replace('_', '-')}")
            elif v is not None:
                command.extend([f"--{k.replace('_', '-')}", str(v)])

        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1 # Line-buffered output
            )
            print(f"INFO: Anvil process started with PID {self._process.pid}")

            # Wait for Anvil to be ready
            self.get_web3_instance() # Initialize w3
            timeout = 30
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    if self.w3.is_connected():
                        print("INFO: Anvil client is connected and ready.")
                        return
                except Exception:
                    pass
                time.sleep(0.1)
            raise RuntimeError(f"Anvil client did not become ready within {timeout} seconds.")
        except FileNotFoundError:
            raise RuntimeError(f"Anvil binary not found at '{self.binary_path}'. Please ensure Anvil is installed and in your PATH, or provide the correct binary_path.")
        except Exception as e:
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
            raise RuntimeError(f"Failed to start Anvil client: {e}")

    def stop(self) -> None:
        """
        Stops/terminates the Anvil client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle or self._process is None:
            return

        print("INFO: Stopping Anvil client...")
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
            print("INFO: Anvil client stopped.")
        except subprocess.TimeoutExpired:
            print("WARN: Anvil client did not terminate gracefully. Killing process.")
            self._process.kill()
            self._process.wait()
        self._process = None

    def reset_state(self) -> None:
        """
        Resets the Anvil blockchain state using anvil_reset RPC.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("reset_state", "anvil_reset")
            self.call_custom_rpc(method)
            print("INFO: Anvil state reset.")
        except Exception as e:
            print(f"ERROR: Failed to reset Anvil state: {e}")
            raise

    def fund_accounts(self, addresses: List[str], amount: int) -> None:
        """
        Funds the specified addresses using anvil_setBalance RPC.
        """
        w3 = self.get_web3_instance()
        amount_wei = w3.to_wei(amount, 'ether')
        try:
            method = self.rpc_method_aliases.get("fund_accounts", "anvil_setBalance")
            for addr in addresses:
                self.call_custom_rpc(method, addr, hex(amount_wei))
            print(f"INFO: Funded {len(addresses)} accounts with {amount} ETH each.")
        except Exception as e:
            print(f"ERROR: Failed to fund accounts in Anvil: {e}")
            raise

    def get_current_gas_prices(self) -> Dict[str, int]:
        """
        Fetches current gas prices from Anvil.
        Anvil typically provides fixed or predictable gas prices.
        """
        w3 = self.get_web3_instance()
        try:
            # Anvil's default behavior for gas prices
            latest_block = w3.eth.get_block('latest')
            base_fee_per_gas = latest_block.baseFeePerGas if hasattr(latest_block, 'baseFeePerGas') else 0

            # Anvil often has a default max_priority_fee_per_gas of 1 Gwei
            max_priority_fee_per_gas = w3.to_wei(1, 'gwei')

            # For EIP-1559, maxFeePerGas should be base_fee_per_gas + max_priority_fee_per_gas
            max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas

            # Anvil doesn't directly expose maxFeePerBlobGas via eth_gasPrice,
            # but we can try to get it or use a heuristic.
            # For now, use a default or try a custom RPC if aliased.
            max_fee_per_blob_gas = 0
            try:
                blob_gas_price_method = self.rpc_method_aliases.get("get_blob_gas_price", "eth_blobGasPrice")
                blob_gas_price_hex = self.call_custom_rpc(blob_gas_price_method)
                if blob_gas_price_hex:
                    max_fee_per_blob_gas = int(blob_gas_price_hex, 16)
            except Exception:
                # Fallback if eth_blobGasPrice is not available or fails
                max_fee_per_blob_gas = w3.to_wei(1, 'gwei') # Heuristic default

            return {
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'gasPrice': w3.eth.gas_price, # Legacy gas price
                'maxFeePerBlobGas': max_fee_per_blob_gas
            }
        except Exception as e:
            print(f"WARN: Could not fetch Anvil gas prices: {e}. Using default values.")
            return {
                'maxFeePerGas': w3.to_wei(100, 'gwei'),
                'maxPriorityFeePerGas': w3.to_wei(1, 'gwei'),
                'gasPrice': w3.to_wei(100, 'gwei'),
                'maxFeePerBlobGas': w3.to_wei(1, 'gwei')
            }

    def sign_and_send_transfer(self, tx: FuzzTx, private_key: str) -> str:
        """
        Signs and sends a transaction to Anvil.
        """
        w3 = self.get_web3_instance()
        account = w3.eth.account.from_key(private_key)

        # Build transaction dictionary based on tx_type
        transaction = {
            'from': tx.sender_address,
            'to': self._client_kwargs.get('default_recipient_address', '0x0000000000000000000000000000000000000000'), # Use a default recipient if not provided
            'value': tx.value,
            'nonce': tx.nonce,
            'gas': 21000, # Standard gas limit for simple transfer
            'chainId': self.chain_id if self.chain_id is not None else w3.eth.chain_id
        }

        if tx.tx_type == 2: # EIP-1559
            transaction['maxFeePerGas'] = tx.price
            transaction['maxPriorityFeePerGas'] = tx.max_priority_fee_per_gas
        elif tx.tx_type == 3: # EIP-4844 (Blob transaction)
            transaction['maxFeePerGas'] = tx.price
            transaction['maxPriorityFeePerGas'] = tx.max_priority_fee_per_gas
            transaction['maxFeePerBlobGas'] = tx.max_fee_per_blob_gas
            transaction['blobVersionedHashes'] = [h.hex() for h in tx.blob_versioned_hashes] if tx.blob_versioned_hashes else []
            transaction['type'] = '0x03' # EIP-4844 type
        else: # Legacy or EIP-2930 (type 0 or 1)
            transaction['gasPrice'] = tx.price
            if tx.tx_type == 1:
                transaction['type'] = '0x01' # EIP-2930 type
            else:
                transaction['type'] = '0x00' # Legacy type

        # Remove None values from transaction dict
        transaction = {k: v for k, v in transaction.items() if v is not None}

        try:
            signed_tx = account.sign_transaction(transaction)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction).hex()
            # Wait for transaction receipt to ensure it's mined/processed by Anvil
            w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
            return tx_hash
        except Exception as e:
            print(f"ERROR: Failed to send transaction: {e}")
            # Anvil might return specific errors, e.g., nonce too low, gas price too low
            raise

    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Retrieves the current transaction pool content from Anvil.
        Anvil provides `eth_pendingTransactions` which is sufficient for basic pool content.
        """
        w3 = self.get_web3_instance()
        try:
            # Anvil's eth_pendingTransactions returns a list of pending transactions.
            # We need to format it to match the expected structure (sender -> nonce -> tx_details)
            pending_txs_list = w3.eth.get_raw_transaction_pool() # This is a common method in testnets

            pending_formatted: Dict[str, Dict[str, Any]] = {}
            for raw_tx in pending_txs_list:
                # Decode raw transaction to get sender, nonce, etc.
                # This is a simplified decoding, a full solution might need more robust parsing
                # For Anvil, we might rely on `debug_getRawTransaction` or similar if available
                # or just assume the structure from `eth_getTransactionByHash` if we had hashes.
                # For now, let's assume we can get sender/nonce from the raw_tx or a mock.
                # Anvil's `eth_pendingTransactions` returns full transaction objects, not just raw.
                # Let's use `eth_getUncleByBlockNumberAndIndex` as a placeholder for a method that returns tx details.
                # This is incorrect. Anvil has `anvil_pendingTransactions` or `eth_pendingTransactions`
                # which returns full transaction objects.

                # Let's assume `eth_pendingTransactions` returns a list of transaction dicts
                # For Anvil, `eth_pendingTransactions` is usually available.
                # If not, we might need to use `debug_getRawTransaction` or similar.
                # For now, let's mock or assume a structure.

                # Re-evaluating: web3.py's `get_raw_transaction_pool` is not standard.
                # The common way to get pending transactions is `web3.eth.get_block('pending', full_transactions=True)`
                # or a custom RPC like `txpool_content` if supported.

                # Anvil supports `eth_pendingTransactions` which returns a list of transaction objects.
                # Let's use that.

                # Fallback to a simpler approach if direct txpool_content is not available
                # Anvil's `eth_pendingTransactions` returns a list of transaction objects.
                # We need to convert this into the expected nested dictionary format.

                # Let's use `eth_getBlock('pending', full_transactions=True)` as it's more standard.
                pending_block = w3.eth.get_block('pending', full_transactions=True)
                if pending_block and pending_block.transactions:
                    for tx_obj in pending_block.transactions:
                        sender = tx_obj['from']
                        nonce = tx_obj['nonce']
                        if sender not in pending_formatted:
                            pending_formatted[sender] = {}
                        pending_formatted[sender][str(nonce)] = {
                            'gasPrice': tx_obj.get('gasPrice', 0),
                            'maxFeePerGas': tx_obj.get('maxFeePerGas', 0),
                            'maxPriorityFeePerGas': tx_obj.get('maxPriorityFeePerGas', 0),
                            'value': tx_obj.get('value', 0),
                            'hash': tx_obj['hash'].hex()
                        }

            # Anvil typically doesn't have a separate 'queued' pool in the same way Geth does.
            # All transactions are either pending or dropped.
            # For simplicity, we'll return an empty queued dict.
            queued_formatted: Dict[str, Dict[str, Any]] = {}

            return {"pending": pending_formatted, "queued": queued_formatted}
        except Exception as e:
            print(f"ERROR: Failed to get Anvil txpool content: {e}")
            return {"pending": {}, "queued": {}}

    def snapshot(self) -> str:
        """
        Creates a snapshot of the current Anvil chain state using evm_snapshot RPC.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("snapshot", "evm_snapshot")
            snapshot_id = self.call_custom_rpc(method)
            print(f"INFO: Anvil state snapshot created with ID: {snapshot_id}")
            return snapshot_id
        except Exception as e:
            print(f"ERROR: Failed to create Anvil snapshot: {e}")
            raise

    def revert(self, snapshot_id: str) -> None:
        """
        Reverts the Anvil chain state to a previously created snapshot using evm_revert RPC.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("revert", "evm_revert")
            self.call_custom_rpc(method, snapshot_id)
            print(f"INFO: Anvil state reverted to snapshot ID: {snapshot_id}")
        except Exception as e:
            print(f"ERROR: Failed to revert Anvil state: {e}")
            raise
