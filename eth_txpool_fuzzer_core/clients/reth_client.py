import subprocess
import time
from typing import Any, Dict, List, Optional

from eth_txpool_fuzzer_core.clients.base_client import IEthereumClient
from eth_txpool_fuzzer_core.tx import FuzzTx

class RethClient(IEthereumClient):
    """
    Ethereum client implementation for Reth.
    Manages a Reth process and interacts with it via RPC.
    """

    def __init__(self, rpc_url: str, manage_lifecycle: bool = True,
                 rpc_method_aliases: Optional[Dict[str, str]] = None,
                 binary_path: str = "reth", port: int = 8545,
                 chain_id: Optional[int] = None, data_dir: Optional[str] = None,
                 **kwargs):
        """
        Initializes the Reth client.

        Args:
            rpc_url: The URL to connect to Reth's RPC endpoint (e.g., "http://127.0.0.1:8545").
            manage_lifecycle: If True, the fuzzer will start and stop the Reth process.
            rpc_method_aliases: Custom RPC method aliases.
            binary_path: Path to the Reth executable.
            port: The port Reth should listen on.
            chain_id: The chain ID for Reth.
            data_dir: Path to the Reth data directory.
            **kwargs: Additional arguments to pass to the Reth binary.
        """
        super().__init__(rpc_url, manage_lifecycle, rpc_method_aliases, **kwargs)
        self.binary_path = binary_path
        self.port = port
        self.chain_id = chain_id
        self.data_dir = data_dir

        # Default Reth-specific RPC aliases
        self.default_rpc_aliases = {
            "reset_state": "debug_resetChain", # Reth might support this or require restart
            "fund_accounts": None, # Reth does not have a direct setBalance equivalent
            "snapshot": None, # Reth does not have direct evm_snapshot/revert
            "revert": None,
            "get_txpool_content": "txpool_content"
        }
        # Merge default aliases with user-provided ones
        self.rpc_method_aliases = {**self.default_rpc_aliases, **self.rpc_method_aliases}

    def start(self) -> None:
        """
        Starts the Reth client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle:
            print(f"INFO: Reth client lifecycle not managed. Assuming Reth is already running at {self.rpc_url}.")
            self.get_web3_instance() # Attempt to connect to verify
            return

        print(f"INFO: Starting Reth client on port {self.port}...")
        command = [self.binary_path, "node", "--http", "--http.port", str(self.port)]
        if self.chain_id is not None:
            command.extend(["--chain", str(self.chain_id)]) # Reth uses --chain for chain ID
        if self.data_dir:
            command.extend(["--datadir", self.data_dir])

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
            print(f"INFO: Reth process started with PID {self._process.pid}")

            # Wait for Reth to be ready
            self.get_web3_instance() # Initialize w3
            timeout = 60 # Reth might take longer to start
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    if self.w3.is_connected():
                        print("INFO: Reth client is connected and ready.")
                        return
                except Exception:
                    pass
                time.sleep(0.5) # Longer sleep for Reth
            raise RuntimeError(f"Reth client did not become ready within {timeout} seconds.")
        except FileNotFoundError:
            raise RuntimeError(f"Reth binary not found at '{self.binary_path}'. Please ensure Reth is installed and in your PATH, or provide the correct binary_path.")
        except Exception as e:
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
            raise RuntimeError(f"Failed to start Reth client: {e}")

    def stop(self) -> None:
        """
        Stops/terminates the Reth client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle or self._process is None:
            return

        print("INFO: Stopping Reth client...")
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
            print("INFO: Reth client stopped.")
        except subprocess.TimeoutExpired:
            print("WARN: Reth client did not terminate gracefully. Killing process.")
            self._process.kill()
            self._process.wait()
        self._process = None

    def reset_state(self) -> None:
        """
        Resets the Reth blockchain state.
        Reth might support `debug_resetChain`. If not, a full restart might be needed.
        """
        w3 = self.get_web3_instance()
        method = self.rpc_method_aliases.get("reset_state")
        if method:
            try:
                self.call_custom_rpc(method)
                print("INFO: Reth state reset via RPC.")
            except Exception as e:
                print(f"ERROR: Failed to reset Reth state via RPC ({method}): {e}. Consider restarting Reth.")
                raise
        else:
            # If no specific RPC for reset, a full restart might be the only option for managed clients.
            # For unmanaged clients, this operation is not possible via the fuzzer.
            if self.manage_lifecycle:
                print("WARN: No direct RPC method for state reset in Reth. Attempting full client restart.")
                self.stop()
                # Clean data directory if specified and managed
                if self.data_dir:
                    print(f"INFO: Deleting Reth data directory: {self.data_dir}")
                    import shutil
                    try:
                        shutil.rmtree(self.data_dir)
                    except OSError as e:
                        print(f"ERROR: Failed to delete Reth data directory {self.data_dir}: {e}")
                        raise
                self.start() # Restart to get a clean state
            else:
                raise NotImplementedError("Reth client does not support state reset without lifecycle management or a specific RPC alias.")

    def fund_accounts(self, addresses: List[str], amount: int) -> None:
        """
        Funds the specified addresses. Reth does not have a direct `setBalance` RPC.
        This would typically involve sending transactions from a pre-funded account.
        For simplicity, this is marked as not implemented for now.
        """
        raise NotImplementedError("RethClient does not support direct account funding via RPC. "
                                  "Accounts must be pre-funded or funded via transactions from a known account.")

    def get_current_gas_prices(self) -> Dict[str, int]:
        """
        Fetches current gas prices from Reth.
        """
        w3 = self.get_web3_instance()
        try:
            # Standard EIP-1559 gas price fetching
            latest_block = w3.eth.get_block('latest')
            base_fee_per_gas = latest_block.baseFeePerGas if hasattr(latest_block, 'baseFeePerGas') else 0

            # eth_maxPriorityFeePerGas is a standard RPC
            max_priority_fee_per_gas = w3.eth.max_priority_fee

            # For EIP-1559, maxFeePerGas should be base_fee_per_gas + max_priority_fee_per_gas
            max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas

            # Reth supports eth_blobGasPrice
            max_fee_per_blob_gas = 0
            try:
                blob_gas_price_method = self.rpc_method_aliases.get("get_blob_gas_price", "eth_blobGasPrice")
                blob_gas_price_hex = self.call_custom_rpc(blob_gas_price_method)
                if blob_gas_price_hex:
                    max_fee_per_blob_gas = int(blob_gas_price_hex, 16)
            except Exception:
                print("WARN: eth_blobGasPrice not available or failed for Reth. Using 0.")
                max_fee_per_blob_gas = 0 # Default to 0 if not available

            return {
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'gasPrice': w3.eth.gas_price, # Legacy gas price
                'maxFeePerBlobGas': max_fee_per_blob_gas
            }
        except Exception as e:
            print(f"WARN: Could not fetch Reth gas prices: {e}. Using default values.")
            return {
                'maxFeePerGas': w3.to_wei(100, 'gwei'),
                'maxPriorityFeePerGas': w3.to_wei(1, 'gwei'),
                'gasPrice': w3.to_wei(100, 'gwei'),
                'maxFeePerBlobGas': w3.to_wei(1, 'gwei')
            }

    def sign_and_send_transfer(self, tx: FuzzTx, private_key: str) -> str:
        """
        Signs and sends a transaction to Reth.
        """
        w3 = self.get_web3_instance()
        account = w3.eth.account.from_key(private_key)

        # Build transaction dictionary based on tx_type
        transaction = {
            'from': tx.sender_address,
            'to': self._client_kwargs.get('default_recipient_address', '0x0000000000000000000000000000000000000000'),
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
            # For Reth, waiting for receipt might be necessary for state updates
            w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
            return tx_hash
        except Exception as e:
            print(f"ERROR: Failed to send transaction to Reth: {e}")
            raise

    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Retrieves the current transaction pool content from Reth using `txpool_content` RPC.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("get_txpool_content", "txpool_content")
            pool_content = self.call_custom_rpc(method)

            # Reth's txpool_content returns 'pending' and 'queued' directly
            # The structure is usually {sender_address: {nonce: tx_details}}
            # We need to ensure the keys are strings for nonces.

            pending_formatted: Dict[str, Dict[str, Any]] = {}
            if 'pending' in pool_content:
                for sender, nonces_txs in pool_content['pending'].items():
                    pending_formatted[sender] = {str(nonce): tx_details for nonce, tx_details in nonces_txs.items()}

            queued_formatted: Dict[str, Dict[str, Any]] = {}
            if 'queued' in pool_content:
                for sender, nonces_txs in pool_content['queued'].items():
                    queued_formatted[sender] = {str(nonce): tx_details for nonce, tx_details in nonces_txs.items()}

            return {"pending": pending_formatted, "queued": queued_formatted}
        except Exception as e:
            print(f"ERROR: Failed to get Reth txpool content: {e}")
            return {"pending": {}, "queued": {}}

    def snapshot(self) -> str:
        """
        Reth does not have a direct `evm_snapshot` equivalent.
        This operation is not supported via RPC for Reth.
        """
        raise NotImplementedError("RethClient does not support chain state snapshot via RPC.")

    def revert(self, snapshot_id: str) -> None:
        """
        Reth does not have a direct `evm_revert` equivalent.
        This operation is not supported via RPC for Reth.
        """
        raise NotImplementedError("RethClient does not support chain state revert via RPC.")
