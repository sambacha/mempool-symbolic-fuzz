import subprocess
import time
from typing import Any, Dict, List, Optional
from web3 import Web3
from web3.middleware import geth_poa_middleware # Geth often uses POA

from eth_txpool_fuzzer_core.clients.base_client import IEthereumClient
from eth_txpool_fuzzer_core.tx import FuzzTx

class GethClient(IEthereumClient):
    """
    Ethereum client implementation for Geth.
    Manages a Geth process and interacts with it via RPC.
    """

    def __init__(self, rpc_url: str, manage_lifecycle: bool = True,
                 rpc_method_aliases: Optional[Dict[str, str]] = None,
                 binary_path: str = "geth", port: int = 8545,
                 chain_id: Optional[int] = None, data_dir: Optional[str] = None,
                 network_id: Optional[int] = None,
                 **kwargs):
        """
        Initializes the Geth client.

        Args:
            rpc_url: The URL to connect to Geth's RPC endpoint (e.g., "http://127.0.0.1:8545").
            manage_lifecycle: If True, the fuzzer will start and stop the Geth process.
            rpc_method_aliases: Custom RPC method aliases.
            binary_path: Path to the Geth executable.
            port: The port Geth should listen on.
            chain_id: The chain ID for Geth.
            data_dir: Path to the Geth data directory.
            network_id: The network ID for Geth.
            **kwargs: Additional arguments to pass to the Geth binary.
        """
        super().__init__(rpc_url, manage_lifecycle, rpc_method_aliases, **kwargs)
        self.binary_path = binary_path
        self.port = port
        self.chain_id = chain_id
        self.data_dir = data_dir
        self.network_id = network_id

        # Default Geth-specific RPC aliases
        self.default_rpc_aliases = {
            "reset_state": "debug_resetChain", # Geth supports this for dev chains
            "fund_accounts": None, # Geth does not have a direct setBalance equivalent
            "snapshot": "evm_snapshot", # Geth supports this on dev chains
            "revert": "evm_revert", # Geth supports this on dev chains
            "get_txpool_content": "txpool_content"
        }
        # Merge default aliases with user-provided ones
        self.rpc_method_aliases = {**self.default_rpc_aliases, **self.rpc_method_aliases}

    def get_web3_instance(self) -> Web3:
        """
        Returns a web3.py instance connected to the Geth RPC endpoint,
        with Geth-specific middleware (e.g., POA) injected.
        """
        if self.w3 is None:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            # Inject Geth POA middleware if needed (common for dev chains)
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        return self.w3

    def start(self) -> None:
        """
        Starts the Geth client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle:
            print(f"INFO: Geth client lifecycle not managed. Assuming Geth is already running at {self.rpc_url}.")
            self.get_web3_instance() # Attempt to connect to verify
            return

        print(f"INFO: Starting Geth client on port {self.port}...")
        command = [
            self.binary_path,
            "--http",
            "--http.port", str(self.port),
            "--http.api", "eth,net,web3,txpool,debug,miner", # Enable necessary APIs
            "--allow-insecure-unlock" # For local testing with unlocked accounts
        ]
        if self.chain_id is not None:
            command.extend(["--chainid", str(self.chain_id)])
        if self.data_dir:
            command.extend(["--datadir", self.data_dir])
        if self.network_id is not None:
            command.extend(["--networkid", str(self.network_id)])

        # Add any extra kwargs as command line arguments
        for k, v in self._client_kwargs.items():
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
            print(f"INFO: Geth process started with PID {self._process.pid}")

            # Wait for Geth to be ready
            self.get_web3_instance() # Initialize w3
            timeout = 60 # Geth might take longer to start
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    if self.w3.is_connected():
                        print("INFO: Geth client is connected and ready.")
                        return
                except Exception:
                    pass
                time.sleep(0.5) # Longer sleep for Geth
            raise RuntimeError(f"Geth client did not become ready within {timeout} seconds.")
        except FileNotFoundError:
            raise RuntimeError(f"Geth binary not found at '{self.binary_path}'. Please ensure Geth is installed and in your PATH, or provide the correct binary_path.")
        except Exception as e:
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
            raise RuntimeError(f"Failed to start Geth client: {e}")

    def stop(self) -> None:
        """
        Stops/terminates the Geth client process if manage_lifecycle is True.
        """
        if not self.manage_lifecycle or self._process is None:
            return

        print("INFO: Stopping Geth client...")
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
            print("INFO: Geth client stopped.")
        except subprocess.TimeoutExpired:
            print("WARN: Geth client did not terminate gracefully. Killing process.")
            self._process.kill()
            self._process.wait()
        self._process = None

    def reset_state(self) -> None:
        """
        Resets the Geth blockchain state.
        Geth supports `debug_resetChain` on dev chains. If not, a full restart might be needed.
        """
        w3 = self.get_web3_instance()
        method = self.rpc_method_aliases.get("reset_state")
        if method:
            try:
                self.call_custom_rpc(method)
                print("INFO: Geth state reset via RPC.")
            except Exception as e:
                print(f"ERROR: Failed to reset Geth state via RPC ({method}): {e}. Consider restarting Geth.")
                raise
        else:
            # If no specific RPC for reset, a full restart might be the only option for managed clients.
            # For unmanaged clients, this operation is not possible via the fuzzer.
            if self.manage_lifecycle:
                print("WARN: No direct RPC method for state reset in Geth. Attempting full client restart.")
                self.stop()
                # Clean data directory if specified and managed
                if self.data_dir:
                    print(f"INFO: Deleting Geth data directory: {self.data_dir}")
                    import shutil
                    try:
                        shutil.rmtree(self.data_dir)
                    except OSError as e:
                        print(f"ERROR: Failed to delete Geth data directory {self.data_dir}: {e}")
                        raise
                self.start() # Restart to get a clean state
            else:
                raise NotImplementedError("Geth client does not support state reset without lifecycle management or a specific RPC alias.")

    def fund_accounts(self, addresses: List[str], amount: int) -> None:
        """
        Funds the specified addresses. Geth does not have a direct `setBalance` RPC.
        This would typically involve sending transactions from a pre-funded account.
        For simplicity, this is marked as not implemented for now.
        """
        raise NotImplementedError("GethClient does not support direct account funding via RPC. "
                                  "Accounts must be pre-funded or funded via transactions from a known account.")

    def get_current_gas_prices(self) -> Dict[str, int]:
        """
        Fetches current gas prices from Geth.
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

            # Geth supports eth_blobGasPrice
            max_fee_per_blob_gas = 0
            try:
                blob_gas_price_method = self.rpc_method_aliases.get("get_blob_gas_price", "eth_blobGasPrice")
                blob_gas_price_hex = self.call_custom_rpc(blob_gas_price_method)
                if blob_gas_price_hex:
                    max_fee_per_blob_gas = int(blob_gas_price_hex, 16)
            except Exception:
                print("WARN: eth_blobGasPrice not available or failed for Geth. Using 0.")
                max_fee_per_blob_gas = 0 # Default to 0 if not available

            return {
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'gasPrice': w3.eth.gas_price, # Legacy gas price
                'maxFeePerBlobGas': max_fee_per_blob_gas
            }
        except Exception as e:
            print(f"WARN: Could not fetch Geth gas prices: {e}. Using default values.")
            return {
                'maxFeePerGas': w3.to_wei(100, 'gwei'),
                'maxPriorityFeePerGas': w3.to_wei(1, 'gwei'),
                'gasPrice': w3.to_wei(100, 'gwei'),
                'maxFeePerBlobGas': w3.to_wei(1, 'gwei')
            }

    def sign_and_send_transfer(self, tx: FuzzTx, private_key: str) -> str:
        """
        Signs and sends a transaction to Geth.
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
            # For Geth, waiting for receipt might be necessary for state updates
            w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
            return tx_hash
        except Exception as e:
            print(f"ERROR: Failed to send transaction to Geth: {e}")
            raise

    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Retrieves the current transaction pool content from Geth using `txpool_content` RPC.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("get_txpool_content", "txpool_content")
            pool_content = self.call_custom_rpc(method)

            # Geth's txpool_content returns 'pending' and 'queued' directly
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
            print(f"ERROR: Failed to get Geth txpool content: {e}")
            return {"pending": {}, "queued": {}}

    def snapshot(self) -> str:
        """
        Creates a snapshot of the current Geth chain state using `evm_snapshot` RPC.
        Note: This is typically only available on development chains.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("snapshot", "evm_snapshot")
            snapshot_id = self.call_custom_rpc(method)
            print(f"INFO: Geth state snapshot created with ID: {snapshot_id}")
            return snapshot_id
        except Exception as e:
            print(f"ERROR: Failed to create Geth snapshot: {e}")
            raise

    def revert(self, snapshot_id: str) -> None:
        """
        Reverts the Geth chain state to a previously created snapshot using `evm_revert` RPC.
        Note: This is typically only available on development chains.
        """
        w3 = self.get_web3_instance()
        try:
            method = self.rpc_method_aliases.get("revert", "evm_revert")
            self.call_custom_rpc(method, snapshot_id)
            print(f"INFO: Geth state reverted to snapshot ID: {snapshot_id}")
        except Exception as e:
            print(f"ERROR: Failed to revert Geth state: {e}")
            raise
