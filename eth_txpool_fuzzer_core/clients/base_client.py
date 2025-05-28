import abc
import subprocess
from typing import Any, Dict, List, Optional
from web3 import Web3
from eth_txpool_fuzzer_core.tx import FuzzTx # Assuming FuzzTx is in eth_txpool_fuzzer_core/tx.py

class IEthereumClient(abc.ABC):
    """
    Abstract Base Class defining the interface for all Ethereum client implementations.
    This ensures a consistent API for the FuzzEngine and other components,
    regardless of the underlying client (Anvil, Reth, Geth, etc.).
    """

    def __init__(self, rpc_url: str, manage_lifecycle: bool = True,
                 rpc_method_aliases: Optional[Dict[str, str]] = None, **kwargs):
        """
        Initializes the Ethereum client interface.

        Args:
            rpc_url: The URL to connect to the client's RPC endpoint (e.g., "http://127.0.0.1:8545").
            manage_lifecycle: If True, the fuzzer will attempt to start and stop the client process.
                              If False, it will only connect to an already running client.
            rpc_method_aliases: An optional dictionary mapping generic fuzzer RPC method names
                                (e.g., "reset_state", "fund_accounts") to client-specific RPC method names.
                                This allows customization for clients with non-standard RPCs or for aliasing.
            **kwargs: Client-specific configuration parameters (e.g., binary path, port for managed clients).
        """
        self.rpc_url = rpc_url
        self.manage_lifecycle = manage_lifecycle
        self.rpc_method_aliases = rpc_method_aliases if rpc_method_aliases is not None else {}
        self.w3: Optional[Web3] = None
        self._process: Optional[subprocess.Popen] = None # For managed clients
        self._client_kwargs = kwargs # Store client-specific kwargs

    @abc.abstractmethod
    def start(self) -> None:
        """
        Starts the Ethereum client process.
        If manage_lifecycle is False, this method should be a no-op or raise an informative error.
        """
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """
        Stops/terminates the Ethereum client process.
        If manage_lifecycle is False, this method should be a no-op.
        """
        pass

    @abc.abstractmethod
    def reset_state(self) -> None:
        """
        Resets the client's blockchain state to a clean state (e.g., genesis or a specific block).
        This method should internally use the rpc_method_aliases to call the correct
        client-specific RPC (e.g., "anvil_reset", "debug_resetChain").
        """
        pass

    @abc.abstractmethod
    def fund_accounts(self, addresses: List[str], amount: int) -> None:
        """
        Funds the specified Ethereum addresses with the given amount.
        This method should internally use the rpc_method_aliases if a custom
        funding RPC is specified, or implement a default funding mechanism.
        """
        pass

    def get_web3_instance(self) -> Web3:
        """
        Returns a web3.py instance connected to the client's RPC endpoint.
        This method should be implemented by concrete classes to ensure the
        Web3 instance is properly configured for the specific client.
        """
        if self.w3 is None:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            # Add any necessary middleware here, e.g., for POA chains
            # from web3.middleware import geth_poa_middleware
            # self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        return self.w3

    @abc.abstractmethod
    def get_current_gas_prices(self) -> Dict[str, int]:
        """
        Fetches the current gas prices from the client.
        Returns a dictionary with keys like 'maxFeePerGas', 'maxPriorityFeePerGas', 'gasPrice', 'maxFeePerBlobGas'.
        """
        pass

    @abc.abstractmethod
    def sign_and_send_transfer(self, tx: FuzzTx, private_key: str) -> str:
        """
        Signs and sends a transaction to the client.
        Returns the transaction hash.
        """
        pass

    @abc.abstractmethod
    def get_txpool_content(self) -> Dict[str, Any]:
        """
        Retrieves the current transaction pool content from the client.
        Returns a dictionary representing the pending and queued transactions.
        """
        pass

    @abc.abstractmethod
    def snapshot(self) -> str:
        """
        Creates a snapshot of the current chain state.
        Returns a snapshot ID (string).
        """
        pass

    @abc.abstractmethod
    def revert(self, snapshot_id: str) -> None:
        """
        Reverts the chain state to a previously created snapshot.
        Args:
            snapshot_id: The ID of the snapshot to revert to.
        """
        pass

    def call_custom_rpc(self, method: str, *args, **kwargs) -> Any:
        """
        A generic method to call any arbitrary RPC method on the connected client.
        This provides maximum flexibility for client-specific features not covered
        by the abstract interface.
        """
        w3 = self.get_web3_instance()
        # Use the aliased method name if available, otherwise use the provided method name
        actual_method = self.rpc_method_aliases.get(method, method)

        # Check if the method exists on the Web3 instance's provider
        # This is a basic check; more robust error handling might be needed
        if hasattr(w3.provider, 'make_request'):
            response = w3.provider.make_request(actual_method, args)
            if 'result' in response:
                return response['result']
            elif 'error' in response:
                raise Exception(f"RPC Error calling {actual_method}: {response['error']}")
            else:
                raise Exception(f"Unexpected RPC response for {actual_method}: {response}")
        else:
            raise NotImplementedError("Provider does not support make_request for custom RPC calls.")
