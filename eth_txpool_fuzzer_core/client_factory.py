from typing import Any, Dict
from eth_txpool_fuzzer_core.clients.base_client import IEthereumClient
from eth_txpool_fuzzer_core.clients.anvil_client import AnvilClient
from eth_txpool_fuzzer_core.clients.reth_client import RethClient
from eth_txpool_fuzzer_core.clients.geth_client import GethClient

class ClientFactory:
    """
    A factory class for creating instances of different Ethereum clients
    based on a specified client type.
    """

    @staticmethod
    def create_client(client_type: str, client_config: Dict[str, Any]) -> IEthereumClient:
        """
        Creates and returns an instance of an Ethereum client.

        Args:
            client_type: The type of Ethereum client to create (e.g., "anvil", "reth", "geth").
            client_config: A dictionary containing configuration parameters for the client.
                           This should include 'rpc_url', 'manage_lifecycle' (optional),
                           'rpc_method_aliases' (optional), and any client-specific parameters.

        Returns:
            An instance of a class implementing IEthereumClient.

        Raises:
            ValueError: If an unsupported client_type is provided.
            KeyError: If 'rpc_url' is missing from client_config.
        """
        rpc_url = client_config.get('rpc_url')
        if not rpc_url:
            raise KeyError("client_config must contain 'rpc_url'.")

        manage_lifecycle = client_config.get('manage_lifecycle', True)
        rpc_method_aliases = client_config.get('rpc_method_aliases')

        # Extract client-specific kwargs, excluding common ones already handled
        specific_kwargs = {k: v for k, v in client_config.items()
                           if k not in ['rpc_url', 'manage_lifecycle', 'rpc_method_aliases']}

        if client_type.lower() == "anvil":
            return AnvilClient(
                rpc_url=rpc_url,
                manage_lifecycle=manage_lifecycle,
                rpc_method_aliases=rpc_method_aliases,
                **specific_kwargs
            )
        elif client_type.lower() == "reth":
            return RethClient(
                rpc_url=rpc_url,
                manage_lifecycle=manage_lifecycle,
                rpc_method_aliases=rpc_method_aliases,
                **specific_kwargs
            )
        elif client_type.lower() == "geth":
            return GethClient(
                rpc_url=rpc_url,
                manage_lifecycle=manage_lifecycle,
                rpc_method_aliases=rpc_method_aliases,
                **specific_kwargs
            )
        else:
            raise ValueError(f"Unsupported client type: {client_type}")
