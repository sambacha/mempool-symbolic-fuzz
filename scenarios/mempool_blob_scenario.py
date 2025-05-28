"""
Implements a fuzzing scenario specifically for EIP-4844 blob transactions.
This scenario uses blob-specific mutation strategies and exploit detectors.
"""

from typing import List

# Import core library components
from eth_txpool_fuzzer_core.accounts import AccountManager
from eth_txpool_fuzzer_core.client_comms import EthereumClient
from eth_txpool_fuzzer_core.mutation import DefaultTxPoolMutation, CompositeMutationStrategy
from eth_txpool_fuzzer_core.mutation_strategies.blob_mutation import BlobTxMutationStrategy
from eth_txpool_fuzzer_core.exploit_detectors import ExploitCondition, CompositeExploitCondition, PendingEmptyExploit, LowCostStateExploit
from eth_txpool_fuzzer_core.exploit_detectors_blob import BlobPoolStallExploit, BlobGasPriceManipulationExploit, InvalidBlobTxAcceptanceExploit
from eth_txpool_fuzzer_core.fuzz_engine import FuzzEngine
from eth_txpool_fuzzer_core import config as core_config

def run_mempool_blob_scenario(
    rpc_url: str = core_config.DEFAULT_TARGET_URL,
    key_file_primary: str = core_config.DEFAULT_KEY_FILE_PRIMARY,
    key_file_secondary: str = core_config.DEFAULT_KEY_FILE_SECONDARY,
    txpool_size: int = 16,
    future_slots: int = 4,
    max_fuzz_iterations: int = core_config.DEFAULT_MAX_FUZZ_ITERATIONS,
    global_fuzz_timeout_seconds: float = core_config.DEFAULT_GLOBAL_FUZZ_TIMEOUT_SECONDS,
    max_blobs_per_tx: int = 2,
    min_blob_gas_price: int = 1,
    max_blob_gas_price: int = 1000
):
    """
    Runs a fuzzing scenario specifically designed for EIP-4844 blob transactions.
    """
    print("--- Starting Mempool Blob Scenario ---")
    print(f"Target RPC: {rpc_url}")
    print(f"TxPool Size: {txpool_size}")
    print(f"Future Slots: {future_slots}")
    print(f"Max Blobs per Tx: {max_blobs_per_tx}")
    print(f"Blob Gas Price Range: {min_blob_gas_price}-{max_blob_gas_price}")

    # 1. Initialize AccountManager
    try:
        account_manager = AccountManager(
            key_file_paths=[key_file_primary, key_file_secondary],
            max_accounts_to_load=core_config.MAX_ACCOUNTS_TO_LOAD
        )
        if account_manager.loaded_account_count == 0:
            print("ERROR: No accounts loaded. Cannot proceed with fuzzing.")
            return
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to initialize AccountManager: {e}")
        return

    # 2. Initialize EthereumClient
    try:
        ethereum_client = EthereumClient(rpc_url=rpc_url)
    except ConnectionError as e:
        print(f"CRITICAL ERROR: {e}")
        return
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to initialize EthereumClient: {e}")
        return

    # 3. Initialize Mutation Strategies
    # Combine default mutations with blob-specific mutations
    default_mutation = DefaultTxPoolMutation(
        account_manager=account_manager,
        ethereum_client=ethereum_client, # Add ethereum_client
        txpool_size_config=txpool_size,
        future_slots_config=future_slots,
        price_ladder_step_length=1 # Can be configured
    )
    blob_mutation = BlobTxMutationStrategy(
        account_manager=account_manager,
        ethereum_client=ethereum_client, # Pass the ethereum_client instance
        max_blobs_per_tx=max_blobs_per_tx,
        min_blob_gas_price=min_blob_gas_price,
        max_blob_gas_price=max_blob_gas_price
    )
    mutation_strategy = CompositeMutationStrategy(
        account_manager=account_manager,
        strategies=[default_mutation, blob_mutation]
    )

    # 4. Initialize Exploit Conditions
    # Combine existing exploit conditions with new blob-specific ones
    exploit_conditions_list: List[ExploitCondition] = [
        PendingEmptyExploit(),
        LowCostStateExploit(txpool_size_override=txpool_size),
        # EpsilonCostExploit(epsilon_value=0.5, txpool_size_override=txpool_size), # Example, if desired
        BlobPoolStallExploit(),
        BlobGasPriceManipulationExploit(min_blob_gas_price, max_blob_gas_price),
        InvalidBlobTxAcceptanceExploit()
    ]
    exploit_condition = CompositeExploitCondition(exploit_conditions_list)

    # 5. Initialize and Run FuzzEngine
    fuzz_engine = FuzzEngine(
        account_manager=account_manager,
        ethereum_client=ethereum_client,
        mutation_strategy=mutation_strategy,
        exploit_condition=exploit_condition,
        txpool_size=txpool_size,
        future_slots=future_slots,
        initial_normal_tx_count=txpool_size, # Initialize with normal txs
        initial_normal_tx_price=core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
        max_iterations=max_fuzz_iterations,
        global_timeout_seconds=global_fuzz_timeout_seconds,
        future_flag_enabled=True # Enable future txs for a more complex pool state
    )

    found_exploits = fuzz_engine.run_fuzzing()

    print("\n--- Mempool Blob Scenario Results ---")
    if found_exploits:
        print(f"Found {len(found_exploits)} exploit(s):")
        for i, exploit in enumerate(found_exploits):
            print(f"\nExploit {i+1}:")
            print(f"  Input Symbol: {exploit['input_symbol']}")
            print(f"  Concrete Input: {exploit['input_concrete']}")
            print(f"  End State Symbol: {exploit['end_state_symbol']}")
            print(f"  Found at Generation: {exploit['seed_generation']}")
            print(f"  Time into Fuzzing: {exploit['time_found']:.2f}s")
    else:
        print("No exploits found in this run.")

if __name__ == "__main__":
    run_mempool_blob_scenario(
        txpool_size=16,
        future_slots=4,
        max_blobs_per_tx=2,
        min_blob_gas_price=1,
        max_blob_gas_price=1000
    )
