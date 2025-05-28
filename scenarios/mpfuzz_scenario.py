# eth_txpool_fuzzer/scenarios/mpfuzz_scenario.py
"""
Implements the fuzzing scenario based on the original mpfuzz.py.
This script orchestrates the setup and execution of the FuzzEngine
with specific configurations and exploit conditions.
"""


# Import core library components
from eth_txpool_fuzzer_core.accounts import AccountManager
from eth_txpool_fuzzer_core.client_comms import EthereumClient
from eth_txpool_fuzzer_core.mutation import DefaultTxPoolMutation
from eth_txpool_fuzzer_core.exploit_detectors import LowCostStateExploit
from eth_txpool_fuzzer_core.fuzz_engine import FuzzEngine
from eth_txpool_fuzzer_core import config as core_config

# Optional: For graphviz visualization, if needed in the scenario runner
# import graphviz

def run_mpfuzz_scenario(
    rpc_url: str = core_config.DEFAULT_TARGET_URL,
    key_file_primary: str = core_config.DEFAULT_KEY_FILE_PRIMARY,
    key_file_secondary: str = core_config.DEFAULT_KEY_FILE_SECONDARY,
    txpool_size: int = 4, # Specific to mpfuzz.py
    max_fuzz_iterations: int = core_config.DEFAULT_MAX_FUZZ_ITERATIONS,
    global_fuzz_timeout_seconds: float = core_config.DEFAULT_GLOBAL_FUZZ_TIMEOUT_SECONDS
):
    """
    Runs the fuzzing scenario mimicking the behavior of the original mpfuzz.py.
    """
    print("--- Starting MPFuzz Scenario ---")
    print(f"Target RPC: {rpc_url}")
    print(f"TxPool Size: {txpool_size}")

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

    # 3. Initialize MutationStrategy
    # mpfuzz.py uses step_length = 1 for price laddering
    mutation_strategy = DefaultTxPoolMutation(
        account_manager=account_manager,
        ethereum_client=ethereum_client, # Add ethereum_client
        txpool_size_config=txpool_size,
        price_ladder_step_length=1 # Specific to mpfuzz.py
    )

    # 4. Initialize ExploitCondition
    # mpfuzz.py uses LowCostStateExploit
    exploit_condition = LowCostStateExploit(
        txpool_size_override=txpool_size,
        normal_price_indicator=core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
        parent_replace_threshold=core_config.STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD,
        child_val_threshold=core_config.STATE_CHILD_VALUE_THRESHOLD
    )

    # 5. Initialize and Run FuzzEngine
    fuzz_engine = FuzzEngine(
        account_manager=account_manager,
        ethereum_client=ethereum_client,
        mutation_strategy=mutation_strategy,
        exploit_condition=exploit_condition,
        txpool_size=txpool_size,
        future_slots=core_config.DEFAULT_FUTURE_SLOTS, # mpfuzz.py has future_flag = False, but future_slots is 1
                                                        # The `future_flag_enabled` in FuzzEngine controls if they are sent.
        initial_normal_tx_count=txpool_size, # mpfuzz.py initializes with txpool_size normal txs
        initial_normal_tx_price=core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
        max_iterations=max_fuzz_iterations,
        global_timeout_seconds=global_fuzz_timeout_seconds,
        future_flag_enabled=False # mpfuzz.py has future_flag = False
    )

    found_exploits = fuzz_engine.run_fuzzing()

    print("\n--- MPFuzz Scenario Results ---")
    if found_exploits:
        print(f"Found {len(found_exploits)} exploit(s):")
        for i, exploit in enumerate(found_exploits):
            print(f"\nExploit {i+1}:")
            print(f"  Symbolic Input: {exploit['input_symbol']}")
            print(f"  Concrete Input: {exploit['input_concrete']}")
            print(f"  End State Symbol: {exploit['end_state_symbol']}")
            print(f"  Found at Generation: {exploit['seed_generation']}")
            print(f"  Time into Fuzzing: {exploit['time_found']:.2f}s")
    else:
        print("No exploits found in this run.")

    # Optional: Graphviz visualization (if we decide to re-implement it)
    # f.view() # This would require passing the graphviz object from FuzzEngine or re-creating.
    # For now, we'll skip direct graphviz integration in the scenario runner.

if __name__ == "__main__":
    # Example of how to run this scenario
    # You might want to parse command-line arguments for rpc_url, txpool_size etc.
    # For now, use defaults or hardcoded values for testing.

    # To run: python -m scenarios.mpfuzz_scenario

    # Example: Override txpool_size from original mpfuzz.py
    # run_mpfuzz_scenario(txpool_size=4)

    # Or, to match mpfuzz.py's default:
    run_mpfuzz_scenario(
        txpool_size=4, # Default from mpfuzz.py
        max_fuzz_iterations=1000, # Default from core_config
        global_fuzz_timeout_seconds=3600 # Default from core_config
    )
