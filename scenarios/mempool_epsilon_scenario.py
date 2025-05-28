# eth_txpool_fuzzer/scenarios/mpfuzz_epsilon_scenario.py
"""
Implements the fuzzing scenario based on the original mpfuzz_epsilon.py.
This script orchestrates the setup and execution of the FuzzEngine
with specific configurations and exploit conditions, including an epsilon parameter.
"""

import sys

# Import core library components
from eth_txpool_fuzzer_core.accounts import AccountManager
from eth_txpool_fuzzer_core.client_comms import EthereumClient
from eth_txpool_fuzzer_core.mutation import DefaultTxPoolMutation
from eth_txpool_fuzzer_core.exploit_detectors import EpsilonCostExploit
from eth_txpool_fuzzer_core.fuzz_engine import FuzzEngine
from eth_txpool_fuzzer_core import config as core_config

def run_mpfuzz_epsilon_scenario(
    epsilon: float, # Required parameter for this scenario
    rpc_url: str = core_config.DEFAULT_TARGET_URL,
    key_file_primary: str = core_config.DEFAULT_KEY_FILE_PRIMARY,
    key_file_secondary: str = core_config.DEFAULT_KEY_FILE_SECONDARY,
    txpool_size: int = 16, # Specific to mpfuzz_epsilon.py
    future_slots: int = 4, # Specific to mpfuzz_epsilon.py
    max_fuzz_iterations: int = core_config.DEFAULT_MAX_FUZZ_ITERATIONS,
    global_fuzz_timeout_seconds: float = core_config.DEFAULT_GLOBAL_FUZZ_TIMEOUT_SECONDS
):
    """
    Runs the fuzzing scenario mimicking the behavior of the original mpfuzz_epsilon.py.
    """
    print("--- Starting MPFuzz Epsilon Scenario ---")
    print(f"Target RPC: {rpc_url}")
    print(f"TxPool Size: {txpool_size}")
    print(f"Future Slots: {future_slots}")
    print(f"Epsilon: {epsilon}")

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
    # mpfuzz_epsilon.py uses step_length = 1 for price laddering
    mutation_strategy = DefaultTxPoolMutation(
        account_manager=account_manager,
        txpool_size_config=txpool_size,
        future_slots_config=future_slots,
        price_ladder_step_length=1 # Specific to mpfuzz_epsilon.py
    )

    # 4. Initialize ExploitCondition
    # mpfuzz_epsilon.py uses EpsilonCostExploit
    exploit_condition = EpsilonCostExploit(
        epsilon_value=epsilon,
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
        future_slots=future_slots,
        initial_normal_tx_count=txpool_size, # mpfuzz_epsilon.py initializes with txpool_size normal txs
        initial_normal_tx_price=core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
        max_iterations=max_fuzz_iterations,
        global_timeout_seconds=global_fuzz_timeout_seconds,
        future_flag_enabled=False # mpfuzz_epsilon.py has future_flag = False
    )

    found_exploits = fuzz_engine.run_fuzzing()

    print("\n--- MPFuzz Epsilon Scenario Results ---")
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

if __name__ == "__main__":
    # To run: python -m scenarios.mpfuzz_epsilon_scenario <epsilon_value>
    # Example: python -m scenarios.mpfuzz_epsilon_scenario 0.5

    if len(sys.argv) < 2:
        print("Usage: python -m scenarios.mpfuzz_epsilon_scenario <epsilon_value>")
        sys.exit(1)

    try:
        epsilon_val = float(sys.argv[1])
    except ValueError:
        print("Error: Epsilon value must be a number.")
        sys.exit(1)

    run_mpfuzz_epsilon_scenario(
        epsilon=epsilon_val,
        txpool_size=16, # Default from mpfuzz_epsilon.py
        future_slots=4, # Default from mpfuzz_epsilon.py
        max_fuzz_iterations=1000, # Default from core_config
        global_fuzz_timeout_seconds=3600 # Default from core_config
    )
