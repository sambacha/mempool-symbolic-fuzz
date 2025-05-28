# eth_txpool_fuzzer_core/fuzz_engine.py
"""
Core fuzzing engine components: Seed, SeedDatabase, and the main FuzzEngine class.
This module orchestrates the fuzzing process, managing states, inputs, and mutations.
"""

import sys
import time
from typing import List, Optional, Dict, Any

from .tx import FuzzInput, FuzzTx
from .accounts import AccountManager
from .clients.base_client import IEthereumClient
from .state import get_symbolic_pool_state, get_txpool_energy
from .exploit_detectors import ExploitCondition
from .strategies.base_strategy import MutationStrategy # Import MutationStrategy from its new location
from . import config as core_config

# TODO: Set up a proper logger for this module
# import logging
# logger = logging = logging.getLogger(__name__)

class Seed:
    """
    Represents a seed in the fuzzing process. A seed encapsulates an input
    sequence of transactions and the resulting transaction pool state.
    It also stores metadata used for prioritizing exploration.
    """
    def __init__(self,
                 fuzz_input: FuzzInput,
                 txpool_state: Optional[Dict[str, Any]], # Raw txpool content after executing fuzz_input
                 symbolic_state_str: Optional[str] = None, # Symbolic representation of txpool_state
                 energy: int = sys.maxsize, # Energy score of this state (lower is better)
                 label_for_graph: str = "", # Optional label for graph visualization
                 generation: int = 0 # How many times this seed has been mutated/processed
                ):
        self.fuzz_input: FuzzInput = fuzz_input
        self.txpool_state: Optional[Dict[str, Any]] = txpool_state
        self.symbolic_state_str: Optional[str] = symbolic_state_str
        self.energy: int = energy
        self.label_for_graph: str = label_for_graph
        self.generation: int = generation # Tracks how "old" or processed this seed is

    def __lt__(self, other: 'Seed') -> bool:
        """
        Comparison method for sorting seeds. Prioritizes lower energy.
        As a tie-breaker, prefers seeds that have been processed fewer times (lower generation).
        """
        if self.energy == other.energy:
            return self.generation < other.generation
        return self.energy < other.energy

    def __repr__(self) -> str:
        return (f"Seed(input_tx_count={len(self.fuzz_input.tx_sequence_to_execute)}, "
                f"symbol='{self.symbolic_state_str}', energy={self.energy}, gen={self.generation})")


class SeedDatabase:
    """
    Manages a collection of `Seed` objects. It prioritizes seeds for exploration
    based on their energy score and tracks known symbolic states to avoid redundant work.
    """
    def __init__(self):
        self.seeds: List[Seed] = []
        self.known_symbolic_states: set[str] = set() # Stores symbolic state strings

    def add_seed(self, seed: Seed):
        """
        Adds a new seed to the database if its symbolic state is not already known.
        Maintains the sorted order of seeds by energy.
        """
        if seed.symbolic_state_str is None:
            # TODO: Log warning: "Seed has no symbolic state, cannot track uniqueness."
            # For now, we'll add it but it won't contribute to `known_symbolic_states`
            self.seeds.append(seed)
            self.seeds.sort()
            return

        if seed.symbolic_state_str not in self.known_symbolic_states:
            self.known_symbolic_states.add(seed.symbolic_state_str)
            self.seeds.append(seed)
            self.seeds.sort() # Keep the list sorted by energy
            # TODO: Log: f"Added new seed. Symbolic state: {seed.symbolic_state_str}, Energy: {seed.energy}"
        else:
            # TODO: Log: f"Seed's state {seed.symbolic_state_str} already covered. Not adding."
            pass

    def get_next_seed(self) -> Optional[Seed]:
        """
        Retrieves the highest-priority seed (lowest energy, least processed) from the database.
        The retrieved seed's generation count is incremented, and it's re-sorted.
        Returns None if the database is empty.
        """
        if not self.seeds:
            return None

        # The list is always sorted, so the first element is the highest priority
        next_seed = self.seeds.pop(0) # Remove the best seed

        next_seed.generation += 1 # Mark it as processed one more time
        # Re-add it to the list; it will be re-sorted based on its new generation/energy
        self.seeds.append(next_seed)
        self.seeds.sort() # Re-sort the list

        return next_seed

    def is_empty(self) -> bool:
        """Checks if the seed database contains any seeds."""
        return not self.seeds

    def covers(self, symbolic_state_str: str) -> bool:
        """Checks if a given symbolic state string is already present in the database."""
        return symbolic_state_str in self.known_symbolic_states

    @property
    def count(self) -> int:
        """Returns the number of seeds currently in the database."""
        return len(self.seeds)

    def initialize_with_empty_input(self):
        """
        Adds an initial seed representing the starting state of the fuzzer
        (empty input, no prior txpool state).
        """
        initial_fuzz_input = FuzzInput(tx_sequence_to_execute=[])
        initial_seed = Seed(
            fuzz_input=initial_fuzz_input,
            txpool_state=None, # Represents the state before any fuzzing input is applied
            symbolic_state_str="<INITIAL_STATE>", # A unique symbol for the starting point
            energy=0 # Ensures this seed is picked first
        )
        self.add_seed(initial_seed)


class FuzzEngine:
    """
    The main fuzzing engine that orchestrates the entire process:
    initialization, state execution, mutation, and exploit detection.
    """
    def __init__(self,
                 account_manager: AccountManager,
                 ethereum_client: IEthereumClient, # Changed type hint to IEthereumClient
                 mutation_strategy: MutationStrategy,
                 exploit_condition: ExploitCondition,
                 txpool_size: int = core_config.DEFAULT_TXPOOL_SIZE,
                 future_slots: int = core_config.DEFAULT_FUTURE_SLOTS,
                 initial_normal_tx_count: int = core_config.DEFAULT_TXPOOL_SIZE, # Number of initial normal txs
                 initial_normal_tx_price: int = core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                 default_recipient_address: Optional[str] = None,
                 max_iterations: int = core_config.DEFAULT_MAX_FUZZ_ITERATIONS,
                 global_timeout_seconds: float = core_config.DEFAULT_GLOBAL_FUZZ_TIMEOUT_SECONDS,
                 future_flag_enabled: bool = False # Controls if future transactions are generated initially
                ):
        self.account_manager = account_manager
        self.client = ethereum_client
        self.mutation_strategy = mutation_strategy
        self.exploit_condition = exploit_condition
        self.txpool_size = txpool_size
        self.future_slots = future_slots
        self.initial_normal_tx_count = initial_normal_tx_count
        self.initial_normal_tx_price = initial_normal_tx_price
        self.default_recipient_address = default_recipient_address or self.account_manager.get_account_by_index(0)
        self.max_iterations = max_iterations
        self.global_timeout_seconds = global_timeout_seconds
        self.future_flag_enabled = future_flag_enabled

        self.seed_db = SeedDatabase()
        self.found_exploits: List[Dict[str, Any]] = []
        self.current_fuzzer_account_index = 0 # Global counter for accounts used by fuzzer for new txs

        if self.default_recipient_address is None:
            print("CRITICAL: FuzzEngine initialized without a valid default recipient address.")
            # Consider raising an error

    def _generate_future_tx(self, current_fuzzer_account_index: int, gas_prices: Dict[str, int]) -> FuzzTx:
        """Generates a 'future' transaction (high nonce, low value) using dynamic EIP-1559 prices."""
        acc_addr = self.account_manager.get_account_by_index(current_fuzzer_account_index)
        if acc_addr is None:
            acc_addr = self.account_manager.get_account_by_index(0)
            print(f"WARN: Fuzzer account index {current_fuzzer_account_index} out of bounds. Using account 0 for future tx.")

        return FuzzTx(
            account_manager_index=current_fuzzer_account_index,
            sender_address=acc_addr,
            nonce=10000, # Special nonce for future transactions
            tx_type=2, # EIP-1559 transaction
            price=gas_prices['maxFeePerGas'], # Use 'price' for maxFeePerGas
            max_priority_fee_per_gas=gas_prices['maxPriorityFeePerGas'],
            value=2 # Special value for future transactions
        )

    def _generate_parent_tx(self, current_fuzzer_account_index: int, price: int) -> FuzzTx:
        """Generates a new 'parent' transaction (nonce 0, specific value)."""
        acc_addr = self.account_manager.get_account_by_index(current_fuzzer_account_index)
        if acc_addr is None:
            acc_addr = self.account_manager.get_account_by_index(0)
            print(f"WARN: Fuzzer account index {current_fuzzer_account_index} out of bounds. Using account 0 for parent tx.")

        current_nonce = self.account_manager.get_fuzzer_nonce(acc_addr)
        if current_nonce is None:
            current_nonce = 0
            print(f"WARN: Could not get fuzzer nonce for {acc_addr}. Using 0.")

        value = core_config.DEFAULT_GAS_LIMIT * (12000 - price)

        return FuzzTx(
            account_manager_index=current_fuzzer_account_index,
            sender_address=acc_addr,
            nonce=current_nonce,
            price=price,
            value=value
        )

    def _reset_and_initial_pool_setup(self):
        """
        Resets the txpool and initializes it with a set of 'normal' transactions,
        and optionally 'future' transactions, as per original scripts' `resetAndinitial`.
        Uses dynamic gas prices for initial transactions.
        """
        # Reset the client's state or clear the pool
        print("INFO: Resetting client state or clearing transaction pool...")
        try:
            self.client.reset_state()
            print("INFO: Client state reset via reset_state method.")
        except NotImplementedError:
            print("WARN: Client does not support direct state reset. Attempting to clear txpool only.")
            # The base client's `clear_txpool_custom` is not part of the IEthereumClient interface.
            # This functionality should be handled by `reset_state` or a specific client method.
            # For now, we'll assume `reset_state` is the primary way to clear the pool.
            # If `reset_state` is not implemented, the client should handle it or raise an error.
            print("WARN: No direct txpool clearing method available via client interface. State might be inconsistent.")
        time.sleep(0.1) # Give client a moment

        # Reset all fuzzer nonces for accounts
        self.account_manager.reset_all_fuzzer_nonces(core_config.DEFAULT_INITIAL_NONCE)
        self.current_fuzzer_account_index = 0 # Reset fuzzer's account counter

        # Fetch current gas prices
        current_gas_prices = self.client.get_current_gas_prices()
        if not current_gas_prices:
            print("ERROR: Could not fetch current gas prices. Using default values for initial setup.")
            # Fallback to default values if fetching fails
            current_gas_prices = {
                'gasPrice': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                'maxFeePerGas': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                'maxPriorityFeePerGas': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                'maxFeePerBlobGas': 0 # No blob gas for normal txs
            }

        # Add initial 'normal' transactions
        print(f"INFO: Adding {self.initial_normal_tx_count} initial normal transactions.")
        sent_count = 0
        for i in range(self.txpool_size): # Iterate up to txpool_size accounts for initial txs
            if sent_count >= self.initial_normal_tx_count:
                break
            sender_addr = self.account_manager.get_account_by_index(i)
            if sender_addr is None:
                print(f"WARN: Not enough accounts for initial normal txs. Only {sent_count} sent.")
                break

            # Use EIP-1559 parameters for initial normal transactions
            initial_tx = FuzzTx(
                account_manager_index=i,
                sender_address=sender_addr,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr), # Should be 0
                tx_type=2, # EIP-1559 transaction
                price=current_gas_prices['maxFeePerGas'], # Use 'price' for maxFeePerGas
                max_priority_fee_per_gas=current_gas_prices['maxPriorityFeePerGas'],
                value=1
            )
            tx_hash = self.client.sign_and_send_transfer(initial_tx, self.account_manager.get_private_key(sender_addr))
            if tx_hash:
                self.account_manager.increment_fuzzer_nonce(sender_addr)
                sent_count += 1
            else:
                print(f"WARN: Failed to send initial normal tx from {sender_addr}.")

            if sent_count >= self.initial_normal_tx_count:
                break

        # Add initial 'future' transactions if enabled
        if self.future_flag_enabled:
            print(f"INFO: Adding {self.future_slots} initial future transactions.")
            for i in range(self.future_slots):
                # Future transactions use a high nonce (10000) and a specific value (2)
                # They also use new accounts, incrementing the fuzzer's global account index.
                future_tx = self._generate_future_tx( # Call internal method
                    self.current_fuzzer_account_index, current_gas_prices
                )
                # Need to get the private key for the sender of the future_tx
                future_tx_sender_private_key = self.account_manager.get_private_key(future_tx.sender_address)
                if future_tx_sender_private_key is None:
                    print(f"ERROR: Could not get private key for future tx sender {future_tx.sender_address}. Skipping.")
                    continue

                tx_hash = self.client.sign_and_send_transfer(future_tx, future_tx_sender_private_key)
                if tx_hash:
                    self.current_fuzzer_account_index += 1 # Increment for next future tx
                else:
                    print(f"WARN: Failed to send initial future tx from {future_tx.sender_address}.")


    def _execute_input_sequence(self,
                                input_to_execute: FuzzInput,
                                initial_pool_state_to_recreate: Optional[Dict[str, Any]] = None,
                                 base_input_for_recreation: Optional[FuzzInput] = None # The input that led to initial_pool_state_to_recreate
                               ) -> Optional[Dict[str, Any]]:
        """
        Executes a sequence of transactions against the Ethereum client.
        This involves resetting the pool to a base state (if provided) and then sending
        the transactions in the input sequence.
        Corresponds to the `execute` function in original scripts.

        :param input_to_execute: The FuzzInput object containing the transaction sequence to apply.
        :param initial_pool_state_to_recreate: The raw txpool content of the state to reset to.
                                                If None, performs initial setup (`_reset_and_initial_pool_setup`).
        :param base_input_for_recreation: The FuzzInput object that originally led to `initial_pool_state_to_recreate`.
                                           Used to get `base_input_indices_to_resend`.
        :return: The new raw txpool content after execution, or None if an error occurred.
        """
        print(f"DEBUG: _execute_input_sequence called with input_to_execute: {input_to_execute}")
        print(f"DEBUG: Type of input_to_execute: {type(input_to_execute)}")
        print(f"DEBUG: Type of input_to_execute.tx_sequence_to_execute: {type(input_to_execute.tx_sequence_to_execute)}")
        print(f"DEBUG: Content of input_to_execute.tx_sequence_to_execute: {input_to_execute.tx_sequence_to_execute}")

        if initial_pool_state_to_recreate is None:
            # This is the very first execution (state == None in original)
            self._reset_and_initial_pool_setup()
            # After initial setup, send the transactions from the current input_to_execute
            for tx_intent in input_to_execute.tx_sequence_to_execute:
                # For initial setup, recipient is often sender itself or accounts2[0]
                # Let's use the default recipient for now.
                sender_private_key = self.account_manager.get_private_key(tx_intent.sender_address)
                if sender_private_key is None:
                    print(f"ERROR: Could not get private key for sender {tx_intent.sender_address}. Skipping tx.")
                    continue
                self.client.sign_and_send_transfer(tx_intent, sender_private_key)
                # Nonce increment is handled by the fuzzer loop after successful txs.
        else:
            # Recreate the previous state by clearing and re-sending specific transactions.
            # This corresponds to the `else` branch of `execute` in original scripts.
            print("INFO: Recreating previous pool state and applying new input.")
            # Use client.reset_state() if available, otherwise clear_txpool_custom()
            try:
                self.client.reset_state()
                print("INFO: Client state reset via reset_state method for recreation.")
            except NotImplementedError:
                print("WARN: Client does not support direct state reset. Attempting to clear txpool only for recreation.")
                if not self.client.clear_txpool_custom():
                    print("WARN: Failed to clear txpool for state recreation. Cannot guarantee consistent base state.")
                    return None # Cannot proceed if pool cannot be cleared

            # Reset nonces for accounts involved in the base state recreation
            # The original scripts reset all nonces to 0, then re-sent.
            self.account_manager.reset_all_fuzzer_nonces(core_config.DEFAULT_INITIAL_NONCE)
            self.current_fuzzer_account_index = 0 # Reset fuzzer's account counter

            # Fetch current gas prices for state recreation
            current_gas_prices = self.client.get_current_gas_prices()
            if not current_gas_prices:
                print("ERROR: Could not fetch current gas prices for state recreation. Using default values.")
                current_gas_prices = {
                    'gasPrice': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                    'maxFeePerGas': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                    'maxPriorityFeePerGas': core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                    'maxFeePerBlobGas': 0
                }

            # Re-send 'normal' transactions (price 3) based on symbolic state of `initial_pool_state_to_recreate`
            symbolic_base_state = get_symbolic_pool_state(initial_pool_state_to_recreate, self.txpool_size)
            normal_tx_count_in_base = symbolic_base_state.count('N')

            sent_normal_count = 0
            for i in range(self.txpool_size): # Iterate through accounts for normal txs
                if sent_normal_count >= normal_tx_count_in_base:
                    break
                sender_addr = self.account_manager.get_account_by_index(i)
                if sender_addr is None: break

                # Use EIP-1559 parameters for initial normal transactions during recreation
                initial_normal_tx = FuzzTx(
                    account_manager_index=i,
                    sender_address=sender_addr,
                    nonce=self.account_manager.get_fuzzer_nonce(sender_addr), # Should be 0
                    tx_type=2, # EIP-1559 transaction
                    price=current_gas_prices['maxFeePerGas'], # Use 'price' for maxFeePerGas
                    max_priority_fee_per_gas=current_gas_prices['maxPriorityFeePerGas'],
                    value=1
                )
                sender_private_key = self.account_manager.get_private_key(sender_addr)
                if sender_private_key is None:
                    print(f"ERROR: Could not get private key for sender {sender_addr}. Skipping normal tx.")
                    continue
                tx_hash = self.client.sign_and_send_transfer(initial_normal_tx, sender_private_key)
                if tx_hash:
                    self.account_manager.increment_fuzzer_nonce(sender_addr)
                    sent_normal_count += 1
                else:
                    print(f"WARN: Failed to re-send normal tx from {sender_addr}.")

            # Re-send 'future' transactions if enabled and present in base state
            if self.future_flag_enabled:
                future_tx_count_in_base = symbolic_base_state.count('F')
                for i in range(future_tx_count_in_base):
                    future_tx = self._generate_future_tx( # Call internal method
                        self.current_fuzzer_account_index, current_gas_prices
                    )
                    future_tx_sender_private_key = self.account_manager.get_private_key(future_tx.sender_address)
                    if future_tx_sender_private_key is None:
                        print(f"ERROR: Could not get private key for future tx sender {future_tx.sender_address}. Skipping.")
                        continue
                    tx_hash = self.client.sign_and_send_transfer(future_tx, future_tx_sender_private_key)
                    if tx_hash:
                        self.current_fuzzer_account_index += 1
                    else:
                        print(f"WARN: Failed to re-send future tx from {future_tx.sender_address} during state recreation.")

            # Re-send transactions from the previous input that were marked as "in pool"
            # This is the `tx_indexs` part of the original `Input` class.
            if base_input_for_recreation and base_input_for_recreation.base_input_indices_to_resend:
                sorted_indices = sorted(base_input_for_recreation.base_input_indices_to_resend)
                for idx in sorted_indices:
                    if idx < len(base_input_for_recreation.tx_sequence_to_execute):
                        tx_to_resend = base_input_for_recreation.tx_sequence_to_execute[idx]
                        # The original `resend` function just calls `send` with the tx's original nonce.
                        # This implies the fuzzer's nonce tracking is separate from the tx's nonce for these.
                        tx_to_resend_private_key = self.account_manager.get_private_key(tx_to_resend.sender_address)
                        if tx_to_resend_private_key is None:
                            print(f"ERROR: Could not get private key for re-sent tx sender {tx_to_resend.sender_address}. Skipping.")
                            continue
                        self.client.sign_and_send_transfer(tx_to_resend, tx_to_resend_private_key)
                        # Do NOT increment fuzzer nonce for these re-sent transactions, as they are part of base state.
                    else:
                        print(f"WARN: Invalid index {idx} in base_input_for_recreation.base_input_indices_to_resend. Skipping.")

            # Finally, send the transactions from the current `input_to_execute`
            # The original `execute` also re-sent the *last* tx if len > 1.
            # This is a specific heuristic. Let's apply the full sequence.
            for tx_intent in input_to_execute.tx_sequence_to_execute:
                sender_private_key = self.account_manager.get_private_key(tx_intent.sender_address)
                if sender_private_key is None:
                    print(f"ERROR: Could not get private key for sender {tx_intent.sender_address}. Skipping tx.")
                    continue
                tx_hash = self.client.sign_and_send_transfer(tx_intent, sender_private_key)
                if tx_hash:
                    # Only increment nonce if the transaction was successfully sent and is not a future tx
                    if tx_intent.nonce != 10000:
                        self.account_manager.increment_fuzzer_nonce(tx_intent.sender_address)
                else:
                    print(f"WARN: Failed to send tx from {tx_intent.sender_address} (Nonce: {tx_intent.nonce}) during input execution.")

        # After all transactions are sent, get the final txpool state
        final_txpool_state = self.client.get_txpool_content()
        return final_txpool_state


    def run_fuzzing(self):
        """
        Executes the main fuzzing loop.
        """
        print("INFO: Starting fuzzing campaign...")
        start_time = time.time()
        exploit_count = 0

        # Initialize the seed database with an empty input
        self.seed_db.initialize_with_empty_input()

        iteration_count = 0
        while not self.seed_db.is_empty() and iteration_count < self.max_iterations and (time.time() - start_time) < self.global_timeout_seconds:
            iteration_count += 1
            print(f"\n--- Fuzzing Iteration {iteration_count} ---")
            print(f"Seeds in DB: {self.seed_db.count}")

            current_seed = self.seed_db.get_next_seed()
            if current_seed is None:
                print("INFO: Seed database is empty. Exiting fuzzing loop.")
                break

            print(f"INFO: Processing seed: {current_seed}")

            # 1. Mutate the current seed's input to generate new inputs
            mutated_inputs = self.mutation_strategy.mutate(
                base_input=current_seed.fuzz_input,
                current_txpool_state=current_seed.txpool_state,
                current_fuzzer_account_index=self.current_fuzzer_account_index
            )

            for new_input in mutated_inputs:
                # Execute each new input, starting from the current seed's state
                new_txpool_state = self._execute_input_sequence(
                    input_to_execute=new_input,
                    initial_pool_state_to_recreate=current_seed.txpool_state,
                    base_input_for_recreation=current_seed.fuzz_input # Pass the input that led to current_seed.txpool_state
                )

                if new_txpool_state is None:
                    print("WARN: Failed to execute input sequence. Skipping this path.")
                    continue

                # Update fuzzer's global account index based on the last transaction sent in `new_input`
                # This is a heuristic from the original scripts.
                if new_input.tx_sequence_to_execute:
                    last_tx_in_input = new_input.tx_sequence_to_execute[-1]
                    if last_tx_in_input.account_manager_index >= self.current_fuzzer_account_index:
                        self.current_fuzzer_account_index = last_tx_in_input.account_manager_index + 1

                # 3. Analyze the new state
                new_symbolic_state = get_symbolic_pool_state(new_txpool_state, self.txpool_size)
                new_energy = get_txpool_energy(new_txpool_state)

                # 4. Check for exploits
                if self.exploit_condition.check_condition(new_txpool_state):
                    exploit_count += 1
                    print(f"!!! EXPLOIT FOUND !!! (Total: {exploit_count})")
                    print(f"  Symbolic Input: {self._parse_input_to_symbol(new_input)}")
                    print(f"  Concrete Input: {self._concrete_input_to_string(new_input)}")
                    print(f"  Symbolic End State: {new_symbolic_state}")
                    self.found_exploits.append({
                        "input_symbol": self._parse_input_to_symbol(new_input),
                        "input_concrete": self._concrete_input_to_string(new_input),
                        "end_state_symbol": new_symbolic_state,
                        "raw_txpool_state": new_txpool_state,
                        "seed_generation": current_seed.generation,
                        "time_found": time.time() - start_time
                    })
                    # In original scripts, some fuzzers stopped after first exploit.
                    # For a library, we continue unless configured otherwise.
                    # if self.stop_on_first_exploit: return

                # 5. Add new state as a seed if novel
                new_seed = Seed(
                    fuzz_input=new_input,
                    txpool_state=new_txpool_state,
                    symbolic_state_str=new_symbolic_state,
                    energy=new_energy,
                    label_for_graph=new_symbolic_state # For graphviz, can be more complex
                )
                self.seed_db.add_seed(new_seed)

        end_time = time.time()
        print("\n--- Fuzzing Campaign Finished ---")
        print(f"Total time: {end_time - start_time:.2f} seconds")
        print(f"Total iterations: {iteration_count}")
        print(f"Total unique states explored: {self.seed_db.count}")
        print(f"Total exploits found: {exploit_count}")

        return self.found_exploits

    def _parse_input_to_symbol(self, fuzz_input: FuzzInput) -> str:
        """
        Converts a FuzzInput's transaction sequence into a symbolic string.
        Corresponds to `parseInput` in original scripts.
        """
        output = ""
        sender_nonce_tracker: Dict[str, int] = {} # Tracks last seen nonce for each sender
        for tx in fuzz_input.tx_sequence_to_execute:
            if tx.nonce == 0:
                if tx.price < core_config.STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD:
                    output += "P"
                else:
                    output += "R"
                sender_nonce_tracker[tx.sender_address] = 0
            elif tx.sender_address in sender_nonce_tracker and tx.nonce == sender_nonce_tracker[tx.sender_address] + 1:
                # Check if it's a child (C) or override (O)
                if tx.value <= core_config.STATE_CHILD_VALUE_THRESHOLD:
                    output += "C"
                else:
                    output += "O"
                sender_nonce_tracker[tx.sender_address] = tx.nonce
            # Transactions that don't fit P/R/C/O pattern (e.g., gapped nonces) are ignored in original symbolization.
        return output

    def _concrete_input_to_string(self, fuzz_input: FuzzInput) -> List[str]:
        """
        Converts a FuzzInput's transaction sequence into a list of concrete string representations.
        Corresponds to `concreteInput` in original scripts.
        """
        output_strings: List[str] = []
        for tx in fuzz_input.tx_sequence_to_execute:
            tx_string = (f"from: {tx.sender_address}, to: {self.default_recipient_address}, "
                         f"nonce: {tx.nonce}, price: {tx.price}, value: {tx.value}")
            output_strings.append(tx_string)
        return output_strings
