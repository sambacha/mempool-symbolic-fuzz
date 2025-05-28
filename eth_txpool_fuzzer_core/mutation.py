"""
Defines strategies and functions for mutating transaction sequences (fuzzing inputs).
"""

import copy
from typing import List, Dict, Any, Optional, Tuple

from .tx import FuzzTx, FuzzInput
from .accounts import AccountManager
from . import config as core_config
from .clients.base_client import IEthereumClient
from .strategies.base_strategy import MutationStrategy
from .mutation_strategies.blob_mutation import BlobTxMutationStrategy

class CompositeMutationStrategy(MutationStrategy):
    """
    A composite mutation strategy that combines multiple individual mutation strategies.
    """
    def __init__(self, account_manager: AccountManager, ethereum_client: IEthereumClient, strategies: List[MutationStrategy]):
        super().__init__(account_manager)
        self.ethereum_client = ethereum_client # Store the client instance
        self.strategies = strategies

        # Re-initialize strategies with the ethereum_client if they are not already
        # This ensures all sub-strategies have access to the client for dynamic pricing
        for i, strategy in enumerate(self.strategies):
            if not hasattr(strategy, 'ethereum_client'):
                # This is a simplified re-initialization. A more robust solution
                # might involve a factory pattern or ensuring strategies are
                # always created with the client from the scenario.
                if isinstance(strategy, DefaultTxPoolMutation):
                    self.strategies[i] = DefaultTxPoolMutation(account_manager, ethereum_client, **{k: v for k, v in strategy.__dict__.items() if k not in ['account_manager', 'ethereum_client']})
                elif isinstance(strategy, BlobTxMutationStrategy):
                    self.strategies[i] = BlobTxMutationStrategy(account_manager, ethereum_client, **{k: v for k, v in strategy.__dict__.items() if k not in ['account_manager', 'ethereum_client']})
                # Add other strategy types here as needed

    def mutate(self,
               base_input: FuzzInput,
               current_txpool_state: Optional[Dict[str, Any]],
               current_fuzzer_account_index: int
              ) -> List[FuzzInput]:
        """
        Applies all contained mutation strategies and returns a combined list of mutated inputs.
        """
        all_mutated_inputs: List[FuzzInput] = []
        for strategy in self.strategies:
            all_mutated_inputs.extend(
                strategy.mutate(base_input, current_txpool_state, current_fuzzer_account_index)
            )
        return all_mutated_inputs

class DefaultTxPoolMutation(MutationStrategy):
    """
    Implements the mutation logic found across mpfuzz.py, mpfuzz_e2a.py, mpfuzz_e2b.py.
    This includes adding child/override transactions, replacement transactions,
    and new parent transactions.
    """
    def __init__(self, account_manager: AccountManager,
                 ethereum_client: IEthereumClient, # Changed type hint to IEthereumClient
                 txpool_size_config: int = core_config.DEFAULT_TXPOOL_SIZE,
                 future_slots_config: int = core_config.DEFAULT_FUTURE_SLOTS,
                 normal_tx_price_indicator: int = core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
                 parent_replacement_price_threshold: int = core_config.STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD,
                 child_value_threshold: int = core_config.STATE_CHILD_VALUE_THRESHOLD,
                 price_ladder_step_length: int = 1 # Configurable step length for price laddering
                ):
        super().__init__(account_manager)
        self.ethereum_client = ethereum_client # Store the client instance
        self.txpool_size = txpool_size_config
        self.future_slots = future_slots_config
        self.normal_tx_price_indicator = normal_tx_price_indicator
        self.parent_replacement_price_threshold = parent_replacement_price_threshold
        self.child_value_threshold = child_value_threshold
        self.price_ladder_step_length = price_ladder_step_length

        # The original scripts often used accounts2[0] as a default recipient.
        # We'll use the first loaded account from AccountManager.
        # Ensure default_recipient_address is always a string.
        try:
            self.default_recipient_address = self._get_safe_account_address(0)
        except RuntimeError as e:
            print(f"CRITICAL: Failed to initialize DefaultTxPoolMutation: {e}")
            self.default_recipient_address = "0x0000000000000000000000000000000000000000" # Fallback dummy address

    def _get_safe_account_address(self, index: int) -> str:
        """
        Retrieves an account address by index, with fallback to index 0 if out of bounds.
        Raises a RuntimeError if no valid account can be found.
        """
        acc_addr = self.account_manager.get_account_by_index(index)
        if acc_addr is None:
            print(f"WARN: Account index {index} out of bounds. Attempting to use account 0.")
            acc_addr = self.account_manager.get_account_by_index(0)
            if acc_addr is None:
                raise RuntimeError("CRITICAL: No valid accounts found in AccountManager. Cannot generate transaction.")
        return acc_addr

    def _generate_future_tx(self, current_fuzzer_account_index: int, price: int) -> FuzzTx:
        """Generates a 'future' transaction (high nonce, low value)."""
        acc_addr = self._get_safe_account_address(current_fuzzer_account_index)
        return FuzzTx(
            account_manager_index=current_fuzzer_account_index,
            sender_address=acc_addr,
            nonce=10000, # Special nonce for future transactions
            price=price,
            value=2 # Special value for future transactions
        )

    def _generate_parent_tx(self, current_fuzzer_account_index: int, price: int) -> FuzzTx:
        """Generates a new 'parent' transaction (nonce 0, specific value)."""
        acc_addr = self._get_safe_account_address(current_fuzzer_account_index)
        current_nonce = self.account_manager.get_fuzzer_nonce(acc_addr)
        if current_nonce is None:
            current_nonce = 0 # Fallback if nonce not tracked
            print(f"WARN: Could not get fuzzer nonce for {acc_addr}. Using 0.")

        value = core_config.DEFAULT_GAS_LIMIT * (12000 - price)

        return FuzzTx(
            account_manager_index=current_fuzzer_account_index,
            sender_address=acc_addr,
            nonce=current_nonce, # Use the current fuzzer nonce
            price=price,
            value=value
        )

    def mutate(self,
               base_input: FuzzInput,
               current_txpool_state: Optional[Dict[str, Any]],
               current_fuzzer_account_index: int # The next index to use for new accounts
              ) -> List[FuzzInput]:
        """
        Applies the default mutation strategies based on the current txpool state.
        """
        mutated_inputs: List[FuzzInput] = []

        # Extract info from current_txpool_state for mutation decisions
        parent_in_pool_senders: List[str] = []
        parent_in_pool_next_nonces: Dict[str, int] = {} # sender -> next nonce
        parent_in_pool_prices: Dict[str, int] = {} # sender -> first tx price
        all_tx_in_pool_details: List[Tuple[str, int, int]] = [] # (sender, nonce, value)

        if current_txpool_state:
            pending_txs = current_txpool_state.get('pending', {})
            queued_txs = current_txpool_state.get('queued', {})

            for sender, txs_by_nonce_str in pending_txs.items():
                if not txs_by_nonce_str: continue

                sorted_nonces = sorted(txs_by_nonce_str.keys(), key=int)
                first_tx_details = txs_by_nonce_str[sorted_nonces[0]]

                try:
                    first_tx_price = int(first_tx_details.get('gasPrice', '0'), 16)
                except ValueError:
                    first_tx_price = self.normal_tx_price_indicator + 1 # Treat as non-normal if malformed

                if first_tx_price != self.normal_tx_price_indicator:
                    parent_in_pool_senders.append(sender)
                    parent_in_pool_next_nonces[sender] = len(txs_by_nonce_str) # Next nonce is count of existing txs
                    parent_in_pool_prices[sender] = first_tx_price

                for nonce_str in sorted_nonces:
                    tx_details = txs_by_nonce_str[nonce_str]
                    try:
                        all_tx_in_pool_details.append((sender, int(nonce_str), int(tx_details.get('value', '0'), 16)))
                    except ValueError:
                        print(f"WARN: Malformed nonce/value in pending tx for {sender} N:{nonce_str}. Skipping for mutation tracking.")

            for sender, txs_by_nonce_str in queued_txs.items():
                if not txs_by_nonce_str: continue
                for nonce_str in sorted(txs_by_nonce_str.keys(), key=int):
                    if int(nonce_str) != 10000: # Exclude special future txs from this list (nonce 10000)
                        tx_details = txs_by_nonce_str[nonce_str]
                        try:
                            all_tx_in_pool_details.append((sender, int(nonce_str), int(tx_details.get('value', '0'), 16)))
                        except ValueError:
                            print(f"WARN: Malformed nonce/value in queued tx for {sender} N:{nonce_str}. Skipping for mutation tracking.")

        # Determine which transactions from the base_input are still in the pool
        # This is the `state_inputindex` concept from original scripts.
        # It's used to re-send existing transactions before adding new ones.
        # Note: The `execute` function will handle the actual re-sending of these.
        base_input_tx_in_pool_indices: List[int] = []
        for i, base_tx in enumerate(base_input.tx_sequence_to_execute):
            # Check if this base_tx (sender, nonce, value) is in all_tx_in_pool_details
            if any(t[0] == base_tx.sender_address and t[1] == base_tx.nonce and t[2] == base_tx.value
                   for t in all_tx_in_pool_details):
                base_input_tx_in_pool_indices.append(i)

        # Fetch current gas prices from the client
        current_gas_prices = self.ethereum_client.get_current_gas_prices()
        base_gas_price = current_gas_prices.get('gasPrice', 0)
        base_max_fee_per_gas = current_gas_prices.get('maxFeePerGas', base_gas_price)
        base_max_priority_fee_per_gas = current_gas_prices.get('maxPriorityFeePerGas', 0)
        base_max_fee_per_blob_gas = current_gas_prices.get('maxFeePerBlobGas', 0)

        # --- Mutation 1: Add Child/Override Transactions (O/C) ---
        # For each parent transaction currently in the pool, add a child/override transaction.
        for sender in parent_in_pool_senders:
            acc_idx = self.account_manager.get_index_by_address(sender)
            if acc_idx is None: continue # Should not happen if sender is in pool

            next_nonce = parent_in_pool_next_nonces[sender]

            # Add an "Override" (O) type child (high value)
            # Use dynamic maxFeePerGas for EIP-1559/4844, or a high fixed price for legacy
            tx_price_o = max(base_max_fee_per_gas, 12000) # Ensure it's at least 12000 for 'R' type logic
            new_tx_o = FuzzTx(
                account_manager_index=acc_idx,
                sender_address=sender,
                nonce=next_nonce,
                price=tx_price_o,
                value=10**15 - core_config.DEFAULT_GAS_LIMIT * tx_price_o - 100, # Value adjusted for dynamic price
                tx_type=2, # Assume EIP-1559 for new non-legacy txs
                max_priority_fee_per_gas=base_max_priority_fee_per_gas
            )
            new_input_o_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_o_seq.append(new_tx_o)
            mutated_inputs.append(FuzzInput(new_input_o_seq, base_input_tx_in_pool_indices))

            # Add a "Child" (C) type child (low value)
            tx_price_c = max(base_max_fee_per_gas, 12000)
            new_tx_c = FuzzTx(
                account_manager_index=acc_idx,
                sender_address=sender,
                nonce=next_nonce,
                price=tx_price_c,
                value=10000, # Value 10000 from original
                tx_type=2,
                max_priority_fee_per_gas=base_max_priority_fee_per_gas
            )
            new_input_c_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_c_seq.append(new_tx_c)
            mutated_inputs.append(FuzzInput(new_input_c_seq, base_input_tx_in_pool_indices))

        # --- Mutation 2: Add Replacement Transactions (R) ---
        # For each parent in pool, add a replacement transaction (nonce 0, high price)
        for sender in parent_in_pool_senders:
            acc_idx = self.account_manager.get_index_by_address(sender)
            if acc_idx is None: continue

            tx_price_r = max(base_max_fee_per_gas, 12000) # Ensure high price for replacement
            new_tx_r = FuzzTx(
                account_manager_index=acc_idx,
                sender_address=sender,
                nonce=0, # Replacement always uses nonce 0
                price=tx_price_r,
                value=10**15 - core_config.DEFAULT_GAS_LIMIT * tx_price_r - 100,
                tx_type=2,
                max_priority_fee_per_gas=base_max_priority_fee_per_gas
            )
            new_input_r_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_r_seq.append(new_tx_r)
            mutated_inputs.append(FuzzInput(new_input_r_seq, base_input_tx_in_pool_indices))

        # --- Mutation 3: Add New Parent Transaction (P) ---
        # This is typically done if there are no parent transactions in the pool,
        # or to introduce new senders.
        if not parent_in_pool_senders: # If no parents from non-normal senders are in pool
            new_fuzzer_acc_idx_for_parent = current_fuzzer_account_index + 1
            sender_addr_p = self._get_safe_account_address(new_fuzzer_acc_idx_for_parent)
            # Use dynamic base_gas_price for new parent
            new_parent_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx_for_parent,
                sender_address=sender_addr_p,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr_p) or 0,
                price=base_gas_price, # Use current gas price as base
                value=core_config.DEFAULT_GAS_LIMIT * (12000 - base_gas_price), # Value adjusted
                tx_type=0 # Default to legacy for simplicity, or could be EIP-1559
            )
            new_input_p_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_p_seq.append(new_parent_tx)
            mutated_inputs.append(FuzzInput(new_input_p_seq, base_input_tx_in_pool_indices))
            # Note: The FuzzEngine will be responsible for updating its `current_fuzzer_account_index`
            # and the `AccountManager`'s nonces based on successful transaction submissions.

        # --- Mutation 4: Price Laddering / Re-pricing ---
        # This modifies prices of existing parent transactions and adds a new one.
        # It's about creating a new parent tx with a price that fits into a "ladder"
        # of existing parent prices, and re-pricing existing ones.

        # Extract parent transactions (nonce 0) from the base_input's tx_sequence
        base_input_parent_txs: List[FuzzTx] = [
            tx for tx in base_input.tx_sequence_to_execute if tx.nonce == 0
        ]
        # Sort them by price to establish the "ladder"
        base_input_parent_txs.sort(key=lambda tx: tx.price)
        base_input_parent_prices: List[int] = [tx.price for tx in base_input_parent_txs]

        step_length = self.price_ladder_step_length # Configurable step length

        # Apply this mutation for each parent currently in the pool
        for sender_in_pool in parent_in_pool_senders:
            sender_price_in_pool = parent_in_pool_prices[sender_in_pool]

            # Find the index of this sender's price in the sorted list of *base input* parent prices
            cur_tx_index = -1
            try:
                cur_tx_index = base_input_parent_prices.index(sender_price_in_pool)
            except ValueError:
                # This parent from the pool wasn't in the base_input's parent list.
                # This can happen if the base_input was very short or the parent was added by a previous mutation.
                # For robustness, we might skip this specific re-pricing mutation for this sender.
                continue

            # Generate a list of potential new prices for the ladder, including one extra slot
            # Use base_max_fee_per_gas as a dynamic floor for prices
            price_ladder_options = [max(base_max_fee_per_gas, self.normal_tx_price_indicator + 1) + j * step_length
                                    for j in range(len(base_input_parent_prices) + 1)]

            # The new transaction will take the price at `cur_tx_index` in the ladder.
            # The existing transactions will be re-priced using the remaining options.

            # Create a new parent transaction with a price from the ladder
            new_fuzzer_acc_idx_ladder = current_fuzzer_account_index + 1 # Use a new account index
            sender_addr_ladder = self._get_safe_account_address(new_fuzzer_acc_idx_ladder)
            new_ladder_parent_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx_ladder,
                sender_address=sender_addr_ladder,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr_ladder) or 0,
                price=price_ladder_options[cur_tx_index], # Use price from ladder
                value=core_config.DEFAULT_GAS_LIMIT * (12000 - price_ladder_options[cur_tx_index]),
                tx_type=2,
                max_priority_fee_per_gas=base_max_priority_fee_per_gas
            )

            new_input_ladder_seq = copy.deepcopy(base_input.tx_sequence_to_execute)

            # Re-price existing parent transactions in the new input sequence
            temp_price_ladder_options = list(price_ladder_options) # Make a mutable copy
            if price_ladder_options[cur_tx_index] in temp_price_ladder_options:
                temp_price_ladder_options.remove(price_ladder_options[cur_tx_index])

            for tx in new_input_ladder_seq:
                if tx.nonce == 0 and tx.price in base_input_parent_prices:
                    original_price_idx = base_input_parent_prices.index(tx.price)
                    if original_price_idx < len(temp_price_ladder_options):
                        tx.price = temp_price_ladder_options[original_price_idx]
                        tx.tx_type = 2 # Ensure re-priced txs are EIP-1559
                        tx.max_priority_fee_per_gas = base_max_priority_fee_per_gas
                    else:
                        print(f"WARN: Not enough price ladder options for re-pricing tx {tx.sender_address} N:{tx.nonce}.")

            new_input_ladder_seq.append(new_ladder_parent_tx)
            mutated_inputs.append(FuzzInput(new_input_ladder_seq, base_input_tx_in_pool_indices))

        # --- Mutation 5: Max Index Price Laddering ---
        # This adds a new parent with a price one step above the current highest price in the ladder.
        if base_input_parent_prices:
            max_base_price = max(base_input_parent_prices)
            max_price_idx = base_input_parent_prices.index(max_base_price) # Index of the max price

            new_fuzzer_acc_idx_max_ladder = current_fuzzer_account_index + 1 # Use a new account index
            sender_addr_max_ladder = self._get_safe_account_address(new_fuzzer_acc_idx_max_ladder)
            new_max_ladder_parent_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx_max_ladder,
                sender_address=sender_addr_max_ladder,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr_max_ladder) or 0,
                price=max(base_max_fee_per_gas, self.normal_tx_price_indicator + 1) + (max_price_idx + 1) * step_length,
                value=core_config.DEFAULT_GAS_LIMIT * (12000 - (max(base_max_fee_per_gas, self.normal_tx_price_indicator + 1) + (max_price_idx + 1) * step_length)),
                tx_type=2,
                max_priority_fee_per_gas=base_max_priority_fee_per_gas
            )

            new_input_max_ladder_seq = copy.deepcopy(base_input.tx_sequence_to_execute)

            # Re-price existing parent transactions in the new input sequence (similar to Mutation 4)
            price_ladder_options_for_max = [max(base_max_fee_per_gas, self.normal_tx_price_indicator + 1) + j * step_length
                                            for j in range(len(base_input_parent_prices) + 2)] # Need one more option

            temp_price_ladder_options_for_max = list(price_ladder_options_for_max)
            if new_max_ladder_parent_tx.price in temp_price_ladder_options_for_max:
                temp_price_ladder_options_for_max.remove(new_max_ladder_parent_tx.price)

            for tx in new_input_max_ladder_seq:
                if tx.nonce == 0 and tx.price in base_input_parent_prices:
                    original_price_idx = base_input_parent_prices.index(tx.price)
                    if original_price_idx < len(temp_price_ladder_options_for_max):
                        tx.price = temp_price_ladder_options_for_max[original_price_idx]
                        tx.tx_type = 2
                        tx.max_priority_fee_per_gas = base_max_priority_fee_per_gas
                    else:
                        print(f"WARN: Not enough price ladder options for re-pricing tx {tx.sender_address} N:{tx.nonce} in max ladder mutation.")

            new_input_max_ladder_seq.append(new_max_ladder_parent_tx)
            mutated_inputs.append(FuzzInput(new_input_max_ladder_seq, base_input_tx_in_pool_indices))


        # If no parents were in the pool and no base input parents, ensure at least one new parent is generated
        if not parent_in_pool_senders and not base_input_parent_txs:
            # This covers the `if len(parentInPool_price) == 0:` block in original scripts.
            # It ensures the fuzzer can always introduce a new parent if the pool is empty of them.
            new_fuzzer_acc_idx_single_parent = current_fuzzer_account_index + 1
            new_parent_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx_single_parent,
                sender_address=self.account_manager.get_account_by_index(new_fuzzer_acc_idx_single_parent),
                nonce=self.account_manager.get_fuzzer_nonce(self.account_manager.get_account_by_index(new_fuzzer_acc_idx_single_parent)) or 0,
                price=base_gas_price, # Use current gas price as base
                value=core_config.DEFAULT_GAS_LIMIT * (12000 - base_gas_price),
                tx_type=0
            )
            new_input_single_parent_seq = FuzzInput(tx_sequence_to_execute=[new_parent_tx], base_input_indices_to_resend=base_input_tx_in_pool_indices)
            mutated_inputs.append(new_input_single_parent_seq)

        return mutated_inputs
