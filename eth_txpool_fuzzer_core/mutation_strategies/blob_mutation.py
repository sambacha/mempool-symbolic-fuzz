#!/usr/bin/env python3

"""
Defines mutation strategies specifically for EIP-4844 blob transactions.

eth_txpool_fuzzer_core/mutation_strategies/blob_mutation.py

"""
import copy
import random
from typing import List, Dict, Any, Optional

from eth_txpool_fuzzer_core.tx import FuzzTx, FuzzInput
from eth_txpool_fuzzer_core.accounts import AccountManager
from eth_txpool_fuzzer_core.strategies.base_strategy import MutationStrategy # Import base class from new location
from eth_txpool_fuzzer_core.blob_utils import generate_dummy_blob_data, generate_blob_versioned_hashes
from eth_txpool_fuzzer_core.client_comms import EthereumClient #


class BlobTxMutationStrategy(MutationStrategy):
    """
    Generates new FuzzInput objects containing EIP-4844 blob transactions.
    """
    def __init__(self,
                 account_manager: AccountManager,
                 ethereum_client: EthereumClient, # Add ethereum_client to constructor
                 max_blobs_per_tx: int = 2, # Max blobs to attach to a single transaction
                 min_blob_gas_price: int = 1,
                 max_blob_gas_price: int = 1000,
                 default_recipient_address: Optional[str] = None
                ):
        super().__init__(account_manager)
        self.ethereum_client = ethereum_client # Store the client instance
        self.max_blobs_per_tx = max_blobs_per_tx
        self.min_blob_gas_price = min_blob_gas_price
        self.max_blob_gas_price = max_blob_gas_price
        self.default_recipient_address = default_recipient_address or self.account_manager.get_account_by_index(0)
        if self.default_recipient_address is None:
            print("CRITICAL: BlobTxMutationStrategy initialized without a valid default recipient address.")

    def mutate(self,
               base_input: FuzzInput,
               current_txpool_state: Optional[Dict[str, Any]],
               current_fuzzer_account_index: int # The next index to use for new accounts
              ) -> List[FuzzInput]:
        """
        Generates a list of new FuzzInput objects by applying blob-specific mutations.
        """
        mutated_inputs: List[FuzzInput] = []

        # Determine which transactions from the base_input are still in the pool
        # This is needed to recreate the base state for new mutations.
        base_input_tx_in_pool_indices: List[int] = []
        if current_txpool_state:
            all_tx_in_pool_details: List[Any] = [] # (sender, nonce, value, type)
            pending_txs = current_txpool_state.get('pending', {})
            queued_txs = current_txpool_state.get('queued', {})

            for sender, txs_by_nonce_str in pending_txs.items():
                for nonce_str in sorted(txs_by_nonce_str.keys(), key=int):
                    tx_details = txs_by_nonce_str[nonce_str]
                    try:
                        all_tx_in_pool_details.append((sender, int(nonce_str), int(tx_details.get('value', '0'), 16), int(tx_details.get('type', '0'), 16)))
                    except ValueError:
                        pass # Malformed tx, skip

            for sender, txs_by_nonce_str in queued_txs.items():
                for nonce_str in sorted(txs_by_nonce_str.keys(), key=int):
                    tx_details = txs_by_nonce_str[nonce_str]
                    try:
                        all_tx_in_pool_details.append((sender, int(nonce_str), int(tx_details.get('value', '0'), 16), int(tx_details.get('type', '0'), 16)))
                    except ValueError:
                        pass # Malformed tx, skip

            for i, base_tx in enumerate(base_input.tx_sequence_to_execute):
                if any(t[0] == base_tx.sender_address and t[1] == base_tx.nonce and t[2] == base_tx.value and t[3] == base_tx.tx_type
                       for t in all_tx_in_pool_details):
                    base_input_tx_in_pool_indices.append(i)

        # Mutation 1: Add a new valid blob transaction
        # Use a new account for this new transaction
        new_fuzzer_acc_idx = current_fuzzer_account_index + 1
        sender_addr = self.account_manager.get_account_by_index(new_fuzzer_acc_idx)
        if sender_addr is None:
            print("WARN: Not enough accounts for new blob tx. Skipping new blob tx mutation.")
            return mutated_inputs # Cannot generate new blob tx without an account

        # Fetch current gas prices from the client
        current_gas_prices = self.ethereum_client.get_current_gas_prices()
        base_max_fee_per_gas = current_gas_prices.get('maxFeePerGas', 0)
        base_max_priority_fee_per_gas = current_gas_prices.get('maxPriorityFeePerGas', 0)
        base_max_fee_per_blob_gas = current_gas_prices.get('maxFeePerBlobGas', 0)

        # Generate dummy blob data and hashes
        num_blobs = random.randint(1, self.max_blobs_per_tx)
        dummy_blobs = generate_dummy_blob_data(num_blobs)
        # Pass the web3 instance from ethereum_client
        blob_hashes = generate_blob_versioned_hashes(self.ethereum_client.w3, dummy_blobs)

        if not blob_hashes:
            print("WARN: Failed to generate blob hashes. Skipping new blob tx mutation.")
            return mutated_inputs # Cannot create blob tx without hashes

        # Randomize blob gas price around the fetched base_max_fee_per_blob_gas
        # Ensure it's at least min_blob_gas_price
        blob_gas_price = max(self.min_blob_gas_price, random.randint(base_max_fee_per_blob_gas // 2, base_max_fee_per_blob_gas * 2))

        # For EIP-4844, 'price' in FuzzTx maps to 'maxFeePerGas'
        # 'max_priority_fee_per_gas' can be a small default or randomized
        new_blob_tx = FuzzTx(
            account_manager_index=new_fuzzer_acc_idx,
            sender_address=sender_addr,
            nonce=self.account_manager.get_fuzzer_nonce(sender_addr) or 0,
            price=max(base_max_fee_per_gas, random.randint(1, 100)), # maxFeePerGas
            value=0, # Typically 0 for blob transactions
            tx_type=3, # EIP-4844
            max_priority_fee_per_gas=max(base_max_priority_fee_per_gas, random.randint(1, 50)),
            max_fee_per_blob_gas=blob_gas_price,
            blob_versioned_hashes=blob_hashes
        )
        new_input_blob_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
        new_input_blob_seq.append(new_blob_tx)
        mutated_inputs.append(FuzzInput(new_input_blob_seq, base_input_tx_in_pool_indices))

        # Mutation 2: Add a blob transaction with very low/high blob gas price
        if sender_addr: # Ensure sender_addr is valid from previous check
            # Low blob gas price (ensure it's not zero, but very low)
            low_blob_gas_price = max(1, self.min_blob_gas_price)
            low_blob_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx,
                sender_address=sender_addr,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr) or 0,
                price=max(base_max_fee_per_gas, random.randint(1, 100)),
                value=0,
                tx_type=3,
                max_priority_fee_per_gas=max(base_max_priority_fee_per_gas, random.randint(1, 50)),
                max_fee_per_blob_gas=low_blob_gas_price,
                blob_versioned_hashes=blob_hashes
            )
            new_input_low_blob_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_low_blob_seq.append(low_blob_tx)
            mutated_inputs.append(FuzzInput(new_input_low_blob_seq, base_input_tx_in_pool_indices))

            # High blob gas price
            high_blob_gas_price = self.max_blob_gas_price
            high_blob_tx = FuzzTx(
                account_manager_index=new_fuzzer_acc_idx,
                sender_address=sender_addr,
                nonce=self.account_manager.get_fuzzer_nonce(sender_addr) or 0,
                price=max(base_max_fee_per_gas, random.randint(1, 100)),
                value=0,
                tx_type=3,
                max_priority_fee_per_gas=max(base_max_priority_fee_per_gas, random.randint(1, 50)),
                max_fee_per_blob_gas=high_blob_gas_price,
                blob_versioned_hashes=blob_hashes
            )
            new_input_high_blob_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
            new_input_high_blob_seq.append(high_blob_tx)
            mutated_inputs.append(FuzzInput(new_input_high_blob_seq, base_input_tx_in_pool_indices))

        # Mutation 3: Add a blob transaction with an "invalid" number of blob hashes
        # This might require a client that accepts such a transaction into the pool
        # but then rejects it later, or immediately rejects it.
        # For now, we'll generate a mismatch between dummy_blobs and blob_hashes.
        if sender_addr:
            invalid_num_blobs = num_blobs + 1 # One more hash than actual blobs
            dummy_blobs_for_invalid = generate_dummy_blob_data(num_blobs) # Actual blobs
            # Manually create an "invalid" list of hashes (e.g., by duplicating one)
            invalid_blob_hashes = generate_blob_versioned_hashes(self.ethereum_client.w3, dummy_blobs_for_invalid)
            if invalid_blob_hashes:
                invalid_blob_hashes.append(invalid_blob_hashes[0]) # Duplicate a hash to make count mismatch

                invalid_blob_tx = FuzzTx(
                    account_manager_index=new_fuzzer_acc_idx,
                    sender_address=sender_addr,
                    nonce=self.account_manager.get_fuzzer_nonce(sender_addr) or 0,
                    price=max(base_max_fee_per_gas, random.randint(1, 100)),
                    value=0,
                    tx_type=3,
                    max_priority_fee_per_gas=max(base_max_priority_fee_per_gas, random.randint(1, 50)),
                    max_fee_per_blob_gas=blob_gas_price,
                    blob_versioned_hashes=invalid_blob_hashes # This is the "invalid" part
                )
                new_input_invalid_blob_seq = copy.deepcopy(base_input.tx_sequence_to_execute)
                new_input_invalid_blob_seq.append(invalid_blob_tx)
                mutated_inputs.append(FuzzInput(new_input_invalid_blob_seq, base_input_tx_in_pool_indices))

        return mutated_inputs
