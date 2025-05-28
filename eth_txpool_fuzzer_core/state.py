# eth_txpool_fuzzer_core/state.py
"""
Functions for analyzing and symbolizing the state of the Ethereum transaction pool.
Includes logic for calculating "energy" of a state to guide fuzzing.
"""

from typing import Dict, Any, List

from . import config as core_config

# TODO: Set up a proper logger for this module
# import logging
# logger = logging.getLogger(__name__)

class SenderTxSummary:
    """Helper class to store summary info about a sender's first pending transaction."""
    def __init__(self, sender_address: str, first_tx_price: int, tx_count: int):
        self.sender_address: str = sender_address
        self.first_tx_price: int = first_tx_price
        self.tx_count: int = tx_count # Total pending txs for this sender

    def __lt__(self, other: 'SenderTxSummary') -> bool:
        # For sorting senders primarily by the gas price of their first transaction.
        return self.first_tx_price < other.first_tx_price

def get_symbolic_pool_state(
    txpool_content: Dict[str, Any],
    txpool_size_config: int = core_config.DEFAULT_TXPOOL_SIZE,
    normal_tx_price_indicator: int = core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
    parent_replacement_price_threshold: int = core_config.STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD,
    child_value_threshold: int = core_config.STATE_CHILD_VALUE_THRESHOLD
) -> str:
    """
    Generates a symbolic string representation of the transaction pool state.
    The order of symbols is E (Empty), F (Future), N (Normal), then P/R/C/O for others.

    Symbol Legend:
    - 'E': Empty slot in the pool (calculated based on txpool_size_config)
    - 'F': Future-queued transaction (in 'queued' part of txpool content)
    - 'N': Normal base transaction (e.g., from initial pool setup)
    - 'P': Parent transaction (first tx from a sender, not high-priced like 'R')
    - 'R': Replacement parent transaction (high-priced first tx from a sender)
    - 'C': Child transaction (low value, depends on a 'P' or 'R')
    - 'O': Other/Override child transaction (high value, or child of an 'R' parent)
    - 'B': Valid EIP-4844 Blob transaction
    - 'I': Invalid EIP-4844 Blob transaction (e.g., malformed, too many blobs)
    """
    pending_txs: Dict[str, Dict[str, Any]] = txpool_content.get('pending', {})
    queued_txs: Dict[str, Dict[str, Any]] = txpool_content.get('queued', {})

    future_tx_count = 0
    for sender_queued_txs in queued_txs.values():
        # Check if the queued transaction is a future transaction (nonce 10000)
        # or if it's a blob transaction. For now, 'F' is only for nonce 10000.
        for nonce_str in sender_queued_txs:
            tx_details = sender_queued_txs[nonce_str]
            tx_type = int(tx_details.get('type', '0'), 16) if 'type' in tx_details else 0
            if int(nonce_str) == 10000 and tx_type != 3: # 'F' is for non-blob future txs
                future_tx_count += 1

    normal_sender_tx_count = 0  # Total count of txs from "normal" senders

    # List to hold summaries for senders whose first tx is not "normal"
    non_normal_sender_summaries: List[SenderTxSummary] = []

    total_pending_tx_count = 0
    blob_tx_count = 0 # Count of valid blob transactions
    invalid_blob_tx_count = 0 # Count of invalid blob transactions

    for sender_addr, txs_by_nonce_str in pending_txs.items():
        if not txs_by_nonce_str:
            continue

        total_pending_tx_count += len(txs_by_nonce_str)

        # Nonces are strings in txpool_content, convert to int for sorting
        sorted_nonce_keys = sorted(txs_by_nonce_str.keys(), key=int)

        first_tx_details = txs_by_nonce_str[sorted_nonce_keys[0]]

        try:
            tx_type = int(first_tx_details.get('type', '0'), 16) if 'type' in first_tx_details else 0
            # Gas price is hex string in txpool_content
            first_tx_gas_price = int(first_tx_details.get('gasPrice', '0'), 16) if 'gasPrice' in first_tx_details else 0
            # For EIP-1559/4844, use maxFeePerGas
            if tx_type in [2, 3]:
                first_tx_gas_price = int(first_tx_details.get('maxFeePerGas', '0'), 16) if 'maxFeePerGas' in first_tx_details else 0
        except ValueError:
            print(f"WARN: Malformed tx details for sender {sender_addr}, first tx. Skipping for symbolization.")
            continue # Skip this sender if details are malformed

        if tx_type == 3: # EIP-4844 Blob Transaction
            # Check for validity of blob transaction for 'B' vs 'I'
            # This is a simplified check; a real client would do more.
            # We'll check if blobVersionedHashes is present and not empty.
            blob_hashes = first_tx_details.get('blobVersionedHashes')
            if blob_hashes and isinstance(blob_hashes, list) and len(blob_hashes) > 0:
                blob_tx_count += len(txs_by_nonce_str)
            else:
                invalid_blob_tx_count += len(txs_by_nonce_str)
            continue # Blob transactions are handled separately, not as N/P/R/C/O

        if first_tx_gas_price == normal_tx_price_indicator:
            normal_sender_tx_count += len(txs_by_nonce_str)
        else:
            non_normal_sender_summaries.append(
                SenderTxSummary(sender_addr, first_tx_gas_price, len(txs_by_nonce_str))
            )

    # Sort non-normal senders by their first transaction's gas price
    non_normal_sender_summaries.sort()

    # Build the symbolic string parts
    symbolic_parts: List[str] = []

    # Add 'N's for all transactions from normal senders
    symbolic_parts.extend(['N'] * normal_sender_tx_count)

    # Add symbols for non-normal senders (P/R/C/O)
    for sender_summary in non_normal_sender_summaries:
        sender_addr = sender_summary.sender_address
        sender_pending_txs = pending_txs.get(sender_addr, {})
        sorted_nonce_keys = sorted(sender_pending_txs.keys(), key=int)

        is_high_price_parent_chain = False # True if the first tx of this sender was 'R'

        for i, nonce_str_key in enumerate(sorted_nonce_keys):
            tx_details = sender_pending_txs[nonce_str_key]

            try:
                tx_value = int(tx_details.get('value', '0'), 16)
                tx_gas_price = int(tx_details.get('gasPrice', '0'), 16)
                tx_type = int(tx_details.get('type', '0'), 16) if 'type' in tx_details else 0
                if tx_type in [2, 3]: # For EIP-1559/4844, use maxFeePerGas
                    tx_gas_price = int(tx_details.get('maxFeePerGas', '0'), 16) if 'maxFeePerGas' in tx_details else 0
            except ValueError:
                print(f"WARN: Malformed value/gasPrice/type for tx {sender_addr} N:{nonce_str_key}. Symbolizing as 'O'.")
                symbolic_parts.append('O')
                continue

            if tx_type == 3: # Should have been caught earlier, but as a safeguard
                # This means a blob tx was somehow in non_normal_sender_summaries
                # which should not happen if the initial filtering is correct.
                # For robustness, symbolize as 'B' or 'I' here too.
                blob_hashes = tx_details.get('blobVersionedHashes')
                if blob_hashes and isinstance(blob_hashes, list) and len(blob_hashes) > 0:
                    symbolic_parts.append('B')
                else:
                    symbolic_parts.append('I')
                continue

            if i == 0: # First transaction from this (non-normal) sender
                if tx_gas_price >= parent_replacement_price_threshold:
                    symbolic_parts.append('R')
                    is_high_price_parent_chain = True
                else:
                    symbolic_parts.append('P')
                    is_high_price_parent_chain = False
            else: # Subsequent (child) transaction
                if is_high_price_parent_chain or tx_value > child_value_threshold:
                    symbolic_parts.append('O')
                else:
                    symbolic_parts.append('C')

    # Calculate empty slots
    # total_txs_in_pool = future_tx_count + normal_sender_tx_count + sum(s.tx_count for s in non_normal_sender_summaries)
    # The sum of tx_count from non_normal_sender_summaries is total_pending_tx_count - normal_sender_tx_count
    total_txs_in_pool = future_tx_count + total_pending_tx_count + blob_tx_count + invalid_blob_tx_count
    empty_slot_count = max(0, txpool_size_config - total_txs_in_pool)

    # Final symbolic string construction: E, F, B, I, then sorted N/P/R/C/O
    final_symbol_list: List[str] = ['E'] * empty_slot_count
    final_symbol_list.extend(['F'] * future_tx_count)
    final_symbol_list.extend(['B'] * blob_tx_count)
    final_symbol_list.extend(['I'] * invalid_blob_tx_count)
    final_symbol_list.extend(symbolic_parts) # Contains 'N's then sorted 'P/R/C/O's

    return "".join(final_symbol_list)


def get_txpool_energy(
    txpool_content: Dict[str, Any],
    normal_tx_price_indicator: int = core_config.STATE_NORMAL_TX_PRICE_INDICATOR,
    child_value_threshold: int = core_config.STATE_CHILD_VALUE_THRESHOLD
) -> int:
    """
    Calculates an 'energy' score for the current txpool state.
    Lower energy is generally preferred by the fuzzer.
    Based on `getOutputEngergy` from original scripts, extended for blob transactions.
    """
    pending_txs: Dict[str, Dict[str, Any]] = txpool_content.get('pending', {})
    energy = 0
    non_normal_parent_count = 0 # Count of senders whose first tx is not "normal"
    blob_tx_count = 0
    invalid_blob_tx_count = 0

    for sender_addr, txs_by_nonce_str in pending_txs.items():
        if not txs_by_nonce_str:
            continue

        sorted_nonce_keys = sorted(txs_by_nonce_str.keys(), key=int)
        first_tx_details = txs_by_nonce_str[sorted_nonce_keys[0]]

        try:
            tx_type = int(first_tx_details.get('type', '0'), 16) if 'type' in first_tx_details else 0
            first_tx_gas_price = int(first_tx_details.get('gasPrice', '0'), 16) if 'gasPrice' in first_tx_details else 0
            if tx_type in [2, 3]: # For EIP-1559/4844, use maxFeePerGas
                first_tx_gas_price = int(first_tx_details.get('maxFeePerGas', '0'), 16) if 'maxFeePerGas' in first_tx_details else 0

            # Check for blob-specific fields
            if tx_type == 3:
                blob_hashes = first_tx_details.get('blobVersionedHashes')
                if blob_hashes and isinstance(blob_hashes, list) and len(blob_hashes) > 0:
                    blob_tx_count += len(txs_by_nonce_str)
                    # Add energy based on blob gas price, e.g., higher energy for very low/high prices
                    max_fee_per_blob_gas = int(first_tx_details.get('maxFeePerBlobGas', '0'), 16) if 'maxFeePerBlobGas' in first_tx_details else 0
                    if max_fee_per_blob_gas < 10 or max_fee_per_blob_gas > 1000: # Example thresholds
                        energy += 5 # Boost energy for interesting blob gas prices
                else:
                    invalid_blob_tx_count += len(txs_by_nonce_str)
                    energy += 10 # High energy for invalid blob transactions
                continue # Blob transactions are handled, skip traditional energy calculation for this sender

        except ValueError:
            print(f"WARN: Malformed tx details for energy calc on sender {sender_addr}. Treating as non-normal.")
            first_tx_gas_price = normal_tx_price_indicator + 1

        if first_tx_gas_price != normal_tx_price_indicator:
            non_normal_parent_count += 1
            for nonce_key in sorted_nonce_keys:
                tx_details = txs_by_nonce_str[nonce_key]
                try:
                    tx_value = int(tx_details.get('value', '0'), 16)
                except ValueError:
                    print(f"WARN: Malformed value for energy calc on tx {sender_addr} N:{nonce_key}. Treating as high value.")
                    tx_value = child_value_threshold + 1

                if tx_value > child_value_threshold: # High value "O" type txs
                    continue # Does not add to this part of energy
                else: # Low value "C" type txs or "P"/"R" parents themselves
                    energy += 1
        else: # This sender's sequence starts with a "normal" priced transaction
            # Original scripts add 3 per normal tx in the sequence
            energy += (3 * len(txs_by_nonce_str))

    # Bonus energy based on the number of non_normal_parent_count
    # Original: for i in range(attack_parent): energy += (4 + i)
    for i in range(non_normal_parent_count):
        energy += (4 + i)

    # Additional energy for blob transactions (can be adjusted)
    energy += blob_tx_count * 2 # Small energy for valid blobs
    energy += invalid_blob_tx_count * 15 # Higher energy for invalid blobs

    return energy

def get_total_pending_tx_count(txpool_content: Dict[str, Any]) -> int:
    """Calculates the total number of transactions in the 'pending' part of the txpool."""
    pending_txs: Dict[str, Dict[str, Any]] = txpool_content.get('pending', {})
    count = 0
    for sender_txs_map in pending_txs.values():
        count += len(sender_txs_map)
    return count
