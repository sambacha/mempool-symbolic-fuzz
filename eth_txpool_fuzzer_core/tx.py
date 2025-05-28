"""
Defines the basic data structures for transactions and fuzzing inputs.
"""
from typing import Optional, List
from web3.types import HexBytes

class Tx:
    """
    Represents a single transaction "intent" or "instruction" within the fuzzing logic.
    """
    def __init__(self,
                 account_manager_index: int,
                 sender_address: str,
                 nonce: int,
                 price: int,
                 value: int,
                 tx_type: int = 0,
                 max_priority_fee_per_gas: Optional[int] = None,
                 max_fee_per_blob_gas: Optional[int] = None,
                 blob_versioned_hashes: Optional[List[HexBytes]] = None,
                 tx_hash_on_submission: Optional[str] = None
                ):
        self.account_manager_index: int = account_manager_index
        self.sender_address: str = sender_address
        self.nonce: int = nonce
        self.price: int = price # Used as gasPrice for legacy/EIP-1559, or maxFeePerGas for EIP-4844
        self.value: int = value
        self.tx_type: int = tx_type
        self.max_priority_fee_per_gas: Optional[int] = max_priority_fee_per_gas
        self.max_fee_per_blob_gas: Optional[int] = max_fee_per_blob_gas
        self.blob_versioned_hashes: Optional[List[HexBytes]] = blob_versioned_hashes
        self.tx_hash_on_submission: Optional[str] = tx_hash_on_submission

    def __repr__(self) -> str:
        base_repr = (f"Tx(idx={self.account_manager_index}, sender='{self.sender_address[:10]}...', "
                     f"nonce={self.nonce}, value={self.value}, type={self.tx_type}")

        if self.tx_type == 3: # EIP-4844
            base_repr += (f", maxFeePerGas={self.price}, maxPriorityFeePerGas={self.max_priority_fee_per_gas}, "
                          f"maxFeePerBlobGas={self.max_fee_per_blob_gas}, blobs={len(self.blob_versioned_hashes) if self.blob_versioned_hashes else 0}")
        elif self.tx_type == 2: # EIP-1559
            base_repr += (f", maxFeePerGas={self.price}, maxPriorityFeePerGas={self.max_priority_fee_per_gas}")
        else: # Legacy or EIP-2930
            base_repr += (f", price={self.price}")

        base_repr += f", hash='{self.tx_hash_on_submission}')"
        return base_repr

class Input:
    """
    Represents a sequence of Tx objects that constitute a single fuzzing input (test case).
    It also includes indices of transactions from a previous input that need to be re-sent
    to recreate a base state, as per the original fuzzer's stateful execution model.
    """
    def __init__(self,
                 tx_sequence_to_execute: List[Tx],
                 base_input_indices_to_resend: Optional[List[int]] = None # Indices from the *previous* input to re-send
                ):
        # Add debug print to see what is passed as tx_sequence_to_execute
        print(f"DEBUG: Input.__init__ called. tx_sequence_to_execute type: {type(tx_sequence_to_execute)}, content: {tx_sequence_to_execute}")
        if not isinstance(tx_sequence_to_execute, list):
            print(f"CRITICAL ERROR: Input.__init__ received non-list for tx_sequence_to_execute: {type(tx_sequence_to_execute)}")
            # Raise an error or handle this unexpected type
            raise TypeError(f"Expected list for tx_sequence_to_execute, got {type(tx_sequence_to_execute)}")

        self.tx_sequence_to_execute: List[Tx] = tx_sequence_to_execute
        self.base_input_indices_to_resend: List[int] = base_input_indices_to_resend if base_input_indices_to_resend is not None else []

    def __repr__(self) -> str:
        return (f"Input(tx_count={len(self.tx_sequence_to_execute)}, "
                f"resend_indices_count={len(self.base_input_indices_to_resend)})")

# Type alias for clarity in other modules, if preferred
FuzzTx = Tx
FuzzInput = Input
