"""
Utility functions for generating and handling EIP-4844 blob data and hashes.
"""
import os
from typing import List
from web3 import Web3
from web3.types import HexBytes

def generate_dummy_blob_data(num_blobs: int, blob_size: int = 131072) -> List[bytes]:
    """
    Generates a list of dummy blob data (each 128KB) for testing purposes.
    Each blob is filled with random bytes.

    :param num_blobs: The number of blobs to generate.
    :param blob_size: The size of each blob in bytes (default 128KB).
    :return: A list of bytes objects, each representing a blob.
    """
    if num_blobs <= 0:
        return []

    dummy_blobs = []
    for _ in range(num_blobs):
        dummy_blobs.append(os.urandom(blob_size))
    return dummy_blobs

def generate_blob_versioned_hashes(w3_instance: Web3, blob_data: List[bytes]) -> List[HexBytes]:
    """
    Computes the blob versioned hashes (KZG commitments) for a list of raw blob data
    using a provided Web3 instance.

    :param w3_instance: The Web3 instance to use for KZG operations.
    :param blob_data: A list of raw blob data as bytes objects.
    :return: A list of HexBytes objects, each representing a blob versioned hash.
    """
    if not blob_data:
        return []

    versioned_hashes = []
    for blob in blob_data:
        try:
            versioned_hashes.append(w3_instance.to_blob_versioned_hash(blob))
        except Exception as e:
            print(f"ERROR: Failed to generate blob versioned hash for a blob: {e}")
            return []
    return versioned_hashes
