"""
Manages Ethereum accounts, private keys, and nonces for fuzzing operations.
"""
import pandas as pd
from web3 import Web3
from typing import Dict, List, Optional

from . import config as core_config

class AccountManager:
    """
    Handles loading of Ethereum accounts from CSV files, stores private keys,
    and manages nonces for fuzzing purposes.
    """
    def __init__(self,
                 key_file_paths: Optional[List[str]] = None,
                 max_accounts_to_load: int = core_config.MAX_ACCOUNTS_TO_LOAD,
                 initial_nonce_value: int = core_config.DEFAULT_INITIAL_NONCE
                ):
        """
        Initializes the AccountManager.

        :param key_file_paths: List of paths to CSV files containing 'pub_key' and 'priv_key'.
                               If None, uses default paths from core_config.
        :param max_accounts_to_load: Maximum number of unique accounts to load.
        :param initial_nonce_value: The starting nonce for all loaded accounts.
        """
        if key_file_paths is None:
            key_file_paths = [core_config.DEFAULT_KEY_FILE_PRIMARY, core_config.DEFAULT_KEY_FILE_SECONDARY]

        self.key_storage: Dict[str, str] = {}
        self.account_addresses: List[str] = []
        self.address_to_internal_index: Dict[str, int] = {}

        self.fuzzer_nonces: Dict[str, int] = {}

        self._load_accounts_from_files(key_file_paths, max_accounts_to_load)
        self._initialize_all_fuzzer_nonces(initial_nonce_value)

    def _load_accounts_from_files(self, file_paths: List[str], limit: int):
        """Loads account public and private keys from specified CSV files."""
        print(f"INFO: AccountManager attempting to load up to {limit} accounts.")
        loaded_count = 0
        for file_path in file_paths:
            if loaded_count >= limit:
                break
            try:
                print(f"INFO: Loading keys from: {file_path}")
                key_data_frame = pd.read_csv(file_path)
                for _, row_data in key_data_frame.iterrows():
                    if loaded_count >= limit:
                        break

                    if 'pub_key' not in row_data or 'priv_key' not in row_data:
                        print(f"WARN: Skipping row in {file_path} due to missing 'pub_key' or 'priv_key'. Row: {row_data}")
                        continue

                    try:
                        address_str = Web3.to_checksum_address(row_data['pub_key'])
                        private_key_str = row_data['priv_key']
                        if not (len(private_key_str) == 64 or (private_key_str.startswith('0x') and len(private_key_str) == 66)):
                            print(f"WARN: Skipping row in {file_path} due to potentially invalid private key format for {address_str}.")
                            continue
                    except Exception as e:
                        print(f"WARN: Skipping row in {file_path} due to address/key validation error: {e}. Row: {row_data}")
                        continue

                    if address_str not in self.key_storage:
                        self.key_storage[address_str] = private_key_str
                        self.account_addresses.append(address_str)
                        self.address_to_internal_index[address_str] = loaded_count
                        loaded_count += 1
            except FileNotFoundError:
                print(f"WARN: Key file not found: {file_path}")
            except pd.errors.EmptyDataError:
                print(f"WARN: Key file is empty: {file_path}")
            except Exception as e:
                print(f"ERROR: Failed to load or parse key file {file_path}: {e}")

        if not self.account_addresses:
            print("CRITICAL: No accounts were loaded. Fuzzer may not function correctly.")
        else:
            print(f"INFO: AccountManager successfully loaded {len(self.account_addresses)} accounts.")

    def _initialize_all_fuzzer_nonces(self, nonce_val: int):
        """Sets the initial fuzzer nonce for all loaded accounts."""
        for acc_addr in self.account_addresses:
            self.fuzzer_nonces[acc_addr] = nonce_val

    def get_private_key(self, address: str) -> Optional[str]:
        """Retrieves the private key for a given checksummed account address."""
        return self.key_storage.get(address)

    def get_fuzzer_nonce(self, address: str) -> Optional[int]:
        """Gets the current fuzzer-managed nonce for a given checksummed account address."""
        return self.fuzzer_nonces.get(address)

    def set_fuzzer_nonce(self, address: str, nonce: int) -> bool:
        """
        Sets the fuzzer-managed nonce for a given checksummed account address.
        Returns True if successful, False if account is not managed.
        """
        if address in self.key_storage:
            self.fuzzer_nonces[address] = nonce
            return True
        print(f"WARN: Attempted to set nonce for unmanaged account {address}")
        return False

    def increment_fuzzer_nonce(self, address: str) -> Optional[int]:
        """
        Increments the fuzzer-managed nonce for an account and returns the new nonce.
        Returns None if the account is not managed.
        """
        if address in self.fuzzer_nonces:
            self.fuzzer_nonces[address] += 1
            return self.fuzzer_nonces[address]
        print(f"WARN: Attempted to increment nonce for unmanaged account {address}")
        return None

    def reset_all_fuzzer_nonces(self, nonce_val: Optional[int] = None):
        """Resets all fuzzer-managed nonces to a specified value, or the default initial value."""
        effective_nonce_val = nonce_val if nonce_val is not None else core_config.DEFAULT_INITIAL_NONCE
        self._initialize_all_fuzzer_nonces(effective_nonce_val)

    def get_account_by_index(self, index: int) -> Optional[str]:
        """Gets an account address by its internal load order index."""
        if 0 <= index < len(self.account_addresses):
            return self.account_addresses[index]
        return None

    def get_index_by_address(self, address: str) -> Optional[int]:
        """Gets the internal load order index of a checksummed account address."""
        return self.address_to_internal_index.get(address)

    @property
    def loaded_account_count(self) -> int:
        """Returns the number of unique accounts loaded and managed."""
        return len(self.account_addresses)

    @property
    def managed_accounts_list(self) -> List[str]:
        """Returns a copy of the list of managed account addresses."""
        return list(self.account_addresses)
