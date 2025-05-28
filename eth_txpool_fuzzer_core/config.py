# eth_txpool_fuzzer_core/config.py
"""
Default configuration values for the Ethereum TxPool Fuzzer Core library.
These can be overridden by scenario-specific configurations.
"""

# --- Client Communication ---
DEFAULT_TARGET_URL: str = "http://127.0.0.1:18546" # Default RPC endpoint for the Ethereum client
DEFAULT_CHAIN_ID: int = 20191003 # Chain ID for transactions (from original scripts)
DEFAULT_GAS_LIMIT: int = 21000   # Default gas limit for simple transfers

# --- TxPool Fuzzing Parameters ---
DEFAULT_TXPOOL_SIZE: int = 4      # Default assumed size of the transaction pool's pending slots
DEFAULT_FUTURE_SLOTS: int = 1     # Default assumed number of future (queued) slots per account or globally
                                  # Note: Original scripts had txpool_size = 4, 6, or 16 and future_slots = 1, 2, or 4.
                                  # These should be configurable per scenario.

# --- Account Management ---
DEFAULT_KEY_FILE_PRIMARY: str = './key_prive2.csv'    # Primary CSV file for private keys
DEFAULT_KEY_FILE_SECONDARY: str = './key_prive.csv'  # Secondary CSV file, loaded if primary doesn't meet needs
DEFAULT_INITIAL_NONCE: int = 0                       # Default starting nonce for accounts in fuzzing
MAX_ACCOUNTS_TO_LOAD: int = 100                      # Safety limit for the number of accounts to load

# --- State Symbolization & Energy Calculation ---
# These are default thresholds for get_symbolic_pool_state and get_txpool_energy
# They might be overridden by specific ExploitCondition classes or FuzzEngine configurations.
STATE_NORMAL_TX_PRICE_INDICATOR: int = 3
STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD: int = 12000
STATE_CHILD_VALUE_THRESHOLD: int = 10000 # Value (in Wei, usually) to distinguish 'C' from 'O'

# --- Visualization (Graphviz) ---
DEFAULT_GRAPHVIZ_FILENAME: str = 'txpool_fuzz_graph'
DEFAULT_GRAPHVIZ_VIEW_ON_COMPLETE: bool = True # Whether to automatically open the graphviz output

# --- Fuzzing Engine Loop ---
DEFAULT_MAX_FUZZ_ITERATIONS: int = 1000 # Default max iterations for the main fuzzing loop
DEFAULT_TIMEOUT_PER_ITERATION_SECONDS: float = 5.0 # Timeout for a single fuzzing step (e.g., RPC call)
DEFAULT_GLOBAL_FUZZ_TIMEOUT_SECONDS: float = 3600.0 # 1 hour global timeout for a fuzzing campaign

# --- Logging ---
# Placeholder for logging configuration, e.g., log level, log file path
LOG_LEVEL: str = "INFO"
LOG_TO_FILE: bool = False
LOG_FILE_PATH: str = "fuzzer.log"
