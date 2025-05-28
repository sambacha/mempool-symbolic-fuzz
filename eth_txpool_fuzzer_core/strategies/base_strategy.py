from typing import List, Dict, Any, Optional

from ..tx import FuzzInput
from ..accounts import AccountManager

class MutationStrategy:
    """
    Abstract base class for mutation strategies.
    """
    def __init__(self, account_manager: AccountManager):
        self.account_manager = account_manager

    def mutate(self,
               base_input: FuzzInput,
               current_txpool_state: Optional[Dict[str, Any]],
               current_fuzzer_account_index: int # The next index to use for new accounts
              ) -> List[FuzzInput]:
        """
        Generates a list of new FuzzInput objects by applying various mutation
        strategies to the base_input and current_txpool_state.

        :param base_input: The FuzzInput that led to the current_txpool_state.
        :param current_txpool_state: The raw txpool content to mutate from.
        :param current_fuzzer_account_index: The current global account index used by the fuzzer.
        :return: A list of new FuzzInput objects.
        """
        raise NotImplementedError("Subclasses must implement the mutate method.")
