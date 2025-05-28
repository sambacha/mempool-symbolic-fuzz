import pytest
from unittest.mock import Mock, patch
from eth_txpool_fuzzer_core.fuzz_engine import FuzzEngine
from eth_txpool_fuzzer_core.tx import FuzzInput, FuzzTx
from eth_txpool_fuzzer_core.accounts import AccountManager
from eth_txpool_fuzzer_core.client_comms import EthereumClient
from eth_txpool_fuzzer_core.mutation import MutationStrategy
from eth_txpool_fuzzer_core.exploit_detectors import ExploitCondition
from hypothesis import given, strategies as st, settings, HealthCheck

@pytest.fixture
def mock_account_manager():
    """Fixture for a mocked AccountManager."""
    mock_am = Mock(spec=AccountManager)
    mock_am.get_account_by_index.side_effect = lambda i: f"0xAccount{i}"
    mock_am.get_fuzzer_nonce.return_value = 0
    mock_am.increment_fuzzer_nonce.return_value = None
    return mock_am

@pytest.fixture
def mock_ethereum_client():
    """Fixture for a mocked EthereumClient."""
    mock_ec = Mock(spec=EthereumClient)
    mock_ec.clear_txpool_custom.return_value = True
    mock_ec.get_current_gas_prices.return_value = {
        'maxFeePerGas': 100,
        'maxPriorityFeePerGas': 10,
        'gasPrice': 50, # For legacy transactions, though we're focusing on EIP-1559
        'maxFeePerBlobGas': 1
    }
    mock_ec.sign_and_send_transfer.return_value = "0xmockhash"
    mock_ec.get_txpool_content.return_value = {} # Empty pool for most tests
    return mock_ec

@pytest.fixture
def mock_mutation_strategy():
    """Fixture for a mocked MutationStrategy."""
    mock_ms = Mock(spec=MutationStrategy)
    mock_ms.mutate.return_value = [] # By default, no mutations
    return mock_ms

@pytest.fixture
def mock_exploit_condition():
    """Fixture for a mocked ExploitCondition."""
    mock_ec = Mock(spec=ExploitCondition)
    mock_ec.check_condition.return_value = False # By default, no exploit
    return mock_ec

@pytest.fixture
def fuzz_engine(mock_account_manager, mock_ethereum_client, mock_mutation_strategy, mock_exploit_condition):
    """Fixture for a FuzzEngine instance with mocked dependencies."""
    return FuzzEngine(
        account_manager=mock_account_manager,
        ethereum_client=mock_ethereum_client,
        mutation_strategy=mock_mutation_strategy,
        exploit_condition=mock_exploit_condition,
        default_recipient_address="0xDefaultRecipient"
    )

class TestFuzzEngine:
    @given(
        account_index=st.integers(min_value=0, max_value=5),
        max_fee_per_gas=st.integers(min_value=1, max_value=1000),
        max_priority_fee_per_gas=st.integers(min_value=1, max_value=100)
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_generate_future_tx_eip1559(self, fuzz_engine, mock_account_manager, account_index, max_fee_per_gas, max_priority_fee_per_gas):
        """
        Test _generate_future_tx method to ensure it creates EIP-1559 transactions
        with correct dynamic gas prices and future-specific attributes.
        """
        gas_prices = {
            'maxFeePerGas': max_fee_per_gas,
            'maxPriorityFeePerGas': max_priority_fee_per_gas,
            'gasPrice': 50,
            'maxFeePerBlobGas': 1
        }

        # Ensure get_account_by_index is called with the correct index
        mock_account_manager.get_account_by_index.return_value = f"0xAccount{account_index}"

        future_tx = fuzz_engine._generate_future_tx(account_index, gas_prices)

        assert isinstance(future_tx, FuzzTx)
        assert future_tx.account_manager_index == account_index
        assert future_tx.sender_address == f"0xAccount{account_index}"
        assert future_tx.nonce == 10000 # Future transaction specific nonce
        assert future_tx.tx_type == 2 # EIP-1559 transaction type
        assert future_tx.price == max_fee_per_gas # For EIP-1559, 'price' is maxFeePerGas
        assert future_tx.max_priority_fee_per_gas == max_priority_fee_per_gas
        assert future_tx.value == 2 # Future transaction specific value

        mock_account_manager.get_account_by_index.assert_called_with(account_index)

    def test_generate_future_tx_account_out_of_bounds(self, fuzz_engine, mock_account_manager, capsys):
        """
        Test _generate_future_tx when the provided account index is out of bounds,
        it should fall back to account 0 and log a warning.
        """
        mock_account_manager.get_account_by_index.side_effect = [None, "0xAccount0"] # First call returns None, second returns 0xAccount0
        gas_prices = {'maxFeePerGas': 100, 'maxPriorityFeePerGas': 10, 'gasPrice': 50, 'maxFeePerBlobGas': 1}

        future_tx = fuzz_engine._generate_future_tx(999, gas_prices) # Use an out-of-bounds index

        assert isinstance(future_tx, FuzzTx)
        assert future_tx.sender_address == "0xAccount0" # Should fall back to account 0
        mock_account_manager.get_account_by_index.assert_any_call(999)
        mock_account_manager.get_account_by_index.assert_any_call(0)

        captured = capsys.readouterr()
        assert "WARN: Fuzzer account index 999 out of bounds. Using account 0 for future tx." in captured.out

    @given(
        price=st.integers(min_value=1, max_value=1000),
        account_index=st.integers(min_value=0, max_value=5)
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_generate_parent_tx(self, fuzz_engine, mock_account_manager, price, account_index):
        """
        Test _generate_parent_tx method to ensure it creates transactions
        with correct attributes for parent transactions.
        """
        mock_account_manager.get_account_by_index.return_value = f"0xAccount{account_index}"
        mock_account_manager.get_fuzzer_nonce.return_value = 5 # Simulate a current nonce

        parent_tx = fuzz_engine._generate_parent_tx(account_index, price)

        assert isinstance(parent_tx, FuzzTx)
        assert parent_tx.account_manager_index == account_index
        assert parent_tx.sender_address == f"0xAccount{account_index}"
        assert parent_tx.nonce == 5 # Should use the nonce from account manager
        assert parent_tx.price == price
        assert parent_tx.value == 21000 * (12000 - price) # Value calculation based on core_config.DEFAULT_GAS_LIMIT * (12000 - price)
        # Note: DEFAULT_GAS_LIMIT is 21000 from core_config.py, which is not mocked here.
        # This test assumes core_config.DEFAULT_GAS_LIMIT is 21000.

        mock_account_manager.get_account_by_index.assert_called_with(account_index)
        mock_account_manager.get_fuzzer_nonce.assert_called_with(f"0xAccount{account_index}")

    def test_generate_parent_tx_account_out_of_bounds(self, fuzz_engine, mock_account_manager, capsys):
        """
        Test _generate_parent_tx when the provided account index is out of bounds,
        it should fall back to account 0 and log a warning.
        """
        mock_account_manager.get_account_by_index.side_effect = [None, "0xAccount0"]
        mock_account_manager.get_fuzzer_nonce.return_value = 0 # Default nonce for fallback account

        parent_tx = fuzz_engine._generate_parent_tx(999, 100) # Use an out-of-bounds index

        assert isinstance(parent_tx, FuzzTx)
        assert parent_tx.sender_address == "0xAccount0"
        mock_account_manager.get_account_by_index.assert_any_call(999)
        mock_account_manager.get_account_by_index.assert_any_call(0)

        captured = capsys.readouterr()
        assert "WARN: Fuzzer account index 999 out of bounds. Using account 0 for parent tx." in captured.out

    def test_generate_parent_tx_nonce_none(self, fuzz_engine, mock_account_manager, capsys):
        """
        Test _generate_parent_tx when get_fuzzer_nonce returns None,
        it should fall back to nonce 0 and log a warning.
        """
        mock_account_manager.get_account_by_index.return_value = "0xAccount0"
        mock_account_manager.get_fuzzer_nonce.return_value = None # Simulate nonce not found

        parent_tx = fuzz_engine._generate_parent_tx(0, 100)

        assert isinstance(parent_tx, FuzzTx)
        assert parent_tx.nonce == 0 # Should fall back to nonce 0

        captured = capsys.readouterr()
        assert "WARN: Could not get fuzzer nonce for 0xAccount0. Using 0." in captured.out

    def test_fuzz_tx_sender_address_not_none_after_fallback(self, fuzz_engine, mock_account_manager):
        """
        Test that FuzzTx objects created via mutation strategies always have a non-None sender_address,
        even if the initial account lookup fails and a fallback is used.
        """
        # Simulate get_account_by_index returning None for index 100, then "0xAccount0" for index 0
        mock_account_manager.get_account_by_index.side_effect = [None, "0xAccount0"]

        # Call a method that generates a FuzzTx and uses _get_safe_account_address
        # We'll use _generate_future_tx as an example
        tx = fuzz_engine._generate_future_tx(100, {'maxFeePerGas': 100, 'maxPriorityFeePerGas': 10, 'gasPrice': 50, 'maxFeePerBlobGas': 1})

        assert tx.sender_address is not None
        assert isinstance(tx.sender_address, str)
        assert tx.sender_address == "0xAccount0" # Should have fallen back to account 0

        # Verify that get_account_by_index was called for the original index and then for the fallback index
        mock_account_manager.get_account_by_index.assert_any_call(100)
        mock_account_manager.get_account_by_index.assert_any_call(0)

    @patch('eth_txpool_fuzzer_core.fuzz_engine.time.sleep', return_value=None)
    def test_reset_and_initial_pool_setup_success(self, mock_sleep, fuzz_engine, mock_ethereum_client, mock_account_manager):
        """
        Test _reset_and_initial_pool_setup for successful clearing and initial transaction sending.
        """
        fuzz_engine.initial_normal_tx_count = 2
        fuzz_engine.txpool_size = 2 # Ensure enough accounts are available

        fuzz_engine._reset_and_initial_pool_setup()

        mock_ethereum_client.clear_txpool_custom.assert_called_once()
        mock_account_manager.reset_all_fuzzer_nonces.assert_called_once()
        mock_ethereum_client.get_current_gas_prices.assert_called_once()
        assert mock_ethereum_client.sign_and_send_transfer.call_count == 2 # Two initial normal txs
        assert mock_account_manager.increment_fuzzer_nonce.call_count == 2

    @patch('eth_txpool_fuzzer_core.fuzz_engine.time.sleep', return_value=None)
    def test_reset_and_initial_pool_setup_future_tx_enabled(self, mock_sleep, fuzz_engine, mock_ethereum_client, mock_account_manager):
        """
        Test _reset_and_initial_pool_setup when future transactions are enabled.
        """
        fuzz_engine.initial_normal_tx_count = 1
        fuzz_engine.future_flag_enabled = True
        fuzz_engine.future_slots = 1
        fuzz_engine.txpool_size = 1 # Ensure enough accounts are available

        # Mock _generate_future_tx to return a dummy FuzzTx
        with patch.object(fuzz_engine, '_generate_future_tx', return_value=Mock(spec=FuzzTx, sender_address="0xFutureSender", nonce=10000)) as mock_gen_future_tx:
            fuzz_engine._reset_and_initial_pool_setup()

            mock_ethereum_client.clear_txpool_custom.assert_called_once()
            mock_account_manager.reset_all_fuzzer_nonces.assert_called_once()
            mock_ethereum_client.get_current_gas_prices.assert_called_once()
            assert mock_ethereum_client.sign_and_send_transfer.call_count == 2 # 1 normal + 1 future
            assert mock_account_manager.increment_fuzzer_nonce.call_count == 1 # Only for normal tx
            mock_gen_future_tx.assert_called_once()
            assert fuzz_engine.current_fuzzer_account_index == 1 # Should increment for future tx

    @patch('eth_txpool_fuzzer_core.fuzz_engine.time.sleep', return_value=None)
    def test_reset_and_initial_pool_setup_gas_price_fetch_failure(self, mock_sleep, fuzz_engine, mock_ethereum_client, capsys):
        """
        Test _reset_and_initial_pool_setup when gas price fetching fails,
        it should use default values and log a warning.
        """
        mock_ethereum_client.get_current_gas_prices.return_value = None # Simulate failure
        fuzz_engine.initial_normal_tx_count = 1
        fuzz_engine.txpool_size = 1

        fuzz_engine._reset_and_initial_pool_setup()

        captured = capsys.readouterr()
        assert "ERROR: Could not fetch current gas prices. Using default values for initial setup." in captured.out
        # Verify that sign_and_send_transfer was still called, implying default values were used
        mock_ethereum_client.sign_and_send_transfer.assert_called_once()
        # Check that the sent tx used default EIP-1559 values (from core_config, not mocked here, but implied)
        # For a more robust test, we'd inspect the call args of sign_and_send_transfer.
        # For now, just checking it was called is sufficient.

    @patch('eth_txpool_fuzzer_core.fuzz_engine.time.sleep', return_value=None)
    def test_execute_input_sequence_initial_setup(self, mock_sleep, fuzz_engine, mock_ethereum_client, mock_account_manager):
        """
        Test _execute_input_sequence when initial_pool_state_to_recreate is None,
        triggering _reset_and_initial_pool_setup and then sending input_to_execute.
        """
        input_tx1 = Mock(spec=FuzzTx, sender_address="0xAccount0", nonce=0, tx_type=0)
        input_tx2 = Mock(spec=FuzzTx, sender_address="0xAccount1", nonce=0, tx_type=0)
        test_input = FuzzInput(tx_sequence_to_execute=[input_tx1, input_tx2])

        # Patch _reset_and_initial_pool_setup to prevent actual reset during this test
        with patch.object(fuzz_engine, '_reset_and_initial_pool_setup') as mock_reset_setup:
            fuzz_engine._execute_input_sequence(test_input, initial_pool_state_to_recreate=None)

            mock_reset_setup.assert_called_once()
            # Two calls for the initial setup (from _reset_and_initial_pool_setup)
            # Plus two calls for the test_input transactions
            # The exact count depends on the initial_normal_tx_count in fuzz_engine fixture.
            # Let's just check that the input transactions were sent.
            assert mock_ethereum_client.sign_and_send_transfer.call_args_list[0][0][0] == input_tx1
            assert mock_ethereum_client.sign_and_send_transfer.call_args_list[1][0][0] == input_tx2

    @patch('eth_txpool_fuzzer_core.fuzz_engine.time.sleep', return_value=None)
    @patch('eth_txpool_fuzzer_core.fuzz_engine.get_symbolic_pool_state', return_value="N") # Mock symbolic state for recreation
    def test_execute_input_sequence_recreate_state(self, mock_get_symbolic_pool_state, mock_sleep, fuzz_engine, mock_ethereum_client, mock_account_manager):
        """
        Test _execute_input_sequence when recreating a previous state.
        """
        initial_pool_state = {"pending": {}, "queued": {}}
        base_input = FuzzInput(tx_sequence_to_execute=[
            Mock(spec=FuzzTx, sender_address="0xAccount0", nonce=0, tx_type=0),
            Mock(spec=FuzzTx, sender_address="0xAccount1", nonce=0, tx_type=0)
        ], base_input_indices_to_resend=[0]) # Simulate one tx to resend

        input_tx_new = Mock(spec=FuzzTx, sender_address="0xAccount2", nonce=0, tx_type=0)
        test_input = FuzzInput(tx_sequence_to_execute=[input_tx_new])

        fuzz_engine.txpool_size = 1 # For normal tx recreation count
        fuzz_engine.initial_normal_tx_count = 1 # For normal tx recreation count

        fuzz_engine._execute_input_sequence(
            input_to_execute=test_input,
            initial_pool_state_to_recreate=initial_pool_state,
            base_input_for_recreation=base_input
        )

        mock_ethereum_client.clear_txpool_custom.assert_called_once()
        mock_account_manager.reset_all_fuzzer_nonces.assert_called_once()
        mock_ethereum_client.get_current_gas_prices.assert_called_once()

        # Expected calls: 1 normal tx recreation + 1 base_input_to_resend + 1 new input tx
        # The exact order and number of calls to sign_and_send_transfer can be tricky due to internal logic.
        # Let's check for specific calls.
        # Check for the normal tx recreation
        assert any(call.args[0].sender_address == "0xAccount0" and call.args[0].value == 1 for call in mock_ethereum_client.sign_and_send_transfer.call_args_list)
        # Check for the base_input_to_resend tx
        assert any(call.args[0] == base_input.tx_sequence_to_execute[0] for call in mock_ethereum_client.sign_and_send_transfer.call_args_list)
        # Check for the new input tx
        assert any(call.args[0] == input_tx_new for call in mock_ethereum_client.sign_and_send_transfer.call_args_list)

        # Ensure nonce is incremented for the new input tx (if not future tx)
        if input_tx_new.nonce != 10000:
            mock_account_manager.increment_fuzzer_nonce.assert_called_with(input_tx_new.sender_address)

    def test_parse_input_to_symbol(self, fuzz_engine):
        """
        Test _parse_input_to_symbol for various transaction types.
        """
        # Mock core_config values for consistent testing
        with patch('eth_txpool_fuzzer_core.fuzz_engine.core_config.STATE_PARENT_REPLACEMENT_PRICE_THRESHOLD', 100):
            with patch('eth_txpool_fuzzer_core.fuzz_engine.core_config.STATE_CHILD_VALUE_THRESHOLD', 50):
                # P: nonce 0, price < threshold
                tx_p = FuzzTx(account_manager_index=0, sender_address="0xSender1", nonce=0, price=50, value=100)
                # R: nonce 0, price >= threshold
                tx_r = FuzzTx(account_manager_index=0, sender_address="0xSender2", nonce=0, price=150, value=100)
                # C: nonce 1 (child of 0), value <= threshold
                tx_c = FuzzTx(account_manager_index=0, sender_address="0xSender1", nonce=1, price=50, value=20)
                # O: nonce 1 (child of 0), value > threshold
                tx_o = FuzzTx(account_manager_index=0, sender_address="0xSender2", nonce=1, price=150, value=60)
                # Future tx (should be ignored by this symbolization logic)
                tx_f = FuzzTx(account_manager_index=0, sender_address="0xSender3", nonce=10000, price=10, value=2)
                # Gapped nonce (should be ignored)
                tx_g = FuzzTx(account_manager_index=0, sender_address="0xSender1", nonce=5, price=10, value=10)


                fuzz_input = FuzzInput(tx_sequence_to_execute=[tx_p, tx_r, tx_c, tx_o, tx_f, tx_g])
                symbol = fuzz_engine._parse_input_to_symbol(fuzz_input)
                assert symbol == "PRCO" # Future and gapped nonces are ignored

    def test_concrete_input_to_string(self, fuzz_engine):
        """
        Test _concrete_input_to_string for correct formatting.
        """
        tx1 = FuzzTx(account_manager_index=0, sender_address="0xSender1", nonce=0, price=10, value=100)
        tx2 = FuzzTx(account_manager_index=1, sender_address="0xSender2", nonce=1, price=20, value=200)
        fuzz_input = FuzzInput(tx_sequence_to_execute=[tx1, tx2])

        concrete_strings = fuzz_engine._concrete_input_to_string(fuzz_input)

        expected_strings = [
            "from: 0xSender1, to: 0xDefaultRecipient, nonce: 0, price: 10, value: 100",
            "from: 0xSender2, to: 0xDefaultRecipient, nonce: 1, price: 20, value: 200"
        ]
        assert concrete_strings == expected_strings
