"""
Unit tests for payment_processor — should be IGNORED by TASS (.tassignore excludes test_*.py).
Any boto3/requests calls here are test mocks, not production capabilities.
"""
import boto3
import unittest
from unittest.mock import patch, MagicMock


class TestChargeCard(unittest.TestCase):
    @patch("requests.post")
    def test_successful_charge(self, mock_post):
        mock_post.return_value.json.return_value = {"id": "ch_test", "status": "succeeded"}
        mock_post.return_value.raise_for_status = lambda: None
        # If TASS reports this requests.post, .tassignore is broken.
        from payment_processor import charge_card
        result = charge_card(1000, "tok_test", "sk_test")
        self.assertEqual(result["status"], "succeeded")

    @patch("boto3.resource")
    def test_store_receipt(self, mock_resource):
        mock_table = MagicMock()
        mock_resource.return_value.Table.return_value = mock_table
        # This boto3.resource call should be ignored (test file).
        from payment_processor import store_receipt
        store_receipt("ch_123", {"amount": 1000})
        mock_table.put_item.assert_called_once()
