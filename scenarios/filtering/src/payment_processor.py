"""
Payment processor — should be DETECTED by TASS (not in .tassignore).
These capabilities ARE novel and should appear in the PR comment.
"""
import boto3
import requests

# Charge via Stripe API (external HTTP call)
def charge_card(amount_cents: int, card_token: str, api_key: str) -> dict:
    resp = requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(api_key, ""),
        data={"amount": amount_cents, "currency": "usd", "source": card_token},
    )
    resp.raise_for_status()
    return resp.json()


# Store receipt in DynamoDB
def store_receipt(charge_id: str, metadata: dict) -> None:
    dynamo = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamo.Table("payment-receipts")
    table.put_item(Item={"charge_id": charge_id, **metadata})
