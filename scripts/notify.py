"""
Notification helper — sends alerts via AWS SNS and logs to S3.
Added as part of the TASS scan test.
"""
import boto3
import requests

def send_alert(message: str, topic_arn: str) -> None:
    client = boto3.client("sns", region_name="us-east-1")
    client.publish(TopicArn=topic_arn, Message=message)

def post_webhook(url: str, payload: dict) -> None:
    resp = requests.post(url, json=payload, timeout=10)
    resp.raise_for_status()
