"""
Vendored AWS SDK wrapper — should be IGNORED by TASS (.tassignore excludes vendor/).
TASS should NOT report these boto3 calls as novel capabilities.
"""
import boto3

# This is third-party vendored code.
# If TASS reports these, the .tassignore integration is broken.
s3 = boto3.client("s3")
dynamo = boto3.resource("dynamodb")
sqs = boto3.client("sqs")


def vendored_helper(bucket, key):
    return s3.get_object(Bucket=bucket, Key=key)
