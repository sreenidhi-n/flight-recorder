"""
Document ingestion pipeline — reads from S3, indexes in DynamoDB, queues via SQS.
"""
import json
import boto3
from datetime import datetime

# S3 client for document storage
s3 = boto3.client("s3", region_name="us-east-1")
dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
sqs = boto3.client("sqs", region_name="us-east-1")

TABLE_NAME = "documents-index"
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789/doc-processing-queue"
BUCKET = "acme-document-store"


def ingest_document(doc_key: str) -> dict:
    """Fetch a document from S3, store metadata in DynamoDB, enqueue for processing."""
    # Fetch raw document from S3
    response = s3.get_object(Bucket=BUCKET, Key=doc_key)
    raw = response["Body"].read()

    metadata = {
        "doc_key": doc_key,
        "size_bytes": len(raw),
        "ingested_at": datetime.utcnow().isoformat(),
        "status": "pending",
    }

    # Index in DynamoDB
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item=metadata)

    # Enqueue for async processing
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps({"doc_key": doc_key, "size": len(raw)}),
    )

    return metadata


def list_pending_docs(prefix: str = "uploads/") -> list[str]:
    """List unprocessed documents in S3."""
    paginator = s3.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    return keys
