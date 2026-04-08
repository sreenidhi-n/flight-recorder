"""
ML inference layer — invokes Amazon Bedrock for document classification
and stores results in DynamoDB + publishes to SNS.
"""
import json
import boto3

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
sns = boto3.client("sns", region_name="us-east-1")
secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")

MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"
TOPIC_ARN = "arn:aws:sns:us-east-1:123456789:doc-classified"
RESULTS_TABLE = "classification-results"
SECRET_NAME = "prod/acme/model-config"


def classify_document(doc_text: str) -> dict:
    """Send document to Bedrock Claude for classification."""
    # Retrieve model config from Secrets Manager
    secret = secretsmanager.get_secret_value(SecretId=SECRET_NAME)
    config = json.loads(secret["SecretString"])

    prompt = f"""Classify the following document into one of: invoice, contract, report, other.
Document:
{doc_text[:2000]}

Respond with JSON: {{"category": "<category>", "confidence": <0-1>}}"""

    response = bedrock.invoke_model(
        modelId=MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": config.get("temperature", 0.1),
        }),
    )

    result = json.loads(response["body"].read())
    classification = json.loads(result["content"][0]["text"])

    # Persist to DynamoDB
    table = dynamodb.Table(RESULTS_TABLE)
    table.put_item(Item={"doc_hash": hash(doc_text), **classification})

    # Publish classification event
    sns.publish(
        TopicArn=TOPIC_ARN,
        Message=json.dumps(classification),
        Subject="Document classified",
    )

    return classification
