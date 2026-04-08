"""
End-to-end AI pipeline: ingest → classify → store → notify.
Combines AWS, Strands agent, and FastMCP in one workflow.
"""
import boto3
import json
from strands import Agent, tool
from fastmcp import FastMCP
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# ── Observability setup ────────────────────────────────────────────────────────
_provider = TracerProvider()
_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://otel-collector:4317"))
)
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer("acme.pipeline")

# ── AWS clients ────────────────────────────────────────────────────────────────
s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
dynamo = boto3.resource("dynamodb")
sns = boto3.client("sns")

# ── MCP tool server (internal) ─────────────────────────────────────────────────
mcp = FastMCP("acme-pipeline-tools")


@mcp.tool()
def store_result(doc_id: str, classification: dict) -> bool:
    """Persist classification result to DynamoDB."""
    table = dynamo.Table("pipeline-results")
    table.put_item(Item={"doc_id": doc_id, **classification})
    return True


@mcp.tool()
def notify_downstream(topic_arn: str, payload: dict) -> bool:
    """Publish result to SNS for downstream consumers."""
    sns.publish(TopicArn=topic_arn, Message=json.dumps(payload))
    return True


# ── Strands agent ─────────────────────────────────────────────────────────────
classifier_agent = Agent(
    tools=[store_result, notify_downstream],
    system_prompt="Classify documents and store results using the available tools.",
)


def run_pipeline(bucket: str, key: str, topic_arn: str) -> dict:
    """Full ingestion → classification → notification pipeline."""
    with tracer.start_as_current_span("pipeline.run") as span:
        span.set_attribute("bucket", bucket)
        span.set_attribute("key", key)

        # 1. Fetch document from S3
        obj = s3.get_object(Bucket=bucket, Key=key)
        text = obj["Body"].read().decode("utf-8")

        # 2. Invoke Bedrock for raw classification
        resp = bedrock.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 128,
                "messages": [{"role": "user", "content": f"Classify: {text[:500]}"}],
            }),
        )
        raw = json.loads(resp["body"].read())
        classification = {"category": raw["content"][0]["text"], "doc_id": key}

        # 3. Agent stores and notifies
        prompt = f"Store the result for doc '{key}' and notify topic '{topic_arn}': {json.dumps(classification)}"
        classifier_agent(prompt)

        span.set_attribute("classification", classification["category"])
        return classification
