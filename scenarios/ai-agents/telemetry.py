"""
OpenTelemetry tracing setup for the AI agents microservice.
Sends traces to a Jaeger / OTLP collector.
"""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.requests import RequestsInstrumentor

OTLP_ENDPOINT = "http://otel-collector:4317"

resource = Resource.create({"service.name": "acme-ai-agents", "service.version": "1.0.0"})

provider = TracerProvider(resource=resource)
exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True)
provider.add_span_processor(BatchSpanProcessor(exporter))

# Register as global tracer provider
trace.set_tracer_provider(provider)

# Auto-instrument outbound HTTP calls
RequestsInstrumentor().instrument()

tracer = trace.get_tracer("acme.agents")


def traced_agent_call(agent_name: str, prompt: str):
    """Wrap an agent invocation with an OTel span."""
    with tracer.start_as_current_span(f"agent.{agent_name}") as span:
        span.set_attribute("agent.name", agent_name)
        span.set_attribute("prompt.length", len(prompt))
        # ... call the agent
        span.set_attribute("agent.status", "ok")
