"""
Customer support AI agent built on Strands Agents SDK.
Handles ticket routing, sentiment analysis, and escalations.
"""
from strands import Agent, tool
from strands.models import BedrockModel

# Configure the underlying LLM
model = BedrockModel(
    model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
    region_name="us-east-1",
)


@tool
def lookup_ticket(ticket_id: str) -> dict:
    """Retrieve a support ticket from the CRM."""
    # In production this would call the CRM API
    return {"id": ticket_id, "status": "open", "priority": "normal"}


@tool
def escalate_ticket(ticket_id: str, reason: str) -> bool:
    """Escalate a ticket to the L2 support team."""
    print(f"Escalating {ticket_id}: {reason}")
    return True


@tool
def send_reply(ticket_id: str, message: str) -> bool:
    """Send a reply to the customer."""
    print(f"Replying to {ticket_id}: {message}")
    return True


# Instantiate the Strands agent with tools
support_agent = Agent(
    model=model,
    tools=[lookup_ticket, escalate_ticket, send_reply],
    system_prompt="""You are a customer support agent for Acme Corp.
Your goal is to resolve tickets efficiently and escalate when needed.
Always be polite, concise, and solution-oriented.""",
)


def handle_ticket(ticket_id: str, customer_message: str) -> str:
    """Route an incoming ticket through the support agent."""
    prompt = f"Handle ticket {ticket_id}. Customer says: {customer_message}"
    result = support_agent(prompt)
    return str(result)
