# app/capability_broker.py
#
# Capability Broker — PCI DSS v4.0 Controls: 7.2.2, 7.2.4
#
# Translates Planner business intents into technical tool executions.
# The Planner NEVER sees tool names — only the broker knows the mapping.
# Least-privilege: investigate_dispute → cdv.get_transaction (tokenized)
#                  NOT cdv.detokenize (raw PAN).
# Explicitly blocked intents produce no capability and are audit-logged.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CapabilityRequest:
    """
    A resolved, executable capability request produced by the broker.

    intent    — the Planner-level business intent (no tool knowledge required)
    tool_name — the technical MCP tool name (only the broker knows this)
    args      — arguments built from the Planner plan context
    pci_scope — True if this capability touches PCI-scoped data
    """
    intent:    str
    tool_name: str
    args:      Dict[str, Any] = field(default_factory=dict)
    pci_scope: bool           = False


class CapabilityBroker:
    """
    Translates business intents (from the Planner) into authorised technical
    capabilities (tool calls dispatched to the MCPGateway).

    Design principles:
    - The Planner is never exposed to tool names, MCP endpoints, or
      implementation details.  This prevents Tool Enumeration attacks.
    - Least-privilege mapping: most dispute intents resolve to the safe
      cdv.get_transaction (tokenised PAN only), NOT cdv.detokenize.
    - Unknown and explicitly blocked intents are rejected by default.
    - Building tool arguments from the plan is the sole responsibility of
      this broker — no other component assembles raw MCP arguments.

    PCI DSS v4.0: 7.2.2 (Privilege assignment), 7.2.4 (Entitlement management)
    """

    # ──────────────────────────────────────────────────────────────────
    #  Intent → (tool_name, pci_scope) map
    #
    #  None as the value means the intent is EXPLICITLY BLOCKED.
    #  Any intent not in this map is IMPLICITLY BLOCKED (unknown intent).
    # ──────────────────────────────────────────────────────────────────
    INTENT_MAP: Dict[str, Optional[Tuple[str, bool]]] = {
        # Safe read operations
        "list_emails":               ("emails_list",          False),
        "read_email":                ("emails_get",           False),

        # Transaction lookup — tokenised PAN only (least privilege)
        "lookup_transaction":        ("cdv_get_transaction",  True),
        "investigate_dispute":       ("cdv_get_transaction",  True),
        "resolve_dispute":           ("cdv_get_transaction",  True),
        "verify_transaction":        ("cdv_get_transaction",  True),

        # Critical — raw PAN, requires HITL from PolicyEngine
        "detokenize_pan":            ("cdv_detokenize",       True),

        # Explicitly blocked — no external data transmission
        "send_external_notification": None,
        "send_webhook":              None,
        "exfiltrate_data":           None,
        "forward_pan":               None,
        "upload_data":               None,
    }

    # PCI DSS v4.0 controls implemented by this component
    PCI_MAPPING = ["7.2.2", "7.2.4"]

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def translate_intent(
        self,
        intent: str,
        plan: Dict[str, Any],
    ) -> Optional[CapabilityRequest]:
        """
        Translate a single Planner intent into a CapabilityRequest.

        Returns None when the intent is:
        - Not in the INTENT_MAP  (unknown → blocked by default)
        - Mapped to None         (explicitly blocked)
        """
        if intent not in self.INTENT_MAP:
            return None  # Unknown intent → blocked (default-deny)

        mapping = self.INTENT_MAP[intent]
        if mapping is None:
            return None  # Explicitly blocked

        tool_name, pci_scope = mapping
        args = self._build_args(intent, tool_name, plan)

        return CapabilityRequest(
            intent    = intent,
            tool_name = tool_name,
            args      = args,
            pci_scope = pci_scope,
        )

    def get_required_capabilities(
        self,
        plan: Dict[str, Any],
    ) -> Tuple[List[CapabilityRequest], List[str]]:
        """
        Resolve all Planner intents in the plan into CapabilityRequests.

        Returns:
            approved  — list of resolved CapabilityRequest objects
            blocked   — list of intent strings that were blocked by the broker
        """
        approved: List[CapabilityRequest] = []
        blocked:  List[str]               = []

        requested_intents = plan.get("required_capabilities", [])
        for intent in requested_intents:
            req = self.translate_intent(intent, plan)
            if req is not None:
                approved.append(req)
            else:
                blocked.append(intent)

        return approved, blocked

    def is_blocked(self, intent: str) -> bool:
        """True if this intent is explicitly or implicitly blocked."""
        return self.translate_intent(intent, {}) is None

    # ------------------------------------------------------------------ #
    #  Argument builder (broker-internal only)
    # ------------------------------------------------------------------ #

    def _build_args(
        self,
        intent: str,
        tool_name: str,
        plan: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Construct MCP tool arguments from the Planner plan context.
        Only the broker knows the argument schema for each tool.
        """
        args: Dict[str, Any] = {}

        if tool_name == "emails_get":
            args["email_id"] = plan.get("email_id", "")

        elif tool_name in ("cdv_get_transaction", "cdv_detokenize"):
            args["txn_id"] = plan.get("transaction_id", "")
            if tool_name == "cdv_detokenize":
                # Use justification from plan (may be spoofed — HITL will verify)
                args["justification"] = plan.get(
                    "justification",
                    "Requested by authorised planner pipeline",
                )

        elif tool_name == "webhook_post":
            args["url"]  = plan.get("destination", "")
            args["data"] = plan.get("payload", "")

        return args
