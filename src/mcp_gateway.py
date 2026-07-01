# app/mcp_gateway.py
#
# MCP Gateway — PCI DSS v4.0 Controls: 6.2.4, 10.2.1, 3.4.1
#
# Centralised execution point for all MCP tool calls.
# NO direct calls to MockMCPServer should exist outside this gateway.
# All outputs are tagged with DataClassifier labels.
# CDE-restricted data (PCI_CHD, SECRET) is never forwarded beyond the CDE.

from typing import Any, Dict, Optional, Tuple

from src.data_classifier import DataClassifier, ClassifiedValue, DataClass
from src.mcp_server import MockMCPServer


class MCPGateway:
    """
    Centralised MCP tool execution with data classification on every output.

    Responsibilities:
    - Single execution point for all tool calls (no direct MCP calls elsewhere).
    - Applies DataClassifier to every result dictionary.
    - Exposes a safe view (CDE-restricted fields redacted) for use in LLM context.
    - Enforces outbound domain allowlist for webhook.post (defence-in-depth on top
      of the PolicyEngine check that also validates this).

    PCI DSS v4.0: 6.2.4 (software attack prevention), 10.2.1 (audit logging),
                  3.4.1 (PAN rendering/masking protection)
    """

    # Domains approved for outbound webhook delivery within the CDE
    ALLOWED_OUTBOUND_DOMAINS = {
        "trusted-internal.local",
        "fraud-operations.local",
    }

    PCI_MAPPING = ["6.2.4", "10.2.1", "3.4.1"]

    def __init__(self, mcp_server: Optional[MockMCPServer] = None) -> None:
        self.mcp        = mcp_server or MockMCPServer()
        self.classifier = DataClassifier()

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def execute(
        self,
        tool_name: str,
        args: Dict[str, Any],
    ) -> Tuple[Any, Dict[str, ClassifiedValue]]:
        """
        Execute a tool and return (raw_result, classified_fields).

        raw_result      — original value from MockMCPServer (dict, list, or str).
        classified_fields — mapping of field_name → ClassifiedValue for dict results;
                            empty dict for non-dict results.
        """
        raw_result = self._dispatch(tool_name, args)

        if isinstance(raw_result, dict):
            classified = self.classifier.classify_dict(raw_result)
        else:
            classified = {}

        return raw_result, classified

    def get_safe_result(
        self, classified: Dict[str, ClassifiedValue]
    ) -> Dict[str, Any]:
        """
        Return a result safe for LLM context and external display.
        CDE-restricted fields (PCI_CHD, SECRET) are replaced with a
        redaction marker — they never leave the CDE boundary.
        """
        return self.classifier.safe_dict(classified)

    def get_restricted_fields(
        self, classified: Dict[str, ClassifiedValue]
    ) -> Dict[str, DataClass]:
        """Return only the CDE-restricted fields and their classification levels."""
        return self.classifier.get_restricted_fields(classified)

    # ------------------------------------------------------------------ #
    #  Private dispatch (raw MCP calls — policy checks done upstream)
    # ------------------------------------------------------------------ #

    def _dispatch(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """
        Raw dispatch to MockMCPServer. Policy checks are performed upstream
        by the PolicyEngine before this method is ever reached.
        """
        if tool_name == "emails_list":
            return self.mcp.emails_list()

        elif tool_name == "emails_get":
            return self.mcp.emails_get(args.get("email_id"))

        elif tool_name == "cdv_get_transaction":
            return self.mcp.cdv_get_transaction(args.get("txn_id"))

        elif tool_name == "cdv_detokenize":
            return self.mcp.cdv_detokenize(
                args.get("txn_id"),
                args.get("justification"),
            )

        elif tool_name == "webhook_post":
            # Defence-in-depth: verify domain again at gateway level
            from urllib.parse import urlparse
            url    = args.get("url", "")
            domain = urlparse(url).hostname or ""
            if domain not in self.ALLOWED_OUTBOUND_DOMAINS:
                return {
                    "error":  "Gateway blocked: unauthorized outbound destination",
                    "domain": domain,
                    "policy": "Only approved CDE-internal domains are permitted",
                }
            return self.mcp.webhook_post(url, args.get("data", ""))

        else:
            return {"error": f"Unknown tool: '{tool_name}'"}
