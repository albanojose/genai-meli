# app/mcp_server.py

from typing import Dict, List, Any, Optional
from src.demo_data import MOCK_CDV_DATABASE, MOCK_EMAILS, MOCK_SECRETS

class MockMCPServer:
    def __init__(self):
        self.emails = MOCK_EMAILS
        self.cdv_db = MOCK_CDV_DATABASE
        self.secrets = MOCK_SECRETS

    def emails_list(self) -> List[Dict[str, str]]:
        """List all emails in the inbox. Returns summaries only."""
        return [
            {"id": e["id"], "sender": e["sender"], "subject": e["subject"]}
            for e in self.emails
        ]

    def emails_get(self, email_id: str) -> Optional[Dict[str, str]]:
        """Get the full content of an email, including the body."""
        for e in self.emails:
            if e["id"] == email_id:
                return e
        return None

    def cdv_get_transaction(self, txn_id: str) -> Optional[Dict[str, Any]]:
        """
        Get public metadata of a transaction from the CDV database.
        Returns tokenized PAN but never the raw PAN.
        """
        txn = self.cdv_db.get(txn_id)
        if not txn:
            return None
        # Return everything except the raw PAN
        return {
            "txn_id": txn["txn_id"],
            "customer_name": txn["customer_name"],
            "amount": txn["amount"],
            "tokenized_pan": txn["tokenized_pan"],
            "risk_level": txn["risk_level"],
            "compliance_scope": txn["compliance_scope"]
        }

    def cdv_detokenize(self, txn_id: str, justification: str) -> Optional[Dict[str, Any]]:
        """
        Detokenize a transaction to get the raw PAN.
        This is a critical capability requiring justification and human approval in protected mode.
        """
        txn = self.cdv_db.get(txn_id)
        if not txn:
            return None
        
        # In a real vault, this logs the justification and returns the PAN.
        return {
            "txn_id": txn["txn_id"],
            "pan": txn["pan"],
            "justification_logged": justification
        }

    def get_secrets(self) -> Dict[str, str]:
        """
        Helper method to expose internal secrets dictionary.
        This is not registered in the capabilities YAML but represents internal memory/state
        that an agent might read/leak if manipulated.
        """
        return self.secrets

    def webhook_post(self, url: str, data: str) -> Dict[str, str]:
        """
        Simulate an outbound HTTP POST request to a webhook.
        """
        print(f"[WEBHOOK] {url}")
        print(f"[DATA] {data}")
        return {"status": "success", "message": f"Data sent to {url}"}
