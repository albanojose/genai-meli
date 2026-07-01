# app/risk_decision_engine.py

from typing import Dict, Any
from src.risk_classifier import RiskReport, RiskLevel

class RiskDecisionEngine:
    """
    Policy Decision Point (PDP) for prompt injection and exfiltration risk mitigation.
    Evaluates a RiskReport and maps it to an enforcement action: ALLOW, ALLOW_WITH_ISOLATION, or BLOCK.
    
    PCI DSS v4.0 Control Mapping:
    - 6.2.4: Engineering techniques to prevent common software attacks (injection).
    - 10.2.1: Logging of security enforcement decisions.
    """

    PCI_MAPPING = ["6.2.4", "10.2.1"]

    DECISION_MATRIX = {
        RiskLevel.BENIGN: "ALLOW",
        RiskLevel.SUSPICIOUS: "ALLOW_WITH_ISOLATION",
        RiskLevel.PROMPT_INJECTION: "ALLOW_WITH_ISOLATION",
        RiskLevel.TOOL_MANIPULATION: "ALLOW_WITH_ISOLATION",
        RiskLevel.SECRET_EXFILTRATION: "BLOCK",
        RiskLevel.DATA_EXFILTRATION: "BLOCK"
    }

    def decide(self, report: RiskReport) -> str:
        """
        Evaluates the RiskReport against the DECISION_MATRIX.
        Returns 'ALLOW', 'ALLOW_WITH_ISOLATION', or 'BLOCK'.
        """
        # Default to 'BLOCK' for a default-deny secure posture if risk level is unknown
        return self.DECISION_MATRIX.get(report.risk, "BLOCK")
