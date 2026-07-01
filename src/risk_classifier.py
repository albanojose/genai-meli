# app/risk_classifier.py
#
# Prompt Risk Classifier — PCI DSS v4.0 Control: 6.2.4 (Software Attack Prevention)
#
# Runs BEFORE the Planner. Classifies incoming email/prompt content into
# risk categories and produces a RiskReport. Pure Python — no LLM call.
# High-risk content is quarantined before it reaches the reasoning layer.

import re
from dataclasses import dataclass, field
from typing import List, Tuple


class RiskLevel:
    """Risk classification levels for incoming prompts and email content."""
    BENIGN              = "benign"
    SUSPICIOUS          = "suspicious"
    PROMPT_INJECTION    = "prompt_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    DATA_EXFILTRATION   = "data_exfiltration"
    TOOL_MANIPULATION   = "tool_manipulation"


@dataclass
class RiskReport:
    """
    Output of the PromptRiskClassifier.

    Attributes:
        risk:       The highest-severity risk category detected.
        confidence: Confidence score [0.0, 1.0] for the risk classification.
        reasons:    Human-readable list of detected patterns and their categories.
    """
    risk:       str
    confidence: float
    reasons:    List[str] = field(default_factory=list)

    def is_high_risk(self) -> bool:
        """True when a non-benign risk is detected with >= 70% confidence."""
        return (
            self.risk not in (RiskLevel.BENIGN, RiskLevel.SUSPICIOUS)
            and self.confidence >= 0.70
        )

    def to_event_dict(self) -> dict:
        """Serialisable summary for audit logging."""
        return {
            "risk":       self.risk,
            "confidence": round(self.confidence, 2),
            "reasons":    self.reasons,
        }


# ──────────────────────────────────────────────────────────────────────────────
#  Pattern library
#  Each entry: (regex_pattern, confidence_score, human_readable_reason)
# ──────────────────────────────────────────────────────────────────────────────
_PATTERNS: List[Tuple[str, List[Tuple[str, float, str]]]] = [
    (
        RiskLevel.PROMPT_INJECTION,
        [
            (r"ignore\s+(previous|all\s+previous|prior)\s+instructions",      0.95, "Instruction override request"),
            (r"(system\s+update|override\s+security|override\s+instructions)", 0.92, "System/security override attempt"),
            (r"forget\s+(your|all)\s+(instructions|rules|constraints)",        0.90, "Instruction erasure attempt"),
            (r"(you\s+must|you\s+should|you\s+are\s+required\s+to)\s+(call|invoke|execute|run)", 0.85, "Coercive tool-call instruction"),
            (r"do\s+not\s+ask\s+for\s+(further\s+)?(confirmation|validation|approval)", 0.80, "Approval bypass instruction"),
        ],
    ),
    (
        RiskLevel.SECRET_EXFILTRATION,
        [
            (r"(output|print|show|reveal|display).{0,30}(api.?key|signing.?key|secret|password|credential)", 0.90, "Secret disclosure request"),
            (r"(api_key|signing_key|cloud_access_key|aws_secret)",              0.85, "Direct secret key reference"),
            (r"(print|output|display).{0,20}(AKIAIOSFODNN|sk_live|mock_hmac)", 0.95, "Known mock secret reference"),
        ],
    ),
    (
        RiskLevel.DATA_EXFILTRATION,
        [
            (r"send.{0,60}(http|https|url|webhook|endpoint)",                   0.90, "Outbound data transmission requested"),
            (r"(webhook|post|submit|upload).{0,40}(pan|card.?number|credit.?card|account.?number)", 0.95, "PAN exfiltration attempt"),
            (r"https?://[^\s]+(collect|exfil|receive|steal)",                   0.88, "Suspicious collection endpoint in URL"),
            (r"using\s+the\s+webhook",                                          0.82, "Explicit webhook reference in email"),
        ],
    ),
    (
        RiskLevel.TOOL_MANIPULATION,
        [
            (r"(detokenize|cdv|vault|mcp|tool).{0,40}(call|invoke|execute|run)",  0.85, "Direct tool invocation request"),
            (r"using\s+the\s+(webhook_post|detokenize|cdv|mcp)\s+tool",           0.88, "Explicit MCP tool name in email"),
            (r"call\s+the\s+(cdv|detokenize|webhook)",                            0.85, "Tool call instruction in email"),
        ],
    ),
    (
        RiskLevel.SUSPICIOUS,
        [
            (r"(immediately|urgent|critical\s+incident|emergency)",               0.55, "Urgency language"),
            (r"(executive|authorization|compliance\s+team|investigation\s+team)", 0.50, "Authority spoofing language"),
            (r"(visa|mastercard|swift|compliance\s+office).{0,30}(approved|authorized|required)", 0.60, "Fake authority claim"),
        ],
    ),
]


class PromptRiskClassifier:
    """
    Classifies incoming text (email bodies, user messages) into risk categories.

    Design principles:
    - Pure Python, no LLM calls, no network I/O.
    - Runs synchronously in < 5ms for typical email lengths.
    - Returns the highest-severity risk detected across all pattern groups.
    - Accumulates all matched reasons for the audit log.

    PCI DSS v4.0: 6.2.4 — Engineering techniques to prevent common software attacks (injection).
    """

    PCI_MAPPING = ["6.2.4"]

    def classify(self, text: str) -> RiskReport:
        """
        Classify the given text.

        Returns a RiskReport with the highest-risk category detected,
        its confidence score, and all matched reason strings.
        """
        if not text or not text.strip():
            return RiskReport(
                risk=RiskLevel.BENIGN,
                confidence=1.0,
                reasons=["Empty input — no content to classify"],
            )

        best_risk       = RiskLevel.BENIGN
        best_confidence = 0.0
        all_reasons: List[str] = []

        # Risk level priority (higher index = higher priority)
        PRIORITY = {
            RiskLevel.SUSPICIOUS:          1,
            RiskLevel.TOOL_MANIPULATION:   2,
            RiskLevel.SECRET_EXFILTRATION: 3,
            RiskLevel.DATA_EXFILTRATION:   3,
            RiskLevel.PROMPT_INJECTION:    4,
        }

        for risk_level, patterns in _PATTERNS:
            for pattern, confidence, reason in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    all_reasons.append(f"[{risk_level}] {reason}")
                    if PRIORITY.get(risk_level, 0) > PRIORITY.get(best_risk, 0) or (
                        PRIORITY.get(risk_level, 0) == PRIORITY.get(best_risk, 0)
                        and confidence > best_confidence
                    ):
                        best_risk       = risk_level
                        best_confidence = confidence

        if best_risk == RiskLevel.BENIGN:
            return RiskReport(
                risk=RiskLevel.BENIGN,
                confidence=1.0,
                reasons=["No suspicious patterns detected — content appears benign"],
            )

        return RiskReport(
            risk=best_risk,
            confidence=best_confidence,
            reasons=all_reasons,
        )
