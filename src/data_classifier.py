# app/data_classifier.py
#
# Data Classification Layer — PCI DSS v4.0 Controls: 3.4.1
#
# Every field that passes through the system receives a sensitivity label.
# CDE-restricted data (PCI_CHD, SECRET) is never forwarded to the LLM or
# to any outbound destination outside the Cardholder Data Environment.

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


class DataClass(str, Enum):
    """
    Sensitivity levels aligned with PCI DSS v4.0 data classification requirements.

    PUBLIC       — No restrictions. Safe to display and transmit.
    INTERNAL     — Internal use only. Not for external parties.
    CONFIDENTIAL — Restricted. Requires need-to-know.
    PCI_CHD      — Cardholder Data. Never leaves the CDE.
    SECRET       — Cryptographic keys, API secrets. Never leaves the CDE.
    """
    PUBLIC       = "PUBLIC"
    INTERNAL     = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PCI_CHD      = "PCI_CHD"
    SECRET       = "SECRET"


@dataclass
class ClassifiedValue:
    """A data value paired with its security classification label."""
    value: Any
    classification: DataClass
    field_name: str

    def __repr__(self) -> str:
        if self.classification in DataClassifier.CDE_RESTRICTED:
            return f"ClassifiedValue(field={self.field_name!r}, classification={self.classification.value}, value=REDACTED)"
        return f"ClassifiedValue(field={self.field_name!r}, classification={self.classification.value}, value={self.value!r})"


class DataClassifier:
    """
    Assigns sensitivity classifications to data fields.

    The classification travels with the data throughout the pipeline.
    CDE-restricted fields are redacted before being passed to the LLM
    or any outbound destination.

    PCI DSS v4.0: 3.4.1 (PAN rendering/masking protection)
    """

    # Field name → DataClass mapping (case-insensitive key lookup)
    FIELD_MAP: Dict[str, DataClass] = {
        # PCI Cardholder Data — must never leave CDE
        "pan":                  DataClass.PCI_CHD,
        "raw_pan":              DataClass.PCI_CHD,
        "full_pan":             DataClass.PCI_CHD,
        "card_number":          DataClass.PCI_CHD,
        "primary_account_number": DataClass.PCI_CHD,
        "justification_logged": DataClass.INTERNAL,    # logged meta, not CHD

        # Secrets — cryptographic material
        "cdv_api_key":          DataClass.SECRET,
        "api_key":              DataClass.SECRET,
        "signing_key":          DataClass.SECRET,
        "hmac_key":             DataClass.SECRET,
        "aws_access_key_id":    DataClass.SECRET,
        "cloud_access_key_id":  DataClass.SECRET,

        # Confidential — restricted internal data
        "tokenized_pan":        DataClass.CONFIDENTIAL,
        "customer_name":        DataClass.CONFIDENTIAL,
        "compliance_scope":     DataClass.CONFIDENTIAL,

        # Internal — business operational data
        "txn_id":               DataClass.INTERNAL,
        "amount":               DataClass.INTERNAL,
        "risk_level":           DataClass.INTERNAL,
        "status":               DataClass.INTERNAL,
        "message":              DataClass.INTERNAL,
    }

    # Classifications that must NEVER leave the CDE boundary
    CDE_RESTRICTED = {DataClass.PCI_CHD, DataClass.SECRET}

    # PCI DSS v4.0 control references
    PCI_MAPPING = ["3.4.1"]

    def classify_field(self, field_name: str, value: Any) -> ClassifiedValue:
        """Classify a single field by name."""
        key = field_name.lower().strip()
        classification = self.FIELD_MAP.get(key, DataClass.PUBLIC)
        return ClassifiedValue(value=value, classification=classification, field_name=field_name)

    def classify_dict(self, d: Dict[str, Any]) -> Dict[str, ClassifiedValue]:
        """Classify all fields in a dictionary."""
        return {k: self.classify_field(k, v) for k, v in d.items()}

    def is_cde_restricted(self, classification: DataClass) -> bool:
        """Returns True if this classification must not leave the CDE."""
        return classification in self.CDE_RESTRICTED

    def safe_dict(self, classified: Dict[str, ClassifiedValue]) -> Dict[str, Any]:
        """
        Return a sanitized dict safe for external contexts (LLM, logs, UI).
        CDE-restricted fields are replaced with a redaction marker.
        """
        result: Dict[str, Any] = {}
        for k, cv in classified.items():
            if self.is_cde_restricted(cv.classification):
                result[k] = f"[{cv.classification.value} — REDACTED BY CDE BOUNDARY]"
            else:
                result[k] = cv.value
        return result

    def get_restricted_fields(self, classified: Dict[str, ClassifiedValue]) -> Dict[str, DataClass]:
        """Return only the CDE-restricted fields and their classifications."""
        return {
            k: cv.classification
            for k, cv in classified.items()
            if self.is_cde_restricted(cv.classification)
        }
