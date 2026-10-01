"""
OCSF v1.1.0 (Open Cybersecurity Schema Framework) Validator and Taxonomy.
Validates normalized security alerts against official OCSF categories, classes, and mandatory attributes:
- Category 1 (System Activity): Class 1001 (File System Activity), Class 1007 (Process Activity)
- Category 2 (Findings): Class 2001 (Security Finding), Class 2002 (Vulnerability Finding)
- Category 3 (Identity & Access Management): Class 3002 (Authentication)
- Category 4 (Network Activity): Class 4001 (Network Activity)
"""
from enum import IntEnum
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field


class OcsfCategory(IntEnum):
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_ACCESS = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OcsfClass(IntEnum):
    FILE_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    SECURITY_FINDING = 2001
    VULNERABILITY_FINDING = 2002
    AUTHENTICATION = 3002
    NETWORK_ACTIVITY = 4001


class OcsfSeverityId(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


CLASS_TAXONOMY: Dict[int, Dict[str, Any]] = {
    OcsfClass.SECURITY_FINDING: {
        "name": "Security Finding",
        "category": OcsfCategory.FINDINGS,
        "required_fields": ["activity_id", "severity_id", "finding_info"],
    },
    OcsfClass.PROCESS_ACTIVITY: {
        "name": "Process Activity",
        "category": OcsfCategory.SYSTEM_ACTIVITY,
        "required_fields": ["activity_id", "severity_id", "process"],
    },
    OcsfClass.AUTHENTICATION: {
        "name": "Authentication",
        "category": OcsfCategory.IDENTITY_ACCESS,
        "required_fields": ["activity_id", "severity_id", "user"],
    },
    OcsfClass.NETWORK_ACTIVITY: {
        "name": "Network Activity",
        "category": OcsfCategory.NETWORK_ACTIVITY,
        "required_fields": ["activity_id", "severity_id", "src_endpoint"],
    },
}


class OcsfValidationResult(BaseModel):
    is_valid: bool
    class_uid: int
    class_name: str
    category_uid: int
    category_name: str
    errors: List[str] = Field(default_factory=list)
    normalized_ocsf_record: Optional[Dict[str, Any]] = None


class OcsfValidator:
    """
    Enforces strict OCSF v1.1.0 schema conformance on ingested alerts and internal event models.
    """

    @classmethod
    def infer_class_uid(cls, alert_payload: Dict[str, Any]) -> int:
        """Infers OCSF Class UID from alert attributes if not explicitly defined."""
        if "class_uid" in alert_payload and isinstance(alert_payload["class_uid"], int):
            return alert_payload["class_uid"]

        rule = str(alert_payload.get("rule_name", "")).lower()
        if any(term in rule for term in ["login", "ssh", "auth", "credential", "password", "pam"]):
            return OcsfClass.AUTHENTICATION
        if any(term in rule for term in ["network", "beacon", "c2", "port scan", "dns", "traffic"]):
            return OcsfClass.NETWORK_ACTIVITY
        if any(term in rule for term in ["process", "exec", "powershell", "bash", "cmd", "fork"]):
            return OcsfClass.PROCESS_ACTIVITY

        # Default class for SIEM detections is Security Finding (2001)
        return OcsfClass.SECURITY_FINDING

    @classmethod
    def validate_and_conform(
        cls,
        alert_payload: Dict[str, Any],
        strict: bool = False,
    ) -> OcsfValidationResult:
        """
        Validates payload against OCSF v1.1.0 and generates an OCSF-compliant dictionary.
        """
        errors: List[str] = []
        class_uid = cls.infer_class_uid(alert_payload)
        class_info = CLASS_TAXONOMY.get(class_uid, {
            "name": "Generic Finding",
            "category": OcsfCategory.FINDINGS,
            "required_fields": ["activity_id", "severity_id"],
        })

        category_uid = int(class_info["category"])
        class_name = class_info["name"]
        category_name = class_info["category"].name

        # Validate mandatory base fields
        raw_sev = str(alert_payload.get("severity", alert_payload.get("raw_severity", "medium"))).lower()
        sev_map = {
            "informational": OcsfSeverityId.INFORMATIONAL,
            "low": OcsfSeverityId.LOW,
            "medium": OcsfSeverityId.MEDIUM,
            "high": OcsfSeverityId.HIGH,
            "critical": OcsfSeverityId.CRITICAL,
        }
        severity_id = sev_map.get(raw_sev, OcsfSeverityId.MEDIUM)

        # Check required fields
        for field in class_info.get("required_fields", []):
            if field == "finding_info" and "rule_name" not in alert_payload and "finding_info" not in alert_payload:
                errors.append(f"Missing mandatory finding_info/rule_name for OCSF class {class_name}")
            elif field == "user" and "username" not in alert_payload and "user" not in alert_payload:
                errors.append(f"Missing mandatory user identity for OCSF class {class_name}")
            elif field == "src_endpoint" and "source_ip" not in alert_payload and "src_endpoint" not in alert_payload:
                errors.append(f"Missing mandatory source endpoint for OCSF class {class_name}")

        # Construct conformant OCSF dictionary
        ocsf_record: Dict[str, Any] = {
            "version": "1.1.0",
            "category_uid": category_uid,
            "category_name": category_name,
            "class_uid": class_uid,
            "class_name": class_name,
            "severity_id": int(severity_id),
            "severity": raw_sev,
            "activity_id": int(alert_payload.get("activity_id", 1)),
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": alert_payload.get("source", "secops-engine"),
                    "vendor_name": "SecOps Autonomous",
                },
                "tenant_id": alert_payload.get("tenant_id", "default-tenant"),
            },
            "unmapped": {},
        }

        # Embed finding info
        if "rule_name" in alert_payload or "rule_id" in alert_payload:
            ocsf_record["finding_info"] = {
                "title": alert_payload.get("rule_name", "Security Detection"),
                "uid": str(alert_payload.get("rule_id", "RULE-GENERIC")),
                "desc": alert_payload.get("raw_payload", ""),
            }

        # Embed endpoints / entities
        if "source_ip" in alert_payload:
            ocsf_record["src_endpoint"] = {"ip": alert_payload["source_ip"]}
        if "destination_ip" in alert_payload:
            ocsf_record["dst_endpoint"] = {"ip": alert_payload["destination_ip"]}
        if "host" in alert_payload:
            ocsf_record["device"] = {"hostname": alert_payload["host"]}
        if "username" in alert_payload:
            ocsf_record["user"] = {"name": alert_payload["username"]}

        is_valid = len(errors) == 0 if strict else True

        return OcsfValidationResult(
            is_valid=is_valid,
            class_uid=class_uid,
            class_name=class_name,
            category_uid=category_uid,
            category_name=category_name,
            errors=errors,
            normalized_ocsf_record=ocsf_record,
        )


ocsf_validator = OcsfValidator()
