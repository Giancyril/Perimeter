"""
Webhook Security & Authentication Module.
Provides HMAC-SHA256 signature verification, replay attack prevention via timestamp drift checks,
and dual-key secret rotation support.
"""
import hmac
import hashlib
import time
from typing import Optional, List, Dict, Tuple


class WebhookSecurityManager:
    """
    Enforces HMAC-SHA256 signature verification and timestamp freshness on incoming SIEM webhooks.
    Supports seamless secret rotation by validating against a primary secret and optional secondary/fallback secrets.
    """

    def __init__(
        self,
        primary_secret: str = "",
        fallback_secrets: Optional[List[str]] = None,
        max_drift_seconds: int = 300,
    ):
        self.primary_secret = primary_secret
        self.fallback_secrets = fallback_secrets or []
        self.max_drift_seconds = max_drift_seconds

    def sign_payload(self, payload_bytes: bytes, secret: Optional[str] = None, timestamp: Optional[int] = None) -> Tuple[str, int]:
        """
        Generates HMAC-SHA256 signature string: t=<timestamp>,v1=<hex_signature>
        """
        ts = timestamp if timestamp is not None else int(time.time())
        key = (secret if secret is not None else self.primary_secret).encode("utf-8")
        signed_data = f"{ts}.".encode("utf-8") + payload_bytes
        signature = hmac.new(key, signed_data, hashlib.sha256).hexdigest()
        return f"t={ts},v1={signature}", ts

    def verify_signature(
        self,
        payload_bytes: bytes,
        signature_header: Optional[str],
        timestamp_header: Optional[str] = None,
        current_time: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Validates the incoming signature header against primary and fallback secrets.
        Checks for:
        1. Presence of signature header (if secrets configured).
        2. Timestamp freshness (within max_drift_seconds) to prevent replay attacks.
        3. Constant-time HMAC match against configured secrets.
        """
        secrets = [s for s in [self.primary_secret] + self.fallback_secrets if s]
        if not secrets:
            # If no webhook secrets are configured, signature enforcement is inactive
            return True, "No webhook secret configured; signature validation bypassed"

        if not signature_header:
            return False, "Missing required webhook signature header ('X-SecOps-Signature')"

        now = current_time if current_time is not None else int(time.time())

        # Support two header formats:
        # 1. Stripe/Slack style: "t=1727780000,v1=abc123def..."
        # 2. Direct hex with separate 'X-SecOps-Timestamp' header
        parsed_ts: Optional[int] = None
        extracted_sig: Optional[str] = None

        if "t=" in signature_header and "v1=" in signature_header:
            parts = signature_header.split(",")
            for part in parts:
                k_v = part.strip().split("=", 1)
                if len(k_v) == 2:
                    k, v = k_v
                    if k == "t" and v.isdigit():
                        parsed_ts = int(v)
                    elif k == "v1":
                        extracted_sig = v
        else:
            extracted_sig = signature_header.strip()
            if timestamp_header and timestamp_header.isdigit():
                parsed_ts = int(timestamp_header)

        # Check timestamp freshness if provided
        if parsed_ts is not None:
            drift = abs(now - parsed_ts)
            if drift > self.max_drift_seconds:
                return False, f"Timestamp drift exceeds limit: {drift}s > {self.max_drift_seconds}s"
        else:
            # If timestamp wasn't in signature, check if separate timestamp header was provided
            if timestamp_header and timestamp_header.isdigit():
                drift = abs(now - int(timestamp_header))
                if drift > self.max_drift_seconds:
                    return False, f"Timestamp drift exceeds limit: {drift}s > {self.max_drift_seconds}s"
            parsed_ts = now

        if not extracted_sig:
            return False, "Malformed signature header format"

        # Validate against each secret (primary + rotation fallbacks)
        signed_data = f"{parsed_ts}.".encode("utf-8") + payload_bytes
        for sec in secrets:
            expected_hmac = hmac.new(sec.encode("utf-8"), signed_data, hashlib.sha256).hexdigest()
            # Also support payload-only HMAC without timestamp prefix for legacy SIEMs
            payload_only_hmac = hmac.new(sec.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

            if hmac.compare_digest(expected_hmac, extracted_sig) or hmac.compare_digest(payload_only_hmac, extracted_sig):
                return True, "Valid signature"

        return False, "Invalid signature: HMAC-SHA256 digest mismatch"


webhook_security_manager = WebhookSecurityManager()
