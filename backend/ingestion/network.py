"""
Network Address Classification & Metadata Enrichment Module.
Provides high-performance CIDR evaluation and scope classification:
- RFC1918 Private Enterprise Ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- RFC6598 Shared Address Space / CGNAT (100.64.0.0/10)
- RFC1122 / RFC4291 Loopback (127.0.0.0/8, ::1)
- RFC3927 Link-Local (169.254.0.0/16, fe80::/10)
- RFC5771 Multicast & Reserved Bogon Networks
- Public Routable IP classification (threat intel candidate gatekeeper)
"""
import ipaddress
from enum import Enum
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel


class IpScope(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private_rfc1918"
    CGNAT = "cgnat_rfc6598"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    BOGON_RESERVED = "bogon_reserved"
    INVALID = "invalid"


class IpClassification(BaseModel):
    ip: str
    is_valid: bool
    version: int = 4
    scope: IpScope
    is_routable: bool
    is_threat_intel_eligible: bool
    asn_placeholder: Optional[str] = None
    country_code: Optional[str] = None


class NetworkClassifier:
    """Classifies IPv4 and IPv6 addresses into standard IETF/IANA security scopes."""

    @staticmethod
    def classify_ip(ip_str: Optional[str]) -> IpClassification:
        if not ip_str or not isinstance(ip_str, str):
            return IpClassification(
                ip="",
                is_valid=False,
                version=4,
                scope=IpScope.INVALID,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        cleaned = ip_str.strip()
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return IpClassification(
                ip=cleaned,
                is_valid=False,
                version=4,
                scope=IpScope.INVALID,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        version = addr.version

        # Loopback
        if addr.is_loopback:
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.LOOPBACK,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # Link Local
        if addr.is_link_local:
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.LINK_LOCAL,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # Multicast
        if addr.is_multicast:
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.MULTICAST,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # Reserved / Unspecified
        if addr.is_reserved or addr.is_unspecified:
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.BOGON_RESERVED,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # RFC6598 CGNAT (100.64.0.0/10)
        if version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.CGNAT,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # Private RFC1918
        if addr.is_private:
            return IpClassification(
                ip=cleaned,
                is_valid=True,
                version=version,
                scope=IpScope.PRIVATE,
                is_routable=False,
                is_threat_intel_eligible=False,
            )

        # Public Global Routable IP (Eligible for AbuseIPDB / VirusTotal lookup)
        return IpClassification(
            ip=cleaned,
            is_valid=True,
            version=version,
            scope=IpScope.PUBLIC,
            is_routable=True,
            is_threat_intel_eligible=True,
        )


network_classifier = NetworkClassifier()
