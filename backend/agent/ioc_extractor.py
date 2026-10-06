"""
Multi-Modal IOC Extractor.
Extracts IPs, domains, URLs, file hashes (MD5/SHA1/SHA256), emails, CVEs,
registry keys, file paths, process names and usernames from every observable
surface of a NormalizedAlert with tiered confidence (HIGH / MEDIUM / LOW).
"""
from __future__ import annotations
import re
from enum import Enum
from typing import Dict, List, Set
from backend.ingestion.models import EntityType, NormalizedAlert


class IOCType(str, Enum):
    IP_ADDRESS    = "ip_address"
    DOMAIN        = "domain"
    URL           = "url"
    FILE_HASH_MD5  = "hash_md5"
    FILE_HASH_SHA1 = "hash_sha1"
    FILE_HASH_SHA256 = "hash_sha256"
    EMAIL         = "email"
    CVE           = "cve"
    REGISTRY_KEY  = "registry_key"
    FILE_PATH     = "file_path"
    PROCESS_NAME  = "process_name"
    USERNAME      = "username"


class IOCConfidence(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class ExtractedIOC:
    __slots__ = ("ioc_type", "value", "confidence", "source")
    def __init__(self, ioc_type, value, confidence, source):
        self.ioc_type   = ioc_type
        self.value      = value.strip()
        self.confidence = confidence
        self.source     = source
    def to_dict(self) -> Dict[str, str]:
        return {"type": self.ioc_type.value, "value": self.value,
                "confidence": self.confidence.value, "source": self.source}


IGNORABLE_IPS = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255", "::1"})
_RE_IPV4    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_DOMAIN  = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|edu|gov|co|info|biz|me|dev|app|xyz|ru|cn|tk|cc|top)\b", re.IGNORECASE)
_RE_URL     = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&()*+,;=%]+", re.IGNORECASE)
_RE_SHA256  = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1    = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5     = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_EMAIL   = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_CVE     = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_REG     = re.compile(r"(?:HKEY_|HK(?:LM|CU|CR|U|CC))\\[\w\\]+", re.IGNORECASE)
_RE_WIN     = re.compile(r"[A-Za-z]:\\(?:[^\\/:\*\?<>|\r\n]+\\)*[^\\/:\*\?<>|\r\n]*")
_RE_UNIX    = re.compile(r"(?:/[\w.\-]+){2,}")


def _extract(text: str, label: str, conf: IOCConfidence) -> List[ExtractedIOC]:
    out: List[ExtractedIOC] = []
    seen: Set[str] = set()
    def add(t, v):
        k = f"{t.value}:{v.lower()}"
        if k not in seen:
            seen.add(k); out.append(ExtractedIOC(t, v, conf, label))
    for m in _RE_URL.findall(text):    add(IOCType.URL, m)
    for m in _RE_SHA256.findall(text): add(IOCType.FILE_HASH_SHA256, m.lower())
    for m in _RE_SHA1.findall(text):   add(IOCType.FILE_HASH_SHA1, m.lower())
    for m in _RE_MD5.findall(text):
        if len(m) == 32:               add(IOCType.FILE_HASH_MD5, m.lower())
    for m in _RE_IPV4.findall(text):
        if m not in IGNORABLE_IPS:     add(IOCType.IP_ADDRESS, m)
    for m in _RE_DOMAIN.findall(text): add(IOCType.DOMAIN, m.lower())
    for m in _RE_EMAIL.findall(text):  add(IOCType.EMAIL, m.lower())
    for m in _RE_CVE.findall(text):   add(IOCType.CVE, m.upper())
    for m in _RE_REG.findall(text):   add(IOCType.REGISTRY_KEY, m)
    for m in _RE_WIN.findall(text):   add(IOCType.FILE_PATH, m)
    for m in _RE_UNIX.findall(text):
        if len(m) > 4:                add(IOCType.FILE_PATH, m)
    return out


class IOCExtractor:
    """Extracts and deduplicates IOCs across all alert surfaces."""
    def extract(self, alert: NormalizedAlert) -> List[Dict[str, str]]:
        iocs: List[ExtractedIOC] = []
        seen: Set[str] = set()
        def merge(lst):
            for ioc in lst:
                k = f"{ioc.ioc_type.value}:{ioc.value.lower()}"
                if k not in seen:
                    seen.add(k); iocs.append(ioc)
        for ent in alert.entities:
            if   ent.type == EntityType.IP and ent.value not in IGNORABLE_IPS:
                merge([ExtractedIOC(IOCType.IP_ADDRESS, ent.value, IOCConfidence.HIGH, "entity")])
            elif ent.type == EntityType.DOMAIN:
                merge([ExtractedIOC(IOCType.DOMAIN, ent.value, IOCConfidence.HIGH, "entity")])
            elif ent.type == EntityType.USER:
                merge([ExtractedIOC(IOCType.USERNAME, ent.value, IOCConfidence.HIGH, "entity")])
        if alert.file_hash:
            hlen = len(alert.file_hash.strip())
            t = IOCType.FILE_HASH_SHA256 if hlen == 64 else (IOCType.FILE_HASH_SHA1 if hlen == 40 else IOCType.FILE_HASH_MD5)
            merge([ExtractedIOC(t, alert.file_hash.strip(), IOCConfidence.HIGH, "file_hash_field")])
        if alert.source_ip      and alert.source_ip      not in IGNORABLE_IPS:
            merge([ExtractedIOC(IOCType.IP_ADDRESS, alert.source_ip,      IOCConfidence.HIGH, "source_ip")])
        if alert.destination_ip and alert.destination_ip not in IGNORABLE_IPS:
            merge([ExtractedIOC(IOCType.IP_ADDRESS, alert.destination_ip, IOCConfidence.HIGH, "dest_ip")])
        if alert.process_name:
            merge([ExtractedIOC(IOCType.PROCESS_NAME, alert.process_name, IOCConfidence.HIGH, "process_name")])
        merge(_extract(f"{alert.rule_name} {alert.rule_description}", "rule", IOCConfidence.MEDIUM))
        if alert.raw_payload:
            merge(_extract(" ".join(str(v) for v in alert.raw_payload.values()), "raw_payload", IOCConfidence.LOW))
        return [i.to_dict() for i in iocs]

    def extract_batch(self, alerts):
        return {a.alert_id: self.extract(a) for a in alerts}


ioc_extractor = IOCExtractor()
