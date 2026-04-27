"""
Indicator normalization for the ingestion pipeline.

All feed workers produce raw indicator dicts; the normalizer
validates and canonicalizes them before they are published to NATS.
"""
import ipaddress
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Hash length validation
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def normalize_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_domain(value: str) -> Optional[str]:
    cleaned = value.strip().lower().lstrip("*.@")
    if not cleaned or len(cleaned) > 253:
        return None
    # Must contain at least one dot, no spaces, no slashes
    if "." not in cleaned or " " in cleaned or "/" in cleaned:
        return None
    # Reject obvious non-domains
    if cleaned.startswith("-") or cleaned.endswith("-"):
        return None
    return cleaned


def normalize_url(value: str) -> Optional[str]:
    v = value.strip()
    if not v:
        return None
    # Ensure scheme is present
    if not v.startswith(("http://", "https://", "ftp://")):
        v = "http://" + v
    if len(v) > 2048:
        return None
    return v


def normalize_hash(value: str, hash_type: str) -> Optional[str]:
    v = value.strip().lower()
    expected = HASH_LENGTHS.get(hash_type)
    if expected and len(v) != expected:
        return None
    if not HEX_RE.match(v):
        return None
    return v


def normalize_email(value: str) -> Optional[str]:
    v = value.strip().lower()
    if "@" not in v or len(v) > 320:
        return None
    return v


NORMALIZERS = {
    "ip":     normalize_ip,
    "domain": normalize_domain,
    "url":    normalize_url,
    "md5":    lambda v: normalize_hash(v, "md5"),
    "sha1":   lambda v: normalize_hash(v, "sha1"),
    "sha256": lambda v: normalize_hash(v, "sha256"),
    "sha512": lambda v: normalize_hash(v, "sha512"),
    "email":  normalize_email,
}


def normalize(itype: str, value: str) -> Optional[str]:
    """
    Return the normalized form of an indicator value.
    Returns None if the value is invalid for the given type.
    """
    fn = NORMALIZERS.get(itype)
    if fn is None:
        logger.debug("No normalizer for type %r, using stripped value", itype)
        return value.strip() or None
    result = fn(value)
    if result is None:
        logger.debug("Normalization failed: type=%r value=%r", itype, value[:80])
    return result
