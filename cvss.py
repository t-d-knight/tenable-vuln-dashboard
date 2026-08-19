#!/usr/bin/env python3
"""
Vendor-agnostic CVSS parsing, severity banding, remote/no-auth classification,
and SLA logic. Operates on primitives (vector strings, scores, flags) rather
than any one vendor's raw payload shape, so any adapter can extract its own
vendor-specific fields and hand them to these functions.
"""
import time
from typing import Any, Dict, Optional


def parse_cvss_vector(vector: Optional[str]) -> Dict[str, str]:
    """
    Normalise a CVSS v2 / v3 / v4 vector string into a dict of metrics.
    """
    if not vector or not isinstance(vector, str):
        return {}

    if vector.startswith("CVSS:"):
        parts = vector.split("/")[1:]
    else:
        parts = vector.split("/")

    out: Dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        out[k] = v
    return out


def severity_band_from_score(score: Optional[float]) -> Optional[str]:
    """
    Map a CVSS base score to 'critical'/'high'/'medium'/'low'.
    """
    if score is None or score <= 0:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def classify_severity_fallback(sev_raw: Any) -> Optional[str]:
    """
    Normalise a vendor's own severity label/ordinal to one of:
    critical, high, medium, low. Used when no CVSS score is available.
    """
    try:
        s = int(sev_raw)
        return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: None}.get(s)
    except (TypeError, ValueError):
        pass

    if isinstance(sev_raw, str):
        s = sev_raw.strip().lower()
        if s in ("critical", "high", "medium", "low"):
            return s

    return None


def is_remote_no_auth(
    vector: Optional[str],
    *,
    exploit_available: Any = None,
    exploitability_ease: Optional[str] = None,
    require_exploit: bool = True,
) -> bool:
    """
    Decide if a vulnerability is 'remote, no-auth' based on a CVSS vector
    (v2, v3, or v4). Optionally require a known exploit to reduce noise.
    """
    m = parse_cvss_vector(vector)
    if not m:
        return False

    av = m.get("AV")
    pr = m.get("PR")
    au = m.get("Au")  # CVSS v2

    remote = av in ("N", "A")
    noauth = (pr == "N") or (au == "N")

    if not (remote and noauth):
        return False

    if not require_exploit:
        return True

    ease = (exploitability_ease or "").lower()
    return bool(exploit_available) or ("no known" not in ease)


def sla_days(risk: str) -> int:
    return {"critical": 2, "high": 14, "medium": 30, "low": 60}.get(
        (risk or "").lower(), 60
    )


def age_days(epoch_seconds: Any) -> float:
    if epoch_seconds is None:
        return 0.0
    try:
        epoch_seconds = int(epoch_seconds)
    except (TypeError, ValueError):
        return 0.0
    return (int(time.time()) - epoch_seconds) / 86400.0
