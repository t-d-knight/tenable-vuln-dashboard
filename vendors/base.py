#!/usr/bin/env python3
"""
Vendor adapter contract. Any source (Tenable, future CrowdStrike Falcon
Exposure Management, Intune, ...) implements fetch_findings(cfg) and yields
NormalizedFinding rows in this shape. ingest_findings.py upserts whatever
comes out of this into the vendor-agnostic vuln_findings table, so this
dataclass IS the seam a new adapter needs to fill.
"""
import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class NormalizedFinding:
    source: str                    # 'tenable', future: 'crowdstrike_em', 'intune'
    source_asset_id: str
    source_rule_id: str
    state: str                     # 'OPEN' | 'REOPENED' | 'FIXED'
    severity: str                  # 'critical' | 'high' | 'medium' | 'low'
    first_found: dt.datetime
    last_found: dt.datetime
    site_label: str

    port: int = 0
    protocol: str = ""

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    title: Optional[str] = None
    plugin_family: Optional[str] = None
    synopsis: Optional[str] = None
    solution: Optional[str] = None

    is_remote_no_auth: bool = False
    exploit_available: Optional[bool] = None
    exploited_by_malware: Optional[bool] = None
    has_patch: Optional[bool] = None
    patch_published: Optional[dt.datetime] = None

    product_key: Optional[str] = None
    product_vendor: Optional[str] = None
    product_family: Optional[str] = None

    site_tag: Optional[str] = None
    asset_type: Optional[str] = None
    hostname: Optional[str] = None

    last_fixed: Optional[dt.datetime] = None

    cves: List[str] = field(default_factory=list)


class VendorAdapter(Protocol):
    def fetch_findings(
        self, cfg: Dict[str, Any]
    ) -> "tuple[List[NormalizedFinding], Dict[int, Dict[str, Any]], Dict[int, set]]":
        """
        Returns (findings, plugin_meta, plugin_cves):
          - findings: normalized rows for vuln_findings/vuln_finding_cves
          - plugin_meta: plugin_id -> plugin_metadata row dict (side channel,
            may be empty for vendors with no equivalent catalog concept)
          - plugin_cves: plugin_id -> set of CVE strings (side channel)
        """
        ...
