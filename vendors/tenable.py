#!/usr/bin/env python3
"""
Tenable.io adapter: pulls /vulns/export ONCE (state OPEN+REOPENED+FIXED,
all severities, no last_found bound at the API level — staleness policy is
applied later, uniformly, at rollup time via reporting.days_last_seen so
raw history isn't discarded at ingest), classifies each finding via the
shared cvss/sites/product_classify modules, and yields NormalizedFinding
rows. Also accumulates the plugin/CVE catalog in the same pass (previously
a separate, redundant Tenable export in tenable_product_drivers.py).
"""
import datetime as dt
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests

import cvss
import sites as sites_mod
import product_classify

from vendors.base import NormalizedFinding


# ------------------------------------------------------------
#  TENABLE API HELPERS
# ------------------------------------------------------------

def tenable_session(base_url: str, access_key: str, secret_key: str) -> requests.Session:
    s = requests.Session()
    s.base_url = base_url.rstrip("/")
    s.headers.update({
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s


def start_export(sess: requests.Session, filters: Dict[str, Any]) -> str:
    payload = {"filters": filters, "include_unlicensed": True}
    resp = sess.post(f"{sess.base_url}/vulns/export", data=json.dumps(payload))
    if resp.status_code != 200:
        raise RuntimeError(f"Export start failed: {resp.status_code}, {resp.text}")

    data = resp.json()
    export_uuid = data.get("export_uuid") or data.get("uuid")
    if not export_uuid:
        raise RuntimeError(f"Export UUID missing: {data}")

    print(f"[tenable] Export started: {export_uuid}")
    return export_uuid


def poll_export(sess: requests.Session, uuid: str, interval: int = 10) -> Dict[str, Any]:
    url = f"{sess.base_url}/vulns/export/{uuid}/status"
    start = time.time()

    while True:
        resp = sess.get(url)
        resp.raise_for_status()
        status = resp.json()

        elapsed = int(time.time() - start)
        print(
            f"[tenable] poll {uuid} status={status.get('status')} "
            f"chunks={status.get('chunks_available')} elapsed={elapsed}s"
        )

        if status.get("status") == "FINISHED":
            print("[tenable] Export complete.")
            return status

        if status.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Export failed: {status}")

        time.sleep(interval)


def iter_chunks(sess: requests.Session, uuid: str, chunks) -> Iterable[Dict[str, Any]]:
    for chunk in chunks:
        resp = sess.get(f"{sess.base_url}/vulns/export/{uuid}/chunks/{chunk}")
        resp.raise_for_status()
        data = resp.json()
        vulns = data if isinstance(data, list) else data.get("vulnerabilities", data)
        for v in vulns:
            yield v


def fetch_all_asset_tags(sess: requests.Session) -> Dict[str, Any]:
    """
    Export all assets with tags. Returns dict: asset_uuid -> tags
    """
    print("[tenable] Exporting asset list (tags included)...")

    resp = sess.post(
        f"{sess.base_url}/assets/export",
        json={"include_attributes": ["tags"], "chunk_size": 5000},
    )
    resp.raise_for_status()
    data = resp.json()
    uuid = data.get("export_uuid")
    if not uuid:
        raise RuntimeError(f"Asset export UUID missing: {data}")

    while True:
        status = sess.get(f"{sess.base_url}/assets/export/{uuid}/status").json()
        if status.get("status") == "FINISHED":
            break
        if status.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Asset export failed: {status}")
        print("[tenable] poll-assets status=", status.get("status"))
        time.sleep(2)

    chunks = status.get("chunks_available", [])
    print(f"[tenable] Asset export ready ({len(chunks)} chunks)")

    asset_tags: Dict[str, Any] = {}
    for c in chunks:
        chunk = sess.get(f"{sess.base_url}/assets/export/{uuid}/chunks/{c}").json()
        assets = chunk if isinstance(chunk, list) else chunk.get("assets", chunk)
        for a in assets:
            aid = a.get("id") or a.get("uuid")
            tags = a.get("tags") or []
            if aid:
                asset_tags[aid] = tags

    print(f"[tenable] Loaded {len(asset_tags)} assets with tag data.")
    return asset_tags


# ------------------------------------------------------------
#  TENABLE-SPECIFIC CVSS FIELD EXTRACTION
#  (key names are Tenable's plugin payload shape; the parsing/scoring
#  logic itself lives in cvss.py and is vendor-agnostic)
# ------------------------------------------------------------

def _get_cvss_vector_string(plugin: Dict[str, Any]) -> Optional[str]:
    if not plugin:
        return None

    candidate_keys = [
        "cvss4_vector", "cvss4_temporal_vector",
        "cvss3_vector", "cvss3_temporal_vector",
        "cvssv3_vector", "cvssv3_temporal_vector",
        "cvss_vector", "cvss_temporal_vector",
        "cvss2_vector", "cvss2_temporal_vector",
        "cvssv2_vector", "cvssv2_temporal_vector",
    ]

    for key in candidate_keys:
        val = plugin.get(key)
        if not val:
            continue
        if isinstance(val, dict):
            vec = (
                val.get("raw") or val.get("vector") or val.get("base_vector")
                or val.get("v4_vector") or val.get("v3_vector") or val.get("v2_vector")
            )
            if vec:
                return str(vec)
        else:
            return str(val)

    cvss_dict = plugin.get("cvss") or {}
    if isinstance(cvss_dict, dict):
        vec = (
            cvss_dict.get("raw") or cvss_dict.get("vector") or cvss_dict.get("base_vector")
            or cvss_dict.get("v4_vector") or cvss_dict.get("v3_vector") or cvss_dict.get("v2_vector")
        )
        if vec:
            return str(vec)

    return None


def _get_cvss_score(plugin: Dict[str, Any]) -> Optional[float]:
    for key in (
        "cvss4_base_score", "cvss4_score",
        "cvss3_base_score", "cvss3_score",
        "cvss_base_score", "cvss_score",
        "cvss2_base_score", "cvss2_score",
    ):
        v = plugin.get(key)
        if v is None:
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    return None


def _epoch_to_dt(value: Any) -> Optional[dt.datetime]:
    """
    Tenable has returned timestamps as either epoch integers or ISO8601
    strings depending on API version/tenant -- accept both rather than
    silently failing on whichever one we didn't guess.
    """
    if value is None:
        return None
    try:
        return dt.datetime.fromtimestamp(int(value), tz=dt.timezone.utc)
    except (TypeError, ValueError):
        pass
    if isinstance(value, str):
        try:
            s = value.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            parsed = dt.datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except ValueError:
            return None
    return None


def _extract_cves(plugin: Dict[str, Any]) -> List[str]:
    c = plugin.get("cve") or plugin.get("cves") or []
    if isinstance(c, str):
        c = [c]
    return [x for x in c if str(x).startswith("CVE-")]


def _extract_hostname(asset: Dict[str, Any]) -> Optional[str]:
    hostnames = asset.get("hostname") or asset.get("hostnames") or []
    if isinstance(hostnames, str):
        return hostnames
    if isinstance(hostnames, list):
        for h in hostnames:
            if h:
                return str(h)
    return asset.get("fqdn")


def _extract_port_protocol(finding: Dict[str, Any]) -> Tuple[int, str]:
    port_obj = finding.get("port")
    if isinstance(port_obj, dict):
        port = port_obj.get("port") or 0
        protocol = port_obj.get("protocol") or ""
    else:
        port = port_obj or 0
        protocol = finding.get("protocol") or ""
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    return port, str(protocol)


# ------------------------------------------------------------
#  ADAPTER ENTRYPOINT
# ------------------------------------------------------------

def fetch_findings(
    cfg: Dict[str, Any]
) -> Tuple[List[NormalizedFinding], Dict[int, Dict[str, Any]], Dict[int, Set[str]]]:
    ten_cfg = cfg["tenable"]
    sess = tenable_session(ten_cfg["base_url"], ten_cfg["access_key"], ten_cfg["secret_key"])

    reporting = cfg.get("reporting", {})
    tag_cfg = cfg.get("tags", {})
    require_exploit_flag = reporting.get("require_exploit_for_remote_no_auth", True)

    site_cfg = {s["key"]: s["label"] for s in cfg.get("sites", [])}
    ungrouped = cfg.get("ungrouped_label", "Ungrouped")

    label_to_tag = {v: k for k, v in site_cfg.items()}

    asset_tags = fetch_all_asset_tags(sess)

    filters = {
        "state": ["OPEN", "REOPENED", "FIXED"],
        "severity": ["low", "medium", "high", "critical"],
    }

    uuid = start_export(sess, filters)
    status = poll_export(sess, uuid)
    chunks = status.get("chunks_available") or []

    findings: List[NormalizedFinding] = []
    plugin_meta: Dict[int, Dict[str, Any]] = {}
    plugin_cves: Dict[int, Set[str]] = {}

    total_seen = 0
    total_kept = 0
    dropped_no_rule_id = 0
    dropped_no_severity = 0
    first_dropped_sample: Optional[Dict[str, Any]] = None

    for f in iter_chunks(sess, uuid, chunks):
        total_seen += 1

        plugin = f.get("plugin", {}) or {}

        # Plugin/rule id: used as the finding's dedup key (kept as a string,
        # so it doesn't need to be numeric) and, separately, as the plugin
        # catalog's dict key (needs int -- see pid_int below). A finding
        # with no rule id at all can't be identified, so it's the one
        # thing that's still a hard drop.
        rule_id_raw = plugin.get("id") or plugin.get("plugin_id") or f.get("plugin_id")
        if rule_id_raw is None:
            dropped_no_rule_id += 1
            if first_dropped_sample is None:
                first_dropped_sample = f
            continue

        try:
            pid_int: Optional[int] = int(rule_id_raw)
        except (TypeError, ValueError):
            pid_int = None

        score = _get_cvss_score(plugin)
        vector = _get_cvss_vector_string(plugin)
        severity = cvss.severity_band_from_score(score)
        if not severity:
            severity = cvss.classify_severity_fallback(
                f.get("severity") if f.get("severity") is not None else f.get("severity_id")
            )
        if not severity:
            dropped_no_severity += 1
            if first_dropped_sample is None:
                first_dropped_sample = f
            continue

        asset = f.get("asset", {}) or {}
        sid = asset.get("uuid") or asset.get("id")
        tags = asset_tags.get(sid, [])

        label = sites_mod.site_label(tags, site_cfg, tag_cfg, ungrouped)
        atype = sites_mod.asset_type(tags, tag_cfg)
        site_tag = label_to_tag.get(label, "UNGROUPED" if label == ungrouped else label)

        product_key = product_classify.product_key_from_cpe(plugin)
        cls = product_classify.classify_product(product_key)

        remote = cvss.is_remote_no_auth(
            vector,
            exploit_available=plugin.get("exploit_available"),
            exploitability_ease=plugin.get("exploitability_ease"),
            require_exploit=require_exploit_flag,
        )

        state = (f.get("state") or "").upper()
        first_found = _epoch_to_dt(f.get("first_found") or f.get("first_seen"))
        last_found = _epoch_to_dt(f.get("last_found") or f.get("last_seen")) or first_found
        if first_found is None:
            first_found = last_found
        now = dt.datetime.now(dt.timezone.utc)
        if last_found is None:
            last_found = now
        if first_found is None:
            first_found = last_found or now

        last_fixed = None
        if state == "FIXED":
            last_fixed = _epoch_to_dt(f.get("last_fixed")) or last_found

        port, protocol = _extract_port_protocol(f)
        cves = _extract_cves(plugin)

        nf = NormalizedFinding(
            source="tenable",
            source_asset_id=str(sid) if sid else "unknown",
            source_rule_id=str(rule_id_raw),
            state=state,
            severity=severity,
            first_found=first_found,
            last_found=last_found,
            site_label=label,
            port=port,
            protocol=protocol,
            cvss_score=score,
            cvss_vector=vector,
            title=plugin.get("name"),
            plugin_family=plugin.get("family"),
            synopsis=plugin.get("synopsis"),
            solution=plugin.get("solution"),
            is_remote_no_auth=remote,
            exploit_available=plugin.get("exploit_available"),
            exploited_by_malware=plugin.get("exploited_by_malware"),
            has_patch=bool(plugin.get("patch_publication_date")),
            patch_published=_epoch_to_dt(plugin.get("patch_publication_date")),
            product_key=product_key,
            product_vendor=cls.get("vendor"),
            product_family=cls.get("family"),
            site_tag=site_tag,
            asset_type=atype,
            hostname=_extract_hostname(asset),
            last_fixed=last_fixed,
            cves=cves,
        )
        findings.append(nf)
        total_kept += 1

        # Plugin catalog side-channel is best-effort: skip it (not the
        # whole finding) if this particular rule id isn't numeric.
        if pid_int is not None:
            plugin_meta.setdefault(pid_int, {
                "plugin_id": pid_int,
                "plugin_name": plugin.get("name"),
                "plugin_family": plugin.get("family"),
                "plugin_type": plugin.get("type"),
                "vendor": cls.get("vendor"),
                "product": product_key,
                "product_family": cls.get("family"),
                "synopsis": plugin.get("synopsis"),
                "description": plugin.get("description"),
                "solution": plugin.get("solution"),
                "see_also": plugin.get("see_also"),
                "cvss3_base": plugin.get("cvss3_base_score"),
                "cvss3_vector": plugin.get("cvss3_vector"),
                "exploit_available": plugin.get("exploit_available"),
                "exploited_by_malware": plugin.get("exploited_by_malware"),
                "has_patch": bool(plugin.get("patch_publication_date")),
                "patch_published": plugin.get("patch_publication_date"),
            })
            if cves:
                plugin_cves.setdefault(pid_int, set()).update(cves)

    print(
        f"[tenable] Findings processed: {total_seen}, kept: {total_kept}, "
        f"dropped (no rule id): {dropped_no_rule_id}, "
        f"dropped (no severity): {dropped_no_severity}"
    )

    if total_seen > 0 and total_kept == 0 and first_dropped_sample is not None:
        print("[tenable] WARNING: 0 findings kept out of a non-empty export. "
              "Dumping the first dropped finding's raw JSON for troubleshooting:")
        print(json.dumps(first_dropped_sample, indent=2, default=str)[:4000])

    return findings, plugin_meta, plugin_cves
