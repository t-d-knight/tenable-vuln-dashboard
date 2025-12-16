#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import time
from typing import Dict, Any, Iterable, Tuple, Optional, Set, List
import re

import requests
import yaml

try:
    import psycopg2
except ImportError:
    psycopg2 = None


# ------------------------------------------------------------
#  CONFIG + PRODUCT RULES
# ------------------------------------------------------------

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = os.path.dirname(os.path.abspath(path))
        secrets_path = os.path.join(base_dir, secrets_rel)
        if not os.path.isfile(secrets_path):
            raise FileNotFoundError(f"Secrets file not found: {secrets_path}")

        with open(secrets_path, "r") as sf:
            secrets = yaml.safe_load(sf) or {}

        if "tenable" in secrets:
            cfg.setdefault("tenable", {})
            cfg["tenable"].update(secrets["tenable"])

        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

    return cfg


def load_product_rules(path: str = "product_groups.yaml") -> Dict[str, Any]:
    if not os.path.isfile(path):
        print(f"[warn] product_groups.yaml not found at {path}, all products will be 'Other / Misc'")
        return {"rules": [], "defaults": {"unknown_family_name": "Other / Misc", "vendor_from_prefix": True}}

    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}

    data.setdefault("rules", [])
    data.setdefault("defaults", {})
    data["defaults"].setdefault("unknown_family_name", "Other / Misc")
    data["defaults"].setdefault("vendor_from_prefix", True)
    return data


PRODUCT_RULES = load_product_rules()


def classify_product(product_key: str) -> Dict[str, str]:
    pk_norm = (product_key or "").lower()
    rules = PRODUCT_RULES.get("rules", [])
    family = None

    # PASS 1: rules with explicit `match`
    for r in rules:
        match_type = r.get("match")
        label = r.get("name") or r.get("family")
        if not label or not match_type:
            continue

        pat = r.get("pattern")
        patterns = r.get("patterns", [])

        if match_type == "contains":
            if isinstance(pat, list):
                if any(str(p).lower() in pk_norm for p in pat):
                    family = label
                    break
            else:
                if pat and str(pat).lower() in pk_norm:
                    family = label
                    break

        elif match_type == "startswith":
            if isinstance(pat, list):
                if any(pk_norm.startswith(str(p).lower()) for p in pat):
                    family = label
                    break
            else:
                if pat and pk_norm.startswith(str(pat).lower()):
                    family = label
                    break

        elif match_type == "contains_any":
            if any(str(p).lower() in pk_norm for p in patterns):
                family = label
                break

        elif match_type == "startswith_any":
            if any(pk_norm.startswith(str(p).lower()) for p in patterns):
                family = label
                break

        elif match_type == "regex" and pat:
            if re.search(str(pat), product_key or ""):
                family = label
                break

    # PASS 2: rules with `match_any`
    if not family:
        for r in rules:
            label = r.get("family") or r.get("name")
            match_any = r.get("match_any")
            if not label or not match_any:
                continue
            for pat in match_any:
                if str(pat).lower() in pk_norm:
                    family = label
                    break
            if family:
                break

    if not family:
        family = PRODUCT_RULES.get("defaults", {}).get("unknown_family_name", "Other / Misc")

    vendor = None
    if PRODUCT_RULES.get("defaults", {}).get("vendor_from_prefix", True):
        if product_key and ":" in product_key:
            vendor = product_key.split(":", 1)[0]

    if not vendor:
        vendor = "unknown_vendor"

    return {"vendor": vendor, "family": family}


# ------------------------------------------------------------
#  POSTGRES
# ------------------------------------------------------------

def pg_connect(cfg: Dict[str, Any]):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed in this venv")

    db = cfg.get("database", {})
    return psycopg2.connect(
        host=db.get("host", "127.0.0.1"),
        port=db.get("port", 5432),
        dbname=db.get("name", "tenable_trends"),
        user=db.get("user", "tenable_trends_user"),
        password=db.get("password"),
    )


def init_db(cfg: Dict[str, Any]):
    conn = pg_connect(cfg)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS daily_product_metrics (
        snapshot_date  TEXT NOT NULL,
        site_label     TEXT NOT NULL,
        site_tag       TEXT NOT NULL,
        product        TEXT NOT NULL,

        vendor         TEXT,
        product_family TEXT,

        open_crit      INTEGER NOT NULL,
        open_high      INTEGER NOT NULL,
        open_medium    INTEGER NOT NULL,
        open_low       INTEGER NOT NULL,
        open_total     INTEGER NOT NULL,

        new_crit       INTEGER NOT NULL,
        new_high       INTEGER NOT NULL,
        new_medium     INTEGER NOT NULL,
        new_low        INTEGER NOT NULL,
        new_total      INTEGER NOT NULL,

        fixed_crit     INTEGER NOT NULL,
        fixed_high     INTEGER NOT NULL,
        fixed_medium   INTEGER NOT NULL,
        fixed_low      INTEGER NOT NULL,
        fixed_total    INTEGER NOT NULL,

        PRIMARY KEY (snapshot_date, site_label, product)
    );
    """)

    cur.execute("""ALTER TABLE daily_product_metrics ADD COLUMN IF NOT EXISTS vendor TEXT;""")
    cur.execute("""ALTER TABLE daily_product_metrics ADD COLUMN IF NOT EXISTS product_family TEXT;""")

    conn.commit()
    conn.close()


def prune_old(cfg: Dict[str, Any], retention_days: int):
    if retention_days <= 0:
        return
    cutoff = (dt.date.today() - dt.timedelta(days=retention_days)).isoformat()
    conn = pg_connect(cfg)
    cur = conn.cursor()
    cur.execute("DELETE FROM daily_product_metrics WHERE snapshot_date < %s", (cutoff,))
    conn.commit()
    conn.close()


def write_product_metrics(
    cfg: Dict[str, Any],
    date: str,
    metrics: Dict[Tuple[str, str], Dict[str, int]],
    label_to_tag: Dict[str, str],
    ungrouped: str,
):
    conn = pg_connect(cfg)
    cur = conn.cursor()

    for (site_label, product), d in metrics.items():
        tag = label_to_tag.get(site_label, "UNGROUPED" if site_label == ungrouped else site_label)

        cls = classify_product(product)
        vendor = cls["vendor"]
        family = cls["family"]

        cur.execute("""
        INSERT INTO daily_product_metrics (
            snapshot_date, site_label, site_tag, product,
            vendor, product_family,
            open_crit, open_high, open_medium, open_low, open_total,
            new_crit, new_high, new_medium, new_low, new_total,
            fixed_crit, fixed_high, fixed_medium, fixed_low, fixed_total
        )
        VALUES (%s,%s,%s,%s,
                %s,%s,
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s)
        ON CONFLICT (snapshot_date, site_label, product)
        DO UPDATE SET
            site_tag       = EXCLUDED.site_tag,
            vendor         = EXCLUDED.vendor,
            product_family = EXCLUDED.product_family,
            open_crit      = EXCLUDED.open_crit,
            open_high      = EXCLUDED.open_high,
            open_medium    = EXCLUDED.open_medium,
            open_low       = EXCLUDED.open_low,
            open_total     = EXCLUDED.open_total,
            new_crit       = EXCLUDED.new_crit,
            new_high       = EXCLUDED.new_high,
            new_medium     = EXCLUDED.new_medium,
            new_low        = EXCLUDED.new_low,
            new_total      = EXCLUDED.new_total,
            fixed_crit     = EXCLUDED.fixed_crit,
            fixed_high     = EXCLUDED.fixed_high,
            fixed_medium   = EXCLUDED.fixed_medium,
            fixed_low      = EXCLUDED.fixed_low,
            fixed_total    = EXCLUDED.fixed_total;
        """, (
            date, site_label, tag, product,
            vendor, family,
            d["open_crit"], d["open_high"], d["open_medium"], d["open_low"], d["open_total"],
            d["new_crit"], d["new_high"], d["new_medium"], d["new_low"], d["new_total"],
            d["fixed_crit"], d["fixed_high"], d["fixed_medium"], d["fixed_low"], d["fixed_total"],
        ))

    conn.commit()
    conn.close()


# ------------------------------------------------------------
#  TENABLE HELPERS
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
    return export_uuid


def poll_export(sess: requests.Session, uuid: str, interval: int = 10) -> Dict[str, Any]:
    url = f"{sess.base_url}/vulns/export/{uuid}/status"
    start = time.time()
    while True:
        resp = sess.get(url)
        resp.raise_for_status()
        status = resp.json()
        elapsed = int(time.time() - start)
        print(f"[poll] {uuid} status={status.get('status')} chunks={status.get('chunks_available')} elapsed={elapsed}s")
        if status.get("status") == "FINISHED":
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


# ------------------------------------------------------------
#  PLUGIN / CVE HELPERS
# ------------------------------------------------------------

def extract_plugin_id(plugin: Dict[str, Any]) -> Optional[int]:
    pid = plugin.get("id") or plugin.get("plugin_id")
    try:
        return int(pid) if pid is not None else None
    except (TypeError, ValueError):
        return None


def extract_cves(plugin: Dict[str, Any]) -> List[str]:
    c = plugin.get("cve") or plugin.get("cves") or []
    if isinstance(c, str):
        c = [c]
    out: List[str] = []
    for x in c:
        if not x:
            continue
        s = str(x).strip().upper()
        if s.startswith("CVE-"):
            out.append(s)
    return out


# ------------------------------------------------------------
#  CVSS + CLASSIFICATION
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
            vec = val.get("raw") or val.get("vector") or val.get("base_vector") or val.get("v3_vector") or val.get("v2_vector")
            if vec:
                return str(vec)
        else:
            return str(val)

    cvss = plugin.get("cvss") or {}
    if isinstance(cvss, dict):
        vec = cvss.get("raw") or cvss.get("vector") or cvss.get("base_vector") or cvss.get("v3_vector") or cvss.get("v2_vector")
        if vec:
            return str(vec)

    return None


def get_cvss_score(finding: Dict[str, Any]) -> float:
    plugin = finding.get("plugin", {}) or {}
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
    return 0.0


def severity_band(finding: Dict[str, Any]) -> Optional[str]:
    score = get_cvss_score(finding)
    if score >= 9.0:
        return "critical"
    if 7.0 <= score < 9.0:
        return "high"
    if 4.0 <= score < 7.0:
        return "medium"
    if score > 0.0:
        return "low"
    return None


def classify_sev(finding: Dict[str, Any]) -> Optional[str]:
    plugin = finding.get("plugin", {}) or {}
    sev_raw = plugin.get("severity")
    if sev_raw is None:
        sev_raw = finding.get("severity") or finding.get("severity_id")

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


def vuln_age_days(finding: Dict[str, Any]) -> float:
    ts = (
        finding.get("first_found")
        or finding.get("first_seen")
        or finding.get("first_observed")
        or finding.get("last_found")
        or finding.get("last_seen")
    )
    if not ts:
        return 0.0
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return 0.0
    return (int(time.time()) - ts) / 86400.0


# ------------------------------------------------------------
#  ASSET + SITE HELPERS
# ------------------------------------------------------------

def fetch_all_assets(sess: requests.Session) -> Dict[str, Any]:
    print("[+] Exporting asset list (tags included)…")
    resp = sess.post(f"{sess.base_url}/assets/export", json={"include_attributes": ["tags"], "chunk_size": 5000})
    resp.raise_for_status()
    data = resp.json()
    uuid = data.get("export_uuid")
    if not uuid:
        raise RuntimeError(f"Asset export UUID missing: {data}")

    while True:
        status = sess.get(f"{sess.base_url}/assets/export/{uuid}/status").json()
        if status.get("status") == "FINISHED":
            break
        time.sleep(2)

    chunks = status.get("chunks_available", [])
    asset_tags: Dict[str, Any] = {}

    for c in chunks:
        chunk = sess.get(f"{sess.base_url}/assets/export/{uuid}/chunks/{c}").json()
        for a in chunk:
            aid = a.get("id") or a.get("uuid")
            tags = a.get("tags") or []
            if aid:
                asset_tags[aid] = tags

    print(f"[+] Loaded {len(asset_tags)} assets with tag data.")
    return asset_tags


def site_label(asset: Dict[str, Any], site_cfg: Dict[str, str], tag_cfg: Dict[str, Any], ungrouped: str) -> str:
    tags = asset.get("tags") or []
    cat = str(tag_cfg.get("site_category", "Sites"))

    for t in tags:
        if not isinstance(t, dict):
            continue

        category = str(t.get("category") or t.get("key") or t.get("tag_key") or "")
        value = str(t.get("value") or t.get("tag_value") or "")

        if category == cat and value in site_cfg:
            return site_cfg[value]

        if ":" in category:
            c_cat, c_val = category.split(":", 1)
            if c_cat == cat and c_val in site_cfg:
                return site_cfg[c_val]

        if ":" in value:
            v_cat, v_val = value.split(":", 1)
            if v_cat == cat and v_val in site_cfg:
                return site_cfg[v_val]

    # some APIs return tags as strings
    for t in tags:
        if isinstance(t, str):
            s = t.strip()
            if ":" in s:
                s_cat, s_val = s.split(":", 1)
                if s_cat == cat and s_val in site_cfg:
                    return site_cfg[s_val]

    return ungrouped


def product_key_from_cpe(plugin: Dict[str, Any]) -> str:
    cpes = plugin.get("cpe") or []
    if isinstance(cpes, str):
        cpes = [cpes]

    for c in cpes:
        if not isinstance(c, str):
            continue
        if not c.startswith("cpe:/"):
            continue
        parts = c.split(":")
        if len(parts) >= 4:
            vendor = parts[2] or "unknown_vendor"
            product = parts[3] or "unknown_product"
            return f"{vendor}:{product}"

    family = (plugin.get("family") or "UnknownFamily").strip()
    name = (plugin.get("name") or "UnknownPlugin").strip()
    for sep in ["<", " - ", " : "]:
        if sep in name:
            name = name.split(sep, 1)[0].strip()
            break
    return f"{family} - {name}"


# ------------------------------------------------------------
#  MAIN COLLECTION LOGIC
# ------------------------------------------------------------

def collect_product_metrics(sess, cfg: Dict[str, Any], window_days: int):
    """
    Returns:
      metrics: (site_label, product) -> counters
      plugin_metrics: (site_label, product, plugin_id) -> counters
      plugin_meta: plugin_id -> metadata dict
      plugin_cves: plugin_id -> set(CVE-*)
      site_cfg: mapping key->label from config
      ungrouped: ungrouped label
    """
    total_seen_open = 0
    total_seen_fixed = 0

    asset_tags = fetch_all_assets(sess)

    reporting = cfg["reporting"]
    tag_cfg = cfg["tags"]
    days_last_seen = reporting["days_last_seen"]

    now = int(time.time())
    last_seen_cut = now - days_last_seen * 86400
    fixed_cut = now - window_days * 86400

    site_cfg = {s["key"]: s["label"] for s in cfg["sites"]}
    ungrouped = cfg.get("ungrouped_label", "Ungrouped")

    # aggregate per product
    metrics: Dict[Tuple[str, str], Dict[str, int]] = {}
    # drill aggregate per plugin
    plugin_metrics: Dict[Tuple[str, str, int], Dict[str, int]] = {}
    plugin_meta: Dict[int, Dict[str, Any]] = {}
    plugin_cves: Dict[int, Set[str]] = {}

    def ensure_bucket(site_label_: str, product_: str) -> Dict[str, int]:
        key = (site_label_, product_)
        if key not in metrics:
            metrics[key] = {
                "open_crit": 0, "open_high": 0, "open_medium": 0, "open_low": 0, "open_total": 0,
                "new_crit": 0, "new_high": 0, "new_medium": 0, "new_low": 0, "new_total": 0,
                "fixed_crit": 0, "fixed_high": 0, "fixed_medium": 0, "fixed_low": 0, "fixed_total": 0,
            }
        return metrics[key]

    def ensure_plugin_bucket(site_label_: str, product_: str, plugin_id_: int) -> Dict[str, int]:
        key = (site_label_, product_, plugin_id_)
        if key not in plugin_metrics:
            plugin_metrics[key] = {
                "open_crit": 0, "open_high": 0, "open_medium": 0, "open_low": 0, "open_total": 0,
                "new_crit": 0, "new_high": 0, "new_medium": 0, "new_low": 0, "new_total": 0,
                "fixed_crit": 0, "fixed_high": 0, "fixed_medium": 0, "fixed_low": 0, "fixed_total": 0,
            }
        return plugin_metrics[key]

    def record_plugin_enrichment(plugin: Dict[str, Any], product_: str):
        plugin_id_ = extract_plugin_id(plugin)
        if not plugin_id_:
            return None

        if plugin_id_ not in plugin_meta:
            cls = classify_product(product_)
            plugin_meta[plugin_id_] = {
                "plugin_id": plugin_id_,
                "plugin_name": plugin.get("name"),
                "plugin_family": plugin.get("family"),
                "plugin_type": plugin.get("type"),
                "vendor": cls["vendor"],
                "product": product_,
                "product_family": cls["family"],
                "synopsis": plugin.get("synopsis"),
                "description": plugin.get("description"),
                "solution": plugin.get("solution"),
                "see_also": plugin.get("see_also") or plugin.get("see_also_urls") or [],
                "cvss3_base": plugin.get("cvss3_base_score") or plugin.get("cvss3_score"),
                "cvss3_vector": _get_cvss_vector_string(plugin),
                "exploit_available": plugin.get("exploit_available"),
                "exploited_by_malware": plugin.get("exploited_by_malware"),
                "has_patch": (plugin.get("patch_publication_date") is not None) or bool(plugin.get("patch_published")),
                "patch_published": plugin.get("patch_publication_date"),
            }

        for cve in extract_cves(plugin):
            plugin_cves.setdefault(plugin_id_, set()).add(cve)

        return plugin_id_

    # 1) OPEN / REOPENED
    filters_open = {
        "state": ["OPEN", "REOPENED"],
        "severity": ["low", "medium", "high", "critical"],
        "last_found": last_seen_cut,
    }

    uuid_open = start_export(sess, filters_open)
    status_open = poll_export(sess, uuid_open)
    chunks_open = status_open.get("chunks_available") or []

    for f in iter_chunks(sess, uuid_open, chunks_open):
        total_seen_open += 1

        sev = severity_band(f) or classify_sev(f)
        if not sev:
            continue

        plugin = f.get("plugin", {}) or {}
        product = product_key_from_cpe(plugin)

        asset = f.get("asset", {}) or {}
        sid = asset.get("uuid") or asset.get("id")
        asset["tags"] = asset_tags.get(sid, [])
        lab = site_label(asset, site_cfg, tag_cfg, ungrouped)

        # aggregate product level
        b = ensure_bucket(lab, product)

        if sev == "critical":
            b["open_crit"] += 1
        elif sev == "high":
            b["open_high"] += 1
        elif sev == "medium":
            b["open_medium"] += 1
        elif sev == "low":
            b["open_low"] += 1
        b["open_total"] += 1

        age = vuln_age_days(f)
        if age <= window_days:
            if sev == "critical":
                b["new_crit"] += 1
            elif sev == "high":
                b["new_high"] += 1
            elif sev == "medium":
                b["new_medium"] += 1
            elif sev == "low":
                b["new_low"] += 1
            b["new_total"] += 1

        # drill level
        plugin_id = record_plugin_enrichment(plugin, product)
        if plugin_id:
            pb = ensure_plugin_bucket(lab, product, plugin_id)
            if sev == "critical":
                pb["open_crit"] += 1
            elif sev == "high":
                pb["open_high"] += 1
            elif sev == "medium":
                pb["open_medium"] += 1
            elif sev == "low":
                pb["open_low"] += 1
            pb["open_total"] += 1

            if age <= window_days:
                if sev == "critical":
                    pb["new_crit"] += 1
                elif sev == "high":
                    pb["new_high"] += 1
                elif sev == "medium":
                    pb["new_medium"] += 1
                elif sev == "low":
                    pb["new_low"] += 1
                pb["new_total"] += 1

    print(f"[debug] OPEN/REOPENED findings processed: {total_seen_open}")

    # 2) FIXED
    filters_fixed = {"state": ["FIXED"], "severity": ["low", "medium", "high", "critical"]}

    uuid_fixed = start_export(sess, filters_fixed)
    status_fixed = poll_export(sess, uuid_fixed)
    chunks_fixed = status_fixed.get("chunks_available") or []

    for f in iter_chunks(sess, uuid_fixed, chunks_fixed):
        total_seen_fixed += 1

        sev = severity_band(f) or classify_sev(f)
        if not sev:
            continue

        last_fixed = f.get("last_fixed")
        if not last_fixed:
            continue
        try:
            last_fixed = int(last_fixed)
        except (TypeError, ValueError):
            continue
        if last_fixed < fixed_cut:
            continue

        plugin = f.get("plugin", {}) or {}
        product = product_key_from_cpe(plugin)

        asset = f.get("asset", {}) or {}
        sid = asset.get("uuid") or asset.get("id")
        asset["tags"] = asset_tags.get(sid, [])
        lab = site_label(asset, site_cfg, tag_cfg, ungrouped)

        # aggregate product level
        b = ensure_bucket(lab, product)

        if sev == "critical":
            b["fixed_crit"] += 1
        elif sev == "high":
            b["fixed_high"] += 1
        elif sev == "medium":
            b["fixed_medium"] += 1
        elif sev == "low":
            b["fixed_low"] += 1
        b["fixed_total"] += 1

        # drill level
        plugin_id = record_plugin_enrichment(plugin, product)
        if plugin_id:
            pb = ensure_plugin_bucket(lab, product, plugin_id)
            if sev == "critical":
                pb["fixed_crit"] += 1
            elif sev == "high":
                pb["fixed_high"] += 1
            elif sev == "medium":
                pb["fixed_medium"] += 1
            elif sev == "low":
                pb["fixed_low"] += 1
            pb["fixed_total"] += 1

    print(f"[debug] FIXED findings processed: {total_seen_fixed}")
    print(f"[debug] Distinct (site, product) buckets: {len(metrics)}")
    print(f"[debug] Distinct plugin_ids captured: {len(plugin_meta)}")

    return metrics, plugin_metrics, plugin_meta, plugin_cves, site_cfg, ungrouped


# ------------------------------------------------------------
#  MAIN
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Tenable product driver metrics (open/new/fixed per product)")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--window-days", type=int, default=90)
    parser.add_argument(
        "--dump-plugin-enrichment",
        action="store_true",
        help="Write plugin_meta + plugin_cves to local JSON files for inspection (no DB tables needed yet).",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)

    init_db(cfg)
    prune_old(cfg, cfg["reporting"].get("retention_days", 540))

    ten_cfg = cfg["tenable"]
    sess = tenable_session(ten_cfg["base_url"], ten_cfg["access_key"], ten_cfg["secret_key"])

    date = dt.date.today().isoformat()
    print(f"[+] Beginning product snapshot for {date} (window={args.window_days} days)")

    metrics, plugin_metrics, plugin_meta, plugin_cves, site_cfg, ungrouped = collect_product_metrics(sess, cfg, args.window_days)
    label_to_tag = {v: k for k, v in site_cfg.items()}

    grand_open = sum(d["open_total"] for d in metrics.values())
    grand_new = sum(d["new_total"] for d in metrics.values())
    grand_fixed = sum(d["fixed_total"] for d in metrics.values())
    print(f"[summary] open_total={grand_open}, new_total={grand_new}, fixed_total={grand_fixed}")

    write_product_metrics(cfg, date, metrics, label_to_tag, ungrouped)
    print("[+] Product metrics snapshot complete.")

    if args.dump_plugin_enrichment:
        with open(f"plugin_meta_{date}.json", "w") as f:
            json.dump(plugin_meta, f, indent=2, default=str)
        with open(f"plugin_cves_{date}.json", "w") as f:
            json.dump({str(k): sorted(list(v)) for k, v in plugin_cves.items()}, f, indent=2)
        print(f"[+] Wrote plugin_meta_{date}.json and plugin_cves_{date}.json")


if __name__ == "__main__":
    main()
