#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import time
from typing import Dict, Any, Iterable

import requests
import yaml

# psycopg2 for Postgres
try:
    import psycopg2
except ImportError:
    psycopg2 = None


# ------------------------------------------------------------
#  CONFIG LOADING (supports external secrets file)
# ------------------------------------------------------------

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load main config.yaml, then (optionally) merge in secrets.yaml.
    """
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

        # Merge Tenable keys
        if "tenable" in secrets:
            cfg.setdefault("tenable", {})
            cfg["tenable"].update(secrets["tenable"])

        # Merge Postgres creds
        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

    return cfg


# ------------------------------------------------------------
#  POSTGRES CONNECTION
# ------------------------------------------------------------

def pg_connect(cfg: Dict[str, Any]):
    """
    Returns an active psycopg2 Postgres connection.
    """
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


# ------------------------------------------------------------
#  DB INITIALISATION (POSTGRES ONLY)
# ------------------------------------------------------------

def init_db(cfg: Dict[str, Any]):
    """
    Ensure the required tables exist in Postgres.
    """
    conn = pg_connect(cfg)
    cur = conn.cursor()

    # Snapshot counts per site
    cur.execute("""
    CREATE TABLE IF NOT EXISTS daily_site_metrics (
        snapshot_date TEXT NOT NULL,
        site_label    TEXT NOT NULL,
        site_tag      TEXT NOT NULL,
        crit          INTEGER NOT NULL,
        high          INTEGER NOT NULL,
        medium        INTEGER NOT NULL,
        low           INTEGER NOT NULL,
        total         INTEGER NOT NULL,
        remote_crit   INTEGER NOT NULL,
        remote_high   INTEGER NOT NULL,
        assets        INTEGER NOT NULL,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """)

    # SLA metrics per site
    cur.execute("""
    CREATE TABLE IF NOT EXISTS daily_sla_metrics (
        snapshot_date           TEXT NOT NULL,
        site_label              TEXT NOT NULL,
        site_tag                TEXT NOT NULL,
        risk                    TEXT NOT NULL,
        total_vulns             INTEGER NOT NULL,
        sla_breaches            INTEGER NOT NULL,
        remote_no_auth_vulns    INTEGER NOT NULL,
        remote_no_auth_breaches INTEGER NOT NULL,
        PRIMARY KEY (snapshot_date, site_label, risk)
    );
    """)

    conn.commit()
    conn.close()


# ------------------------------------------------------------
#  RETENTION CLEANUP
# ------------------------------------------------------------

def prune_old(cfg: Dict[str, Any], retention_days: int):
    """
    Delete snapshot rows older than N days from Postgres.
    """
    if retention_days <= 0:
        return

    cutoff = (dt.date.today() - dt.timedelta(days=retention_days)).isoformat()
    conn = pg_connect(cfg)
    cur = conn.cursor()

    cur.execute("DELETE FROM daily_site_metrics WHERE snapshot_date < %s", (cutoff,))
    cur.execute("DELETE FROM daily_sla_metrics  WHERE snapshot_date < %s", (cutoff,))

    conn.commit()
    conn.close()


# ------------------------------------------------------------
#  WRITE SNAPSHOTS (POSTGRES ONLY)
# ------------------------------------------------------------

def write_site(cfg: Dict[str, Any], date: str, data, tag_lookup, ungrouped: str):
    """
    Store per-site severity metrics into Postgres.
    Overwrites rows for the same date+site.
    """
    conn = pg_connect(cfg)
    cur = conn.cursor()

    for lab, d in data.items():
        crit = d["crit"]
        high = d["high"]
        med  = d["medium"]
        low  = d["low"]
        total = crit + high + med + low

        tag = tag_lookup.get(lab, "UNGROUPED" if lab == ungrouped else lab)

        cur.execute("""
        INSERT INTO daily_site_metrics (
            snapshot_date, site_label, site_tag,
            crit, high, medium, low, total,
            remote_crit, remote_high, assets
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (snapshot_date, site_label)
        DO UPDATE SET
            site_tag     = EXCLUDED.site_tag,
            crit         = EXCLUDED.crit,
            high         = EXCLUDED.high,
            medium       = EXCLUDED.medium,
            low          = EXCLUDED.low,
            total        = EXCLUDED.total,
            remote_crit  = EXCLUDED.remote_crit,
            remote_high  = EXCLUDED.remote_high,
            assets       = EXCLUDED.assets;
        """, (
            date, lab, tag,
            crit, high, med, low, total,
            d["remote_crit"], d["remote_high"],
            len(d["assets"]),
        ))

    conn.commit()
    conn.close()


def write_sla(cfg: Dict[str, Any], date: str, sla_data, tag_lookup, ungrouped: str):
    """
    Store SLA metrics per site/risk into Postgres.
    Overwrites rows for the same date+site+risk.
    """
    conn = pg_connect(cfg)
    cur = conn.cursor()

    for lab, risks in sla_data.items():
        tag = tag_lookup.get(lab, "UNGROUPED" if lab == ungrouped else lab)

        for risk, d in risks.items():
            cur.execute("""
            INSERT INTO daily_sla_metrics (
                snapshot_date, site_label, site_tag, risk,
                total_vulns, sla_breaches,
                remote_no_auth_vulns, remote_no_auth_breaches
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label, risk)
            DO UPDATE SET
                site_tag               = EXCLUDED.site_tag,
                total_vulns            = EXCLUDED.total_vulns,
                sla_breaches           = EXCLUDED.sla_breaches,
                remote_no_auth_vulns   = EXCLUDED.remote_no_auth_vulns,
                remote_no_auth_breaches= EXCLUDED.remote_no_auth_breaches;
            """, (
                date, lab, tag, risk,
                d["total"], d["breaches"],
                d["remote_total"], d["remote_breaches"],
            ))

    conn.commit()
    conn.close()
# ------------------------------------------------------------
#   TENABLE API HELPERS
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
    payload = {
        "filters": filters,
        "include_unlicensed": True,
    }
    print("[debug] Export payload:", json.dumps(payload, indent=2))
    resp = sess.post(f"{sess.base_url}/vulns/export", data=json.dumps(payload))
    if resp.status_code != 200:
        raise RuntimeError(f"Export start failed: {resp.status_code}, {resp.text}")

    data = resp.json()
    export_uuid = data.get("export_uuid") or data.get("uuid")
    if not export_uuid:
        raise RuntimeError(f"Export UUID missing: {data}")

    print(f"[debug] Export started: {export_uuid}")
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
            f"[poll] {uuid} status={status.get('status')} "
            f"chunks={status.get('chunks_available')} elapsed={elapsed}s"
        )

        if status.get("status") == "FINISHED":
            print("[poll] Export complete.")
            return status

        if status.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Export failed: {status}")

        time.sleep(interval)


def iter_chunks(sess: requests.Session, uuid: str, chunks) -> Iterable[Dict[str, Any]]:
    for chunk in chunks:
        print(f"[debug] Fetching chunk {chunk}…")
        resp = sess.get(f"{sess.base_url}/vulns/export/{uuid}/chunks/{chunk}")
        resp.raise_for_status()
        data = resp.json()

        # Some tenants return a list, others a dict with 'vulnerabilities'
        if isinstance(data, list):
            vulns = data
        else:
            vulns = data.get("vulnerabilities", data)

        for v in vulns:
            yield v


# ------------------------------------------------------------
#   CVSS + CLASSIFICATION HELPERS
# ------------------------------------------------------------

def parse_cvss(vector) -> Dict[str, str]:
    """
    Normalise Tenable CVSS vector into a dict of metrics.

    Handles:
      - string: "CVSS:3.1/AV:N/AC:L/PR:N/..."
      - dict:   {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/...", ...}
    """
    if not vector:
        return {}

    # If Tenable gives us a dict, try to pull the actual vector string out
    if isinstance(vector, dict):
        vector_str = (
            vector.get("vector")
            or vector.get("base_vector")
            or vector.get("v3_vector")
            or vector.get("v2_vector")
        )
        if not vector_str:
            return {}
        vector = vector_str

    # If it's still not a string, give up gracefully
    if not isinstance(vector, str):
        return {}

    if vector.startswith("CVSS:"):
        parts = vector.split("/")[1:]
    else:
        parts = vector.split("/")

    out: Dict[str, str] = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k] = v
    return out

def extract_cvss_vector(plugin: Dict[str, Any]) -> Any:
    """
    Try to pull a CVSS vector string (or dict with 'vector') out of the plugin
    in a few different shapes Tenable might use.
    Returns either a string, a dict containing 'vector', or None.
    """

    if not isinstance(plugin, dict):
        return None

    # Common direct keys
    for key in ("cvss3_vector", "cvss_vector", "cvssV3_vector", "cvss_v3_vector"):
        v = plugin.get(key)
        if v:
            return v

    # Nested blocks like: plugin["cvss3"] = {"vector": "CVSS:3.1/AV:N/..."}
    for key in ("cvss3", "cvssV3", "cvss_v3", "cvss", "cvssV2", "cvss2"):
        block = plugin.get(key)
        if isinstance(block, dict):
            v = (
                block.get("vector")
                or block.get("base_vector")
                or block.get("v3_vector")
                or block.get("v2_vector")
            )
            if v:
                # Could be either a string or dict; parse_cvss handles both
                return v

    return None

def severity_band(finding) -> str | None:
    """
    Derive 'critical'/'high'/'medium'/'low' from CVSS score,
    so both site metrics and SLA use the same maths.
    """
    cvss = get_cvss_score(finding)
    if cvss is None:
        return None

    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return None

    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    else:
        return None


def is_remote_no_auth(finding: Dict[str, Any], require_exploit=True) -> bool:
    plugin = finding.get("plugin", {}) or {}

    # Try to get *some* usable CVSS vector from all the likely places.
    vector = extract_cvss_vector(plugin)
    m = parse_cvss(vector)

    av = m.get("AV")
    pr = m.get("PR")
    au = m.get("Au")

    # Remote if AV is Network or Adjacent
    remote = av in ("N", "A")

    # "No auth" if no privileges required (CVSSv3 PR=N) or CVSSv2 Au=N
    noauth = (pr == "N") or (au == "N")

    if not (remote and noauth):
        return False

    if not require_exploit:
        return True

    # Only enforced if you explicitly want exploit evidence
    exploited = plugin.get("exploit_available")
    ease = (plugin.get("exploitability_ease") or "").lower()

    return bool(exploited) or ("no known" not in ease)


def get_cvss_score(finding) -> float:
    plugin = finding.get("plugin", {})
    for k in ("cvss3_base_score", "cvss_base_score", "cvss3_score", "cvss_score"):
        v = plugin.get(k)
        if v is not None:
            try:
                return float(v)
            except Exception:
                pass
    return 0.0


def classify_sev(finding):
    """
    Normalise Tenable severity to one of: critical, high, medium, low.

    Handles:
      - severity_id: 4/3/2/1
      - severity:    4/3/2/1
      - severity:    "critical"/"high"/"medium"/"low"
    """
    sev_raw = finding.get("severity")

    # Fall back to severity_id if present
    if sev_raw is None:
        sev_raw = finding.get("severity_id")

    # Try numeric first
    try:
        s = int(sev_raw)
        return {
            4: "critical",
            3: "high",
            2: "medium",
            1: "low",
            0: None,  # info, ignore
        }.get(s)
    except (TypeError, ValueError):
        pass

    # Try string mapping
    if isinstance(sev_raw, str):
        s = sev_raw.strip().lower()
        if s in ("critical", "high", "medium", "low"):
            return s

    return None


def vuln_age_days(finding) -> float:
    ts = (
        finding.get("first_found")
        or finding.get("first_seen")
        or finding.get("last_found")
    )
    if not ts:
        return 0.0
    try:
        ts = int(ts)
    except Exception:
        return 0.0
    return (int(time.time()) - ts) / 86400.0


# ------------------------------------------------------------
#   ASSET TAGS + SLA HELPERS
# ------------------------------------------------------------

def fetch_all_assets(sess: requests.Session) -> Dict[str, Any]:
    """
    Export all assets with tags using assets/export API.
    Returns dict: asset_uuid -> tags
    """
    print("[+] Exporting asset list (tags included)…")

    resp = sess.post(
        f"{sess.base_url}/assets/export",
        json={"include_attributes": ["tags"], "chunk_size": 5000},
    )
    resp.raise_for_status()
    data = resp.json()
    uuid = data.get("export_uuid")

    if not uuid:
        raise RuntimeError(f"Asset export UUID missing: {data}")

    # Poll
    while True:
        status = sess.get(f"{sess.base_url}/assets/export/{uuid}/status").json()
        if status.get("status") == "FINISHED":
            break
        print("[poll-assets] status=", status.get("status"))
        time.sleep(2)

    chunks = status.get("chunks_available", [])
    print(f"[+] Asset export ready ({len(chunks)} chunks)")

    asset_tags: Dict[str, Any] = {}

    # Download each chunk
    for c in chunks:
        print(f"[debug] Fetching asset chunk {c}")
        chunk = sess.get(f"{sess.base_url}/assets/export/{uuid}/chunks/{c}").json()
        for a in chunk:
            aid = a.get("id") or a.get("uuid")
            tags = a.get("tags") or []
            if aid:
                asset_tags[aid] = tags

    print(f"[+] Loaded {len(asset_tags)} assets with tag data.")
    return asset_tags


def asset_type(asset: Dict[str, Any], tag_cfg: Dict[str, Any]) -> str:
    tags = asset.get("tags", [])

    at_cat = tag_cfg.get("asset_type_category", "AssetType")
    vals = [
        t.get("value")
        for t in tags
        if isinstance(t, dict) and t.get("key") == at_cat
    ]

    vset = set(vals)

    if vset & set(tag_cfg.get("internet_values", [])):
        return "internet"
    if vset & set(tag_cfg.get("server_values", [])):
        return "server"
    if vset & set(tag_cfg.get("workstation_values", [])):
        return "workstation"

    return "unknown"

def sla_days(risk: str) -> int:
    return {"Critical": 2, "High": 14, "Medium": 30, "Low": 60}.get(risk, 60)


# ------------------------------------------------------------
#   SITE CLASSIFICATION
# ------------------------------------------------------------

def site_label(asset: Dict[str, Any], site_cfg, tag_cfg, ungrouped: str) -> str:
    """
    Work out the site label for an asset based on tags.

    Supports tag shapes like:
      {"category": "Sites", "value": "BH-Site"}
      {"key": "Sites", "value": "BH-Site"}
      {"tag_key": "Sites", "tag_value": "BH-Site"}
      "Sites:BH-Site"
    """
    tags = asset.get("tags") or []
    cat = str(tag_cfg.get("site_category", "Sites"))

    # Dict-style tags
    for t in tags:
        if not isinstance(t, dict):
            continue

        category = str(
            t.get("category")
            or t.get("key")
            or t.get("tag_key")
            or ""
        )
        value = str(
            t.get("value")
            or t.get("tag_value")
            or ""
        )

        # Case: category == "Sites", value == "BH-Site"
        if category == cat and value in site_cfg:
            return site_cfg[value]

        # Case: category == "Sites:BH-Site"
        if ":" in category:
            c_cat, c_val = category.split(":", 1)
            if c_cat == cat and c_val in site_cfg:
                return site_cfg[c_val]

        # Case: value == "Sites:BH-Site"
        if ":" in value:
            v_cat, v_val = value.split(":", 1)
            if v_cat == cat and v_val in site_cfg:
                return site_cfg[v_val]

    # String-style tags like "Sites:BH-Site"
    for t in tags:
        if isinstance(t, str):
            s = t.strip()
            if ":" in s:
                s_cat, s_val = s.split(":", 1)
                if s_cat == cat and s_val in site_cfg:
                    return site_cfg[s_val]

    # No match → Ungrouped
    return ungrouped


# ------------------------------------------------------------
#   MAIN COLLECTION LOGIC
# ------------------------------------------------------------

def collect(sess, cfg):
    total_seen = 0
    total_with_sev = 0

    asset_tags = fetch_all_assets(sess)

    reporting = cfg["reporting"]
    tag_cfg = cfg["tags"]

    days_last_seen = reporting["days_last_seen"]
    published_older = reporting["vuln_published_older_than_days"]

    require_exploit_flag = reporting.get(
        "require_exploit_for_remote_no_auth",
        True
    )

    now = int(time.time())
    last_seen_cut = now - days_last_seen * 86400
    published_cut = now - published_older * 86400

    site_cfg = {s["key"]: s["label"] for s in cfg["sites"]}
    ungrouped = cfg.get("ungrouped_label", "Ungrouped")
    site_labels = set(site_cfg.values()) | {ungrouped}

    overall = {
        lab: {
            "crit": 0, "high": 0, "medium": 0, "low": 0,
            "remote_crit": 0, "remote_high": 0,
            "assets": set()
        }
        for lab in site_labels
    }

    sla = {lab: {} for lab in site_labels}

    filters = {
        "state": ["OPEN", "REOPENED"],
        "severity": ["low", "medium", "high", "critical"],
        "last_found": last_seen_cut,
    }

    uuid = start_export(sess, filters)
    status = poll_export(sess, uuid)
    chunks = status.get("chunks_available") or []

    # NEW: initialise debug counter
    remote_counter = 0

    for f in iter_chunks(sess, uuid, chunks):
        total_seen += 1

        # First choice: CVSS-based band
        sev = severity_band(f)

        # Optional fallback: if CVSS missing, try Tenable severity
        if not sev:
            sev = classify_sev(f)

        if not sev:
            continue

        total_with_sev += 1


        asset = f.get("asset", {}) or {}
        sid = asset.get("uuid") or asset.get("id")

        # attach tags from lookup
        asset["tags"] = asset_tags.get(sid, [])

        lab = site_label(asset, site_cfg, tag_cfg, ungrouped)

        # track unique assets per site
        if sid:
            overall[lab]["assets"].add(sid)

        # Remote classifier (using your config flag)
        remote = is_remote_no_auth(f, require_exploit=require_exploit_flag)
        if remote:
            remote_counter += 1

        # Site-level severity counts (CVSS-based band)
        if sev == "critical":
            overall[lab]["crit"] += 1
            if remote:
                overall[lab]["remote_crit"] += 1
        elif sev == "high":
            overall[lab]["high"] += 1
            if remote:
                overall[lab]["remote_high"] += 1
        elif sev == "medium":
            overall[lab]["medium"] += 1
        elif sev == "low":
            overall[lab]["low"] += 1

        # SLA risk uses the SAME band (just capitalised)
        risk = sev.capitalize()  # 'critical' -> 'Critical', etc.

        age = vuln_age_days(f)
        breach = age > sla_days(risk)

        bucket = sla[lab].setdefault(
            risk,
            {"total": 0, "breaches": 0, "remote_total": 0, "remote_breaches": 0}
        )

        bucket["total"] += 1
        if breach:
            bucket["breaches"] += 1

        if remote:
            bucket["remote_total"] += 1
            if breach:
                bucket["remote_breaches"] += 1


        # SLA aggregation
        typ = asset_type(asset, tag_cfg)
        cvss = get_cvss_score(f)
        risk = risk_map(typ, cvss)
        age = vuln_age_days(f)
        breach = age > sla_days(risk)

        bucket = sla[lab].setdefault(
            risk,
            {
                "total": 0,
                "breaches": 0,
                "remote_total": 0,
                "remote_breaches": 0,
            },
        )

        bucket["total"] += 1
        if breach:
            bucket["breaches"] += 1

        if remote:
            bucket["remote_total"] += 1
            if breach:
                bucket["remote_breaches"] += 1

    print(
        f"[debug] Findings processed: {total_seen}, "
        f"with recognised severity: {total_with_sev}"
    )
    
    print(f"[debug] Findings processed: {total_seen}, "
          f"with recognised severity: {total_with_sev}, "
          f"remote_no_auth_matches: {remote_counter}")
    return overall, sla, site_cfg, ungrouped


    return overall, sla, site_cfg, ungrouped


# ------------------------------------------------------------
#   MAIN
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)

    # DB housekeeping
    init_db(cfg)
    prune_old(cfg, cfg["reporting"]["retention_days"])

    # Tenable session
    ten_cfg = cfg["tenable"]
    sess = tenable_session(
        ten_cfg["base_url"],
        ten_cfg["access_key"],
        ten_cfg["secret_key"],
    )

    date = dt.date.today().isoformat()
    print(f"[+] Beginning snapshot for {date}")

    overall, sla_data, site_cfg, ungrouped = collect(sess, cfg)
    label_to_tag = {v: k for k, v in site_cfg.items()}

    # Console summary
    for lab, d in overall.items():
        print(
            f"[site] {lab:12s} "
            f"crit={d['crit']:5d} high={d['high']:5d} "
            f"med={d['medium']:5d} low={d['low']:5d} "
            f"total={d['crit']+d['high']+d['medium']+d['low']}"
        )

    # Persist to Postgres
    write_site(cfg, date, overall, label_to_tag, ungrouped)
    write_sla(cfg, date, sla_data, label_to_tag, ungrouped)

    print("[+] Done.")


if __name__ == "__main__":
    main()
