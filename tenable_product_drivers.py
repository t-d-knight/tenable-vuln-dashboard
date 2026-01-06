#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import time
import re
from typing import Dict, Any, Optional, List

import requests
import yaml

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    psycopg2 = None
    Json = None


# ============================================================
# CONFIG
# ============================================================


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = os.path.dirname(os.path.abspath(path))
        secrets_path = os.path.join(base_dir, secrets_rel)
        with open(secrets_path, "r") as sf:
            secrets = yaml.safe_load(sf) or {}
        cfg.setdefault("tenable", {}).update(secrets.get("tenable", {}))
        cfg.setdefault("database", {}).update(secrets.get("database", {}))

    return cfg


# ============================================================
# PRODUCT CLASSIFICATION
# ============================================================


def load_product_rules(path: str = "product_groups.yaml") -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {
            "rules": [],
            "defaults": {
                "unknown_family_name": "Other / Misc",
                "vendor_from_prefix": True,
            },
        }
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("rules", [])
    data.setdefault("defaults", {})
    data["defaults"].setdefault("unknown_family_name", "Other / Misc")
    data["defaults"].setdefault("vendor_from_prefix", True)
    return data


PRODUCT_RULES = load_product_rules()


def classify_product(product_key: str) -> Dict[str, str]:
    pk = (product_key or "").lower()
    family = None

    for r in PRODUCT_RULES["rules"]:
        label = r.get("family") or r.get("name")
        if not label:
            continue

        match = r.get("match")
        pat = r.get("pattern")
        pats = r.get("patterns", [])

        if match == "contains" and pat and pat.lower() in pk:
            family = label
        elif match == "startswith" and pat and pk.startswith(pat.lower()):
            family = label
        elif match == "regex" and pat and re.search(pat, product_key or ""):
            family = label
        elif match == "contains_any" and any(p.lower() in pk for p in pats):
            family = label

        if family:
            break

    if not family:
        family = PRODUCT_RULES["defaults"]["unknown_family_name"]

    vendor = product_key.split(":", 1)[0] if ":" in product_key else "unknown_vendor"
    return {"vendor": vendor, "family": family}


# ============================================================
# POSTGRES
# ============================================================


def pg_connect(cfg):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 not installed")
    db = cfg["database"]
    return psycopg2.connect(
        host=db["host"],
        port=db.get("port", 5432),
        dbname=db["name"],
        user=db["user"],
        password=db["password"],
    )


def init_db(cfg):
    conn = pg_connect(cfg)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS daily_product_metrics (
        snapshot_date TEXT,
        site_label TEXT,
        site_tag TEXT,
        product TEXT,
        vendor TEXT,
        product_family TEXT,
        open_crit INT, open_high INT, open_medium INT, open_low INT, open_total INT,
        new_crit INT, new_high INT, new_medium INT, new_low INT, new_total INT,
        fixed_crit INT, fixed_high INT, fixed_medium INT, fixed_low INT, fixed_total INT,
        PRIMARY KEY (snapshot_date, site_label, product)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS plugin_metadata (
        plugin_id BIGINT PRIMARY KEY,
        plugin_name TEXT,
        plugin_family TEXT,
        plugin_type TEXT,
        vendor TEXT,
        product TEXT,
        product_family TEXT,
        synopsis TEXT,
        description TEXT,
        solution TEXT,
        see_also JSONB,
        cvss3_base FLOAT,
        cvss3_vector TEXT,
        exploit_available BOOLEAN,
        exploited_by_malware BOOLEAN,
        has_patch BOOLEAN,
        patch_published TIMESTAMPTZ
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS plugin_cves (
        plugin_id BIGINT,
        cve TEXT,
        PRIMARY KEY (plugin_id, cve)
    );
    """)

    conn.commit()
    conn.close()


# ============================================================
# TENABLE HELPERS
# ============================================================


def tenable_session(base_url, access_key, secret_key):
    s = requests.Session()
    s.base_url = base_url.rstrip("/")
    s.headers.update(
        {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
        }
    )
    return s


def start_export(sess, filters):
    r = sess.post(f"{sess.base_url}/vulns/export", json={"filters": filters})
    r.raise_for_status()
    return r.json()["export_uuid"]


def poll_export(sess, uuid):
    while True:
        r = sess.get(f"{sess.base_url}/vulns/export/{uuid}/status").json()
        if r["status"] == "FINISHED":
            return r["chunks_available"]
        time.sleep(3)


def iter_chunks(sess, uuid, chunks):
    for c in chunks:
        r = sess.get(f"{sess.base_url}/vulns/export/{uuid}/chunks/{c}")
        r.raise_for_status()
        for v in r.json():
            yield v


# ============================================================
# COLLECTION
# ============================================================


def extract_plugin_id(plugin) -> Optional[int]:
    try:
        return int(plugin.get("id") or plugin.get("plugin_id"))
    except Exception:
        return None


def extract_cves(plugin) -> List[str]:
    c = plugin.get("cve") or plugin.get("cves") or []
    if isinstance(c, str):
        c = [c]
    return [x for x in c if str(x).startswith("CVE-")]


def product_key_from_cpe(plugin) -> str:
    for c in plugin.get("cpe", []) or []:
        if isinstance(c, str) and c.startswith("cpe:/"):
            p = c.split(":")
            if len(p) >= 4:
                return f"{p[2]}:{p[3]}"
    return f"{plugin.get('family', 'Other')} - {plugin.get('name', 'Unknown')}"


def collect_product_metrics(sess, cfg, window_days):
    metrics = {}
    plugin_meta = {}
    plugin_cves = {}

    filters = {"state": ["OPEN", "REOPENED", "FIXED"]}
    uuid = start_export(sess, filters)
    chunks = poll_export(sess, uuid)

    for f in iter_chunks(sess, uuid, chunks):
        plugin = f.get("plugin", {})
        pid = extract_plugin_id(plugin)
        if not pid:
            continue

        product = product_key_from_cpe(plugin)
        cls = classify_product(product)

        plugin_meta.setdefault(
            pid,
            {
                "plugin_id": pid,
                "plugin_name": plugin.get("name"),
                "plugin_family": plugin.get("family"),
                "plugin_type": plugin.get("type"),
                "vendor": cls["vendor"],
                "product": product,
                "product_family": cls["family"],
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
            },
        )

        for cve in extract_cves(plugin):
            plugin_cves.setdefault(pid, set()).add(cve)

    return metrics, plugin_meta, plugin_cves


# ============================================================
# DB WRITE
# ============================================================


def _as_jsonb(value):
    """
    Adapt Python dict/list to JSONB safely for psycopg2.
    - JSONB columns want Json(...) wrapper
    - Keep None as None
    - Keep plain strings as-is (they may already be URLs, etc.)
    """
    if value is None:
        return None
    if Json is None:
        # psycopg2 not installed / extras not available
        return value
    if isinstance(value, (dict, list)):
        return Json(value)
    return value


def write_plugin_enrichment(cfg, plugin_meta, plugin_cves):
    conn = pg_connect(cfg)
    cur = conn.cursor()

    upsert_sql = """
    INSERT INTO plugin_metadata (
        plugin_id,
        plugin_name,
        plugin_family,
        plugin_type,
        vendor,
        product,
        product_family,
        synopsis,
        description,
        solution,
        see_also,
        cvss3_base,
        cvss3_vector,
        exploit_available,
        exploited_by_malware,
        has_patch,
        patch_published
    ) VALUES (
        %(plugin_id)s,
        %(plugin_name)s,
        %(plugin_family)s,
        %(plugin_type)s,
        %(vendor)s,
        %(product)s,
        %(product_family)s,
        %(synopsis)s,
        %(description)s,
        %(solution)s,
        %(see_also)s,
        %(cvss3_base)s,
        %(cvss3_vector)s,
        %(exploit_available)s,
        %(exploited_by_malware)s,
        %(has_patch)s,
        %(patch_published)s
    )
    ON CONFLICT (plugin_id) DO UPDATE SET
        plugin_name = EXCLUDED.plugin_name,
        plugin_family = EXCLUDED.plugin_family,
        plugin_type = EXCLUDED.plugin_type,
        vendor = EXCLUDED.vendor,
        product = EXCLUDED.product,
        product_family = EXCLUDED.product_family,
        synopsis = EXCLUDED.synopsis,
        description = EXCLUDED.description,
        solution = EXCLUDED.solution,
        see_also = EXCLUDED.see_also,
        cvss3_base = EXCLUDED.cvss3_base,
        cvss3_vector = EXCLUDED.cvss3_vector,
        exploit_available = EXCLUDED.exploit_available,
        exploited_by_malware = EXCLUDED.exploited_by_malware,
        has_patch = EXCLUDED.has_patch,
        patch_published = EXCLUDED.patch_published;
    """

    def adapt_value(v):
        # Convert dict/list to JSON for json/jsonb columns (or just to be safe)
        if v is None:
            return None
        if Json is not None and isinstance(v, (dict, list)):
            return Json(v)
        return v

    for p in plugin_meta.values():
        p2 = {k: adapt_value(v) for k, v in p.items()}

        # Optional: if you want to SEE what fields are dict/list BEFORE wrapping, uncomment:
        # for k, v in p.items():
        #     if isinstance(v, dict):
        #         print(f"[DICT] plugin_id={p.get('plugin_id')} field={k} keys={list(v)[:10]}")
        #     if isinstance(v, list):
        #         print(f"[LIST] plugin_id={p.get('plugin_id')} field={k} len={len(v)}")

        try:
            cur.execute(upsert_sql, p2)
        except Exception as e:
            # Helpful crash context
            print(f"[!] Failed upsert for plugin_id={p.get('plugin_id')}: {e}")
            print("[!] Param types:", {k: type(v).__name__ for k, v in p.items()})
            raise

    for pid, cves in plugin_cves.items():
        for cve in cves:
            cur.execute("""
            INSERT INTO plugin_cves (plugin_id, cve)
            VALUES (%s,%s) ON CONFLICT DO NOTHING;
            """, (pid, cve))

    conn.commit()
    conn.close()

# ============================================================
# MAIN
# ============================================================


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--window-days", type=int, default=90)
    parser.add_argument("--dump-json", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    init_db(cfg)

    ten = cfg["tenable"]
    sess = tenable_session(ten["base_url"], ten["access_key"], ten["secret_key"])

    _, plugin_meta, plugin_cves = collect_product_metrics(sess, cfg, args.window_days)
    write_plugin_enrichment(cfg, plugin_meta, plugin_cves)

    if args.dump_json:
        today = dt.date.today().isoformat()
        with open(f"plugin_meta_{today}.json", "w") as f:
            json.dump(plugin_meta, f, indent=2, default=str)

    print("[+] Plugin enrichment complete")


if __name__ == "__main__":
    main()
