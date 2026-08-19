#!/usr/bin/env python3
"""
Plugin/CVE catalog storage: metadata about each vendor detection rule
(Tenable plugin, etc.) and the CVEs it maps to. Populated as a side effect
of the nightly findings ingest (see vendors/tenable.py + ingest_findings.py).
"""
from typing import Any, Dict, Set

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    psycopg2 = None
    Json = None

from db import pg_connect


def init_plugin_catalog(cfg: Dict[str, Any]) -> None:
    conn = pg_connect(cfg)
    cur = conn.cursor()

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


def _adapt_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        if Json is not None:
            return Json(v)
        import json

        return json.dumps(v, default=str)
    return v


def write_plugin_enrichment(
    cfg: Dict[str, Any],
    plugin_meta: Dict[int, Dict[str, Any]],
    plugin_cves: Dict[int, Set[str]],
) -> None:
    conn = pg_connect(cfg)
    cur = conn.cursor()

    upsert_sql = """
    INSERT INTO plugin_metadata (
        plugin_id, plugin_name, plugin_family, plugin_type, vendor, product,
        product_family, synopsis, description, solution, see_also,
        cvss3_base, cvss3_vector, exploit_available, exploited_by_malware,
        has_patch, patch_published
    ) VALUES (
        %(plugin_id)s, %(plugin_name)s, %(plugin_family)s, %(plugin_type)s,
        %(vendor)s, %(product)s, %(product_family)s, %(synopsis)s,
        %(description)s, %(solution)s, %(see_also)s, %(cvss3_base)s,
        %(cvss3_vector)s, %(exploit_available)s, %(exploited_by_malware)s,
        %(has_patch)s, %(patch_published)s
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

    for p in plugin_meta.values():
        p2 = {k: _adapt_value(v) for k, v in p.items()}
        try:
            cur.execute(upsert_sql, p2)
        except Exception as e:
            print(f"[!] Failed upsert for plugin_id={p.get('plugin_id')}: {e}")
            raise

    for pid, cves in plugin_cves.items():
        for cve in cves:
            cur.execute(
                """
                INSERT INTO plugin_cves (plugin_id, cve)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
                """,
                (pid, cve),
            )

    conn.commit()
    conn.close()
