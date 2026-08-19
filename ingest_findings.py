#!/usr/bin/env python3
"""
Nightly findings ingest: runs each enabled vendor adapter ONCE, upserts
into the normalized vuln_findings / vuln_finding_cves tables, and writes
any plugin/CVE catalog data the adapter collected along the way.

This replaces the fetch/classify logic that used to live independently in
tenable_trend_collector.py, fill_daily_product_metrics.py, and
tenable_product_drivers.py (three separate Tenable exports per night).
daily_site_metrics / daily_sla_metrics / daily_product_metrics / KEV
rollups are now derived from vuln_findings by rollup_daily_metrics.py,
not computed here.
"""
import argparse
from typing import Any, Dict

import config as config_mod
import db_schema
import plugin_catalog
from db import pg_connect
from vendors import ADAPTERS
from vendors.base import NormalizedFinding

UPSERT_FINDING_SQL = """
INSERT INTO vuln_findings (
    source, source_asset_id, source_rule_id, port, protocol,
    state, severity, cvss_score, cvss_vector,
    title, plugin_family, synopsis, solution,
    is_remote_no_auth, exploit_available, exploited_by_malware,
    has_patch, patch_published,
    product_key, product_vendor, product_family,
    site_label, site_tag, asset_type, hostname,
    first_found, last_found, last_fixed,
    last_seen_in_export, updated_at
) VALUES (
    %(source)s, %(source_asset_id)s, %(source_rule_id)s, %(port)s, %(protocol)s,
    %(state)s, %(severity)s, %(cvss_score)s, %(cvss_vector)s,
    %(title)s, %(plugin_family)s, %(synopsis)s, %(solution)s,
    %(is_remote_no_auth)s, %(exploit_available)s, %(exploited_by_malware)s,
    %(has_patch)s, %(patch_published)s,
    %(product_key)s, %(product_vendor)s, %(product_family)s,
    %(site_label)s, %(site_tag)s, %(asset_type)s, %(hostname)s,
    %(first_found)s, %(last_found)s, %(last_fixed)s,
    now(), now()
)
ON CONFLICT (source, source_asset_id, source_rule_id, port, protocol)
DO UPDATE SET
    state = EXCLUDED.state,
    severity = EXCLUDED.severity,
    cvss_score = EXCLUDED.cvss_score,
    cvss_vector = EXCLUDED.cvss_vector,
    title = EXCLUDED.title,
    plugin_family = EXCLUDED.plugin_family,
    synopsis = EXCLUDED.synopsis,
    solution = EXCLUDED.solution,
    is_remote_no_auth = EXCLUDED.is_remote_no_auth,
    exploit_available = EXCLUDED.exploit_available,
    exploited_by_malware = EXCLUDED.exploited_by_malware,
    has_patch = EXCLUDED.has_patch,
    patch_published = EXCLUDED.patch_published,
    product_key = EXCLUDED.product_key,
    product_vendor = EXCLUDED.product_vendor,
    product_family = EXCLUDED.product_family,
    site_label = EXCLUDED.site_label,
    site_tag = EXCLUDED.site_tag,
    asset_type = EXCLUDED.asset_type,
    hostname = EXCLUDED.hostname,
    first_found = LEAST(vuln_findings.first_found, EXCLUDED.first_found),
    last_found = EXCLUDED.last_found,
    last_fixed = EXCLUDED.last_fixed,
    last_seen_in_export = now(),
    updated_at = now()
RETURNING id;
"""


def _upsert_finding(cur, nf: NormalizedFinding) -> int:
    cur.execute(UPSERT_FINDING_SQL, {
        "source": nf.source,
        "source_asset_id": nf.source_asset_id,
        "source_rule_id": nf.source_rule_id,
        "port": nf.port,
        "protocol": nf.protocol,
        "state": nf.state,
        "severity": nf.severity,
        "cvss_score": nf.cvss_score,
        "cvss_vector": nf.cvss_vector,
        "title": nf.title,
        "plugin_family": nf.plugin_family,
        "synopsis": nf.synopsis,
        "solution": nf.solution,
        "is_remote_no_auth": nf.is_remote_no_auth,
        "exploit_available": nf.exploit_available,
        "exploited_by_malware": nf.exploited_by_malware,
        "has_patch": nf.has_patch,
        "patch_published": nf.patch_published,
        "product_key": nf.product_key,
        "product_vendor": nf.product_vendor,
        "product_family": nf.product_family,
        "site_label": nf.site_label,
        "site_tag": nf.site_tag,
        "asset_type": nf.asset_type,
        "hostname": nf.hostname,
        "first_found": nf.first_found,
        "last_found": nf.last_found,
        "last_fixed": nf.last_fixed,
    })
    return cur.fetchone()[0]


def _sync_cves(cur, finding_id: int, cves) -> None:
    cur.execute("DELETE FROM vuln_finding_cves WHERE finding_id = %s", (finding_id,))
    for cve in cves:
        cur.execute(
            "INSERT INTO vuln_finding_cves (finding_id, cve) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (finding_id, cve),
        )


def ingest_source(cfg: Dict[str, Any], source_name: str, source_type: str) -> None:
    adapter = ADAPTERS.get(source_type)
    if adapter is None:
        raise RuntimeError(
            f"No adapter registered for source type '{source_type}' "
            f"(source '{source_name}'). Known types: {sorted(ADAPTERS)}"
        )

    print(f"[ingest] Running adapter '{source_type}' for source '{source_name}'...")
    findings, plugin_meta, plugin_cves = adapter.fetch_findings(cfg)
    print(f"[ingest] Adapter '{source_type}' returned {len(findings)} findings")

    conn = pg_connect(cfg)
    cur = conn.cursor()

    count = 0
    for nf in findings:
        finding_id = _upsert_finding(cur, nf)
        _sync_cves(cur, finding_id, nf.cves)
        count += 1
        if count % 2000 == 0:
            conn.commit()
            print(f"[ingest] {count} findings upserted...")

    conn.commit()
    conn.close()
    print(f"[ingest] Done upserting {count} findings for source '{source_name}'.")

    if plugin_meta:
        print(f"[ingest] Writing plugin catalog ({len(plugin_meta)} plugins)...")
        plugin_catalog.write_plugin_enrichment(cfg, plugin_meta, plugin_cves)


def main():
    parser = argparse.ArgumentParser(description="Ingest vulnerability findings from all enabled sources")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = config_mod.load_config(args.config)

    db_schema.ensure_schema(cfg)
    plugin_catalog.init_plugin_catalog(cfg)

    sources = cfg.get("sources") or [{"name": "tenable", "type": "tenable", "enabled": True}]

    for src in sources:
        if not src.get("enabled", True):
            print(f"[ingest] Skipping disabled source '{src.get('name')}'")
            continue
        ingest_source(cfg, src.get("name", src.get("type")), src["type"])

    print("[ingest] All sources complete.")


if __name__ == "__main__":
    main()
