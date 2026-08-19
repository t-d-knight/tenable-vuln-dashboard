#!/usr/bin/env python3
"""
Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog and upserts
it into cisa_kev. Public feed, no auth required. Independent of everything
else in the pipeline -- run it any time, in any order, relative to ingest.
"""
import argparse
import datetime as dt
from typing import Any, Dict, Optional

import requests

import config as config_mod
import db_schema
from db import pg_connect

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(s: Optional[str]) -> Optional[dt.date]:
    if not s:
        return None
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        return None


def fetch_kev_catalog(url: str = KEV_FEED_URL) -> list:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    print(f"[kev] Fetched {len(vulns)} entries from CISA KEV catalog "
          f"(catalogVersion={data.get('catalogVersion')})")
    return vulns


def upsert_kev(cur, entry: Dict[str, Any]) -> None:
    cwes = entry.get("cwes") or []
    if isinstance(cwes, str):
        cwes = [cwes]

    cur.execute(
        """
        INSERT INTO cisa_kev (
            cve_id, vendor_project, product, vulnerability_name,
            date_added, short_description, required_action, due_date,
            known_ransomware_campaign_use, notes, cwes, synced_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
        ON CONFLICT (cve_id) DO UPDATE SET
            vendor_project = EXCLUDED.vendor_project,
            product = EXCLUDED.product,
            vulnerability_name = EXCLUDED.vulnerability_name,
            date_added = EXCLUDED.date_added,
            short_description = EXCLUDED.short_description,
            required_action = EXCLUDED.required_action,
            due_date = EXCLUDED.due_date,
            known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
            notes = EXCLUDED.notes,
            cwes = EXCLUDED.cwes,
            synced_at = now();
        """,
        (
            entry.get("cveID"),
            entry.get("vendorProject"),
            entry.get("product"),
            entry.get("vulnerabilityName"),
            _parse_date(entry.get("dateAdded")),
            entry.get("shortDescription"),
            entry.get("requiredAction"),
            _parse_date(entry.get("dueDate")),
            entry.get("knownRansomwareCampaignUse"),
            entry.get("notes"),
            cwes,
        ),
    )


def main():
    parser = argparse.ArgumentParser(description="Sync the CISA KEV catalog into cisa_kev")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = config_mod.load_config(args.config)
    db_schema.ensure_schema(cfg)

    vulns = fetch_kev_catalog()

    conn = pg_connect(cfg)
    cur = conn.cursor()

    count = 0
    for entry in vulns:
        if not entry.get("cveID"):
            continue
        upsert_kev(cur, entry)
        count += 1

    conn.commit()
    conn.close()
    print(f"[kev] Upserted {count} KEV entries.")


if __name__ == "__main__":
    main()
