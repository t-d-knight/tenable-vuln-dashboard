#!/usr/bin/env python3
"""
Syncs the FIRST.org EPSS (Exploit Prediction Scoring System) daily bulk
export into epss_scores. Public, no auth -- whole-catalog CSV download,
same shape as kev_sync.py, no rate-limit concerns since it's one request.

EPSS gives a daily-updated probability (0-1) that a CVE will be exploited
in the wild in the next 30 days -- the complement to CISA KEV (which is
binary/confirmed, not predictive) and CVSS (which scores severity, not
likelihood).
"""
import argparse
import csv
import gzip
import re
from typing import List, Optional, Tuple

import requests
from psycopg2.extras import execute_values

import config as config_mod
import db_schema
from db import pg_connect

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_epss_csv(url: str = EPSS_CSV_URL) -> Tuple[List[Tuple[str, float, float]], Optional[str]]:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    raw = gzip.decompress(resp.content).decode("utf-8")
    lines = raw.splitlines()

    score_date = None
    if lines and lines[0].startswith("#"):
        m = re.search(r"score_date:(\S+)", lines[0])
        if m:
            score_date = m.group(1)[:10]  # YYYY-MM-DD prefix off the ISO timestamp
        lines = lines[1:]

    reader = csv.DictReader(lines)
    rows = [(r["cve"], float(r["epss"]), float(r["percentile"])) for r in reader]
    return rows, score_date


def main():
    parser = argparse.ArgumentParser(description="Sync the FIRST.org EPSS catalog into epss_scores")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = config_mod.load_config(args.config)
    db_schema.ensure_schema(cfg)

    print("[epss] Downloading EPSS bulk export...")
    rows, score_date = fetch_epss_csv()
    print(f"[epss] Fetched {len(rows)} EPSS scores (score_date={score_date})")

    conn = pg_connect(cfg)
    cur = conn.cursor()

    data = [(cve, epss, pct, score_date) for cve, epss, pct in rows]
    execute_values(
        cur,
        """
        INSERT INTO epss_scores (cve_id, epss, percentile, score_date, synced_at)
        VALUES %s
        ON CONFLICT (cve_id) DO UPDATE SET
            epss = EXCLUDED.epss,
            percentile = EXCLUDED.percentile,
            score_date = EXCLUDED.score_date,
            synced_at = now();
        """,
        data,
        template="(%s, %s, %s, %s::date, now())",
        page_size=5000,
    )

    conn.commit()
    conn.close()
    print(f"[epss] Upserted {len(data)} EPSS scores.")


if __name__ == "__main__":
    main()
