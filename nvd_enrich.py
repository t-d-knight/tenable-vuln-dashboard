#!/usr/bin/env python3
"""
Backfills vuln_findings.cvss_vector / cvss_score from NVD for CVE-backed
findings the source vendor didn't provide a vector for. Only helps
findings that actually have a CVE -- there's nothing to look up for
non-CVE findings (compliance/misconfiguration checks), those stay on the
vendor's own severity fallback.

Rate-limited and cached: NVD allows 5 requests/30s without an API key, 50/30s
with a free one (set reporting via secrets.yaml's `nvd: api_key:`). Every
lookup result -- found or not -- is cached in nvd_cvss_cache so a given CVE
is never queried more than necessary; "not found" results are retried after
--retry-after-days, since NVD's own analyst backlog means a CVE with no
score today may have one in a few weeks.

--max-lookups caps how much a single run does, so this works through a
large backlog gradually across nightly runs instead of stalling the
pipeline on a first-run flood of NVD requests.
"""
import argparse
import time
from typing import Any, Dict, List, Optional

import requests

import config as config_mod
import db_schema
from db import pg_connect

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Preferred CVSS version order: newest first
METRIC_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]


def _best_cvss(cve_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    metrics = cve_obj.get("metrics", {}) or {}
    for key in METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer NVD's own "Primary" source over CNA-supplied "Secondary"
        primary = [e for e in entries if e.get("type") == "Primary"]
        chosen = (primary or entries)[0]
        data = chosen.get("cvssData", {})
        if not data.get("vectorString"):
            continue
        return {
            "vector": data.get("vectorString"),
            "score": data.get("baseScore"),
            "version": data.get("version"),
        }
    return None


def lookup_cve(session: requests.Session, cve_id: str) -> Optional[Dict[str, Any]]:
    resp = session.get(NVD_API_URL, params={"cveId": cve_id}, timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    return _best_cvss(vulns[0].get("cve", {}))


def fetch_pending_cves(cur, retry_after_days: int, max_lookups: int) -> List[str]:
    cur.execute(
        """
        SELECT DISTINCT fc.cve
        FROM vuln_finding_cves fc
        JOIN vuln_findings vf ON vf.id = fc.finding_id
        LEFT JOIN nvd_cvss_cache c ON c.cve_id = fc.cve
        WHERE vf.cvss_vector IS NULL
          AND (
                c.cve_id IS NULL
                OR (c.found = FALSE AND c.checked_at < now() - (%(days)s || ' days')::interval)
              )
        LIMIT %(limit)s
        """,
        {"days": retry_after_days, "limit": max_lookups},
    )
    return [r[0] for r in cur.fetchall()]


def apply_to_findings(cur, cve_id: str, vector: str, score: Optional[float]) -> int:
    cur.execute(
        """
        UPDATE vuln_findings vf
        SET cvss_vector = %s, cvss_score = %s
        FROM vuln_finding_cves fc
        WHERE fc.finding_id = vf.id AND fc.cve = %s AND vf.cvss_vector IS NULL
        """,
        (vector, score, cve_id),
    )
    return cur.rowcount


def main():
    parser = argparse.ArgumentParser(description="Backfill CVSS vectors from NVD for CVE-backed findings missing one")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--max-lookups", type=int, default=200, help="Cap on new NVD lookups this run")
    parser.add_argument("--retry-after-days", type=int, default=14, help="Re-check CVEs NVD had nothing for, after this many days")
    args = parser.parse_args()

    cfg = config_mod.load_config(args.config)
    db_schema.ensure_schema(cfg)

    nvd_cfg = cfg.get("nvd", {}) or {}
    api_key = nvd_cfg.get("api_key")
    delay = 0.7 if api_key else 6.5
    if not api_key:
        print("[nvd] No nvd.api_key configured -- using the public 5 req/30s rate limit. "
              "Register a free key at nvd.nist.gov and set it in secrets.yaml for ~10x faster backfill.")

    conn = pg_connect(cfg)
    cur = conn.cursor()

    pending = fetch_pending_cves(cur, args.retry_after_days, args.max_lookups)
    print(f"[nvd] {len(pending)} CVE(s) to look up this run (max_lookups={args.max_lookups})")

    if not pending:
        conn.close()
        return

    session = requests.Session()
    if api_key:
        session.headers.update({"apiKey": api_key})

    found_count = 0
    backfilled_rows = 0

    for i, cve_id in enumerate(pending, start=1):
        try:
            result = lookup_cve(session, cve_id)
        except requests.RequestException as e:
            print(f"[nvd] [{i}/{len(pending)}] {cve_id}: request failed ({e}), will retry next run")
            time.sleep(delay)
            continue

        found = result is not None
        vector = result.get("vector") if result else None
        score = result.get("score") if result else None
        version = result.get("version") if result else None

        cur.execute(
            """
            INSERT INTO nvd_cvss_cache (cve_id, cvss_vector, cvss_score, cvss_version, found, checked_at)
            VALUES (%s, %s, %s, %s, %s, now())
            ON CONFLICT (cve_id) DO UPDATE SET
                cvss_vector = EXCLUDED.cvss_vector,
                cvss_score = EXCLUDED.cvss_score,
                cvss_version = EXCLUDED.cvss_version,
                found = EXCLUDED.found,
                checked_at = now();
            """,
            (cve_id, vector, score, version, found),
        )

        if found:
            found_count += 1
            backfilled_rows += apply_to_findings(cur, cve_id, vector, score)

        if i % 20 == 0:
            conn.commit()
            print(f"[nvd] [{i}/{len(pending)}] progress: {found_count} found so far")

        time.sleep(delay)

    conn.commit()
    conn.close()
    print(f"[nvd] Done. {found_count}/{len(pending)} CVEs had NVD CVSS data, "
          f"backfilled {backfilled_rows} vuln_findings row(s).")


if __name__ == "__main__":
    main()
