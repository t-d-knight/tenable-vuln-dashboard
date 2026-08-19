#!/usr/bin/env python3
"""
Run this before wiring vuln-dashboard.json into a live Grafana instance.
Checks that everything the dashboard's panels query actually exists and
has data, so a broken import shows up here instead of as a wall of "No
data" panels in Grafana.

Usage:
  python3 grafana/preflight_check.py --config config.yaml
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load_config
from db import pg_connect

# (name, kind, empty_is_fatal, empty_hint)
REQUIRED_RELATIONS = [
    ("vuln_findings", "table", True, "Run ingest_findings.py first."),
    ("vuln_finding_cves", "table", False, "Empty until findings with CVEs are ingested -- OK if vuln_findings is also empty."),
    ("cisa_kev", "table", True, "Run kev_sync.py first (CISA KEV feed sync)."),
    ("daily_site_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_sla_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_product_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_kev_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_mttr_metrics", "table", False, "Empty until findings have actually been fixed -- not fatal early on."),
    ("fact_vuln_findings_current", "view", True, "Run db_schema.ensure_schema() (any of ingest_findings.py / rollup_daily_metrics.py / kev_sync.py does this)."),
    ("dim_site", "view", True, "Same as above."),
    ("dim_product", "view", False, "Empty until findings have a classified product_key."),
    ("asset_risk_summary", "view", True, "Same as fact_vuln_findings_current."),
]


def check_relation_exists(cur, name: str) -> bool:
    cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{name}",))
    return bool(cur.fetchone()[0])


def check_row_count(cur, name: str) -> int:
    cur.execute(f"SELECT count(*) FROM {name}")  # nosec: name is from our own fixed allowlist above
    return cur.fetchone()[0]


def check_grafana_service_local() -> None:
    """
    Best-effort check for a local grafana-server systemd unit. Only
    meaningful if this script runs on the same host as Grafana (or is
    meant to) -- purely informational, never fatal, since Grafana may
    legitimately live elsewhere or run some other way (container, etc).
    """
    import shutil
    import subprocess

    if not shutil.which("systemctl"):
        print("[SKIP] Local grafana-server service check -- systemctl not available on this host.")
        return

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "grafana-server"],
            capture_output=True, text=True, timeout=5,
        )
        state = result.stdout.strip()
        if state == "active":
            print("[PASS] grafana-server systemd service is active on this host.")
        elif state in ("inactive", "failed"):
            print(f"[WARN] grafana-server systemd service is installed but {state} -- "
                  f"start it with: sudo systemctl enable --now grafana-server")
        else:
            print("[INFO] grafana-server systemd service not found on this host "
                  "(status: not-found) -- Grafana isn't installed here yet, or runs elsewhere.")
    except Exception as e:
        print(f"[SKIP] Local grafana-server service check failed: {e}")


def check_grafana_reachable(cfg) -> bool:
    """Returns True only if Grafana was actually confirmed reachable and healthy."""
    grafana_cfg = cfg.get("grafana") or {}
    url = grafana_cfg.get("url")
    guessed = False
    if not url:
        url = "http://127.0.0.1:3000"
        guessed = True
        print(f"[INFO] No `grafana.url` set in config.yaml -- guessing {url} (default Grafana port on this host).")
        print("       Set `grafana: {url: 'http://your-grafana-host:3000'}` in config.yaml once you know the real address.")

    try:
        import requests
    except ImportError:
        print("[SKIP] Grafana HTTP reachability -- `requests` not installed.")
        return False

    try:
        resp = requests.get(f"{url.rstrip('/')}/api/health", timeout=5)
        if resp.status_code == 200:
            print(f"[PASS] Grafana reachable at {url}")
            return True
        print(f"[WARN] Grafana at {url} responded with status {resp.status_code}")
        return False
    except requests.RequestException as e:
        level = "INFO" if guessed else "FAIL"
        print(f"[{level}] Could not reach Grafana at {url}: {e}")
        if guessed:
            print("       This is expected if Grafana isn't installed on this host yet -- "
                  "see the README's Grafana install steps.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Preflight check before importing vuln-dashboard.json into Grafana")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)

    print("=== Postgres connectivity ===")
    try:
        conn = pg_connect(cfg)
    except Exception as e:
        print(f"[FAIL] Could not connect to Postgres: {e}")
        sys.exit(1)
    print("[PASS] Connected to Postgres.")

    cur = conn.cursor()
    fatal_failures = 0

    print("\n=== Required tables/views ===")
    for name, kind, empty_is_fatal, hint in REQUIRED_RELATIONS:
        if not check_relation_exists(cur, name):
            print(f"[FAIL] {kind} '{name}' does not exist. {hint}")
            fatal_failures += 1
            continue

        count = check_row_count(cur, name)
        if count == 0:
            level = "FAIL" if empty_is_fatal else "WARN"
            print(f"[{level}] {kind} '{name}' exists but has 0 rows. {hint}")
            if empty_is_fatal:
                fatal_failures += 1
        else:
            print(f"[PASS] {kind} '{name}' exists, {count} row(s).")

    print("\n=== Site coverage ===")
    configured_sites = {s["label"] for s in cfg.get("sites", [])}
    seen_sites = set()
    if check_relation_exists(cur, "dim_site"):
        cur.execute("SELECT DISTINCT site_label FROM dim_site")
        seen_sites = {r[0] for r in cur.fetchall()}

    missing = configured_sites - seen_sites
    if not seen_sites:
        print("[WARN] dim_site has no rows yet -- the Grafana $site variable will be empty until ingest runs.")
    elif missing:
        print(f"[WARN] Configured sites with no findings yet (won't appear in $site until they do): {sorted(missing)}")
    else:
        print(f"[PASS] All {len(configured_sites)} configured sites have appeared in vuln_findings.")

    print("\n=== Grafana ===")
    check_grafana_service_local()
    grafana_up = check_grafana_reachable(cfg)

    conn.close()

    print("\n=== Summary ===")
    if fatal_failures:
        print(f"{fatal_failures} fatal issue(s) found. Fix these before importing vuln-dashboard.json.")
        sys.exit(1)
    else:
        print("All required tables/views are present and populated -- the data side is ready.")
        if grafana_up:
            print("Grafana is reachable. Remaining manual steps: add a PostgreSQL datasource pointing at this "
                  "database, then Import Dashboard -> upload vuln-dashboard.json -> select that datasource "
                  "for DS_POSTGRESQL.")
        else:
            print("Grafana itself is NOT confirmed reachable -- install/start it first (see README Section 11a) "
                  "before the datasource + dashboard import steps will make sense.")


if __name__ == "__main__":
    main()
