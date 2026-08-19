#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import time
from collections import defaultdict
from typing import Dict, Any, Iterable, Tuple

import requests
import yaml

try:
    import psycopg2
except ImportError:
    psycopg2 = None

# Reuse your existing logic so product family rules stay consistent
from tenable_product_drivers import (
    load_config,
    pg_connect,
    tenable_session,
    start_export,
    poll_export,
    iter_chunks,
    classify_product,
    product_key_from_cpe,
)

# Reuse trend collector's site labeling logic (copied in minimal form)
def site_label_from_tags(asset_tags, site_cfg: Dict[str, str], tag_cfg: Dict[str, Any], ungrouped: str) -> str:
    """
    Determine site label from tags.
    tag_cfg.site_category defaults to "Sites".
    site_cfg maps tag key -> label.
    """
    cat = str(tag_cfg.get("site_category", "Sites"))

    # Dict-style tags
    for t in asset_tags or []:
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

    # String-style tags like "Sites:BH-Site"
    for t in asset_tags or []:
        if isinstance(t, str):
            s = t.strip()
            if ":" in s:
                s_cat, s_val = s.split(":", 1)
                if s_cat == cat and s_val in site_cfg:
                    return site_cfg[s_val]

    return ungrouped


def fetch_all_assets_tags(sess: requests.Session) -> Dict[str, Any]:
    """
    Export all assets with tags (assets/export). Returns: asset_uuid -> tags
    """
    resp = sess.post(
        f"{sess.base_url}/assets/export",
        json={"include_attributes": ["tags"], "chunk_size": 5000},
    )
    resp.raise_for_status()
    data = resp.json()
    uuid = data.get("export_uuid")
    if not uuid:
        raise RuntimeError(f"Asset export UUID missing: {data}")

    # poll
    while True:
        status = sess.get(f"{sess.base_url}/assets/export/{uuid}/status").json()
        if status.get("status") == "FINISHED":
            break
        if status.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Asset export failed: {status}")
        time.sleep(2)

    chunks = status.get("chunks_available", []) or []
    out: Dict[str, Any] = {}

    for c in chunks:
        chunk = sess.get(f"{sess.base_url}/assets/export/{uuid}/chunks/{c}").json()
        # tenants vary: list or {assets:[...]}
        assets = chunk if isinstance(chunk, list) else chunk.get("assets", chunk)
        for a in assets:
            aid = a.get("id") or a.get("uuid")
            tags = a.get("tags") or []
            if aid:
                out[aid] = tags

    return out


def classify_sev_bucket(finding: Dict[str, Any]) -> str | None:
    """
    Map Tenable finding severity into one of: crit/high/medium/low.
    Uses numeric 'severity' if present, else string.
    """
    sev_raw = finding.get("severity")
    if sev_raw is None:
        sev_raw = finding.get("severity_id")

    # Tenable: 4=critical,3=high,2=medium,1=low,0=info
    try:
        s = int(sev_raw)
        return {4: "crit", 3: "high", 2: "medium", 1: "low"}.get(s)
    except Exception:
        pass

    if isinstance(sev_raw, str):
        s = sev_raw.strip().lower()
        return {"critical": "crit", "high": "high", "medium": "medium", "low": "low"}.get(s)

    return None


def init_daily_product_metrics(conn):
    """
    Ensure the table exists with expected columns.
    (Does NOT alter existing types; it only creates if missing.)
    """
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS public.daily_product_metrics (
        snapshot_date date NOT NULL,
        site_label text NOT NULL,
        site_tag text,
        product text NOT NULL,
        open_crit integer NOT NULL DEFAULT 0,
        open_high integer NOT NULL DEFAULT 0,
        open_medium integer NOT NULL DEFAULT 0,
        open_low integer NOT NULL DEFAULT 0,
        open_total integer NOT NULL DEFAULT 0,
        new_crit integer NOT NULL DEFAULT 0,
        new_high integer NOT NULL DEFAULT 0,
        new_medium integer NOT NULL DEFAULT 0,
        new_low integer NOT NULL DEFAULT 0,
        new_total integer NOT NULL DEFAULT 0,
        fixed_crit integer NOT NULL DEFAULT 0,
        fixed_high integer NOT NULL DEFAULT 0,
        fixed_medium integer NOT NULL DEFAULT 0,
        fixed_low integer NOT NULL DEFAULT 0,
        fixed_total integer NOT NULL DEFAULT 0,
        vendor text,
        product_family text,
        PRIMARY KEY (snapshot_date, site_label, product)
    );
    """)
    conn.commit()


def upsert_rows(conn, snapshot_date: dt.date, rows: Dict[Tuple[str, str, str], Dict[str, Any]]):
    """
    rows key: (site_label, site_tag, product)
    """
    cur = conn.cursor()

    sql = """
    INSERT INTO public.daily_product_metrics (
        snapshot_date, site_label, site_tag, product,
        open_crit, open_high, open_medium, open_low, open_total,
        new_crit, new_high, new_medium, new_low, new_total,
        fixed_crit, fixed_high, fixed_medium, fixed_low, fixed_total,
        vendor, product_family
    ) VALUES (
        %(snapshot_date)s, %(site_label)s, %(site_tag)s, %(product)s,
        %(open_crit)s, %(open_high)s, %(open_medium)s, %(open_low)s, %(open_total)s,
        %(new_crit)s, %(new_high)s, %(new_medium)s, %(new_low)s, %(new_total)s,
        %(fixed_crit)s, %(fixed_high)s, %(fixed_medium)s, %(fixed_low)s, %(fixed_total)s,
        %(vendor)s, %(product_family)s
    )
    ON CONFLICT (snapshot_date, site_label, product)
    DO UPDATE SET
        site_tag     = EXCLUDED.site_tag,
        open_crit    = EXCLUDED.open_crit,
        open_high    = EXCLUDED.open_high,
        open_medium  = EXCLUDED.open_medium,
        open_low     = EXCLUDED.open_low,
        open_total   = EXCLUDED.open_total,
        new_crit     = EXCLUDED.new_crit,
        new_high     = EXCLUDED.new_high,
        new_medium   = EXCLUDED.new_medium,
        new_low      = EXCLUDED.new_low,
        new_total    = EXCLUDED.new_total,
        fixed_crit   = EXCLUDED.fixed_crit,
        fixed_high   = EXCLUDED.fixed_high,
        fixed_medium = EXCLUDED.fixed_medium,
        fixed_low    = EXCLUDED.fixed_low,
        fixed_total  = EXCLUDED.fixed_total,
        vendor       = EXCLUDED.vendor,
        product_family = EXCLUDED.product_family;
    """

    for (site_label, site_tag, product), d in rows.items():
        payload = {
            "snapshot_date": snapshot_date,
            "site_label": site_label,
            "site_tag": site_tag,
            "product": product,
            **d,
        }
        cur.execute(sql, payload)

    conn.commit()


def collect_for_day(sess: requests.Session, cfg: Dict[str, Any], snapshot_date: dt.date, new_window_days: int):
    """
    Collect product metrics for ONE snapshot day.
    NOTE: Tenable's export is 'current state' biased; snapshot_date is "date collected".
    """
    # assets -> tags lookup
    asset_tags = fetch_all_assets_tags(sess)

    tag_cfg = cfg.get("tags", {})
    site_cfg = {s["key"]: s["label"] for s in cfg.get("sites", [])}
    ungrouped = cfg.get("ungrouped_label", "Ungrouped")
    label_to_tag = {v: k for k, v in site_cfg.items()}  # label -> site_tag

    # "new" threshold (based on first_found epoch)
    now = int(time.time())
    new_cutoff = now - (new_window_days * 86400)

    # rollup dict
    # key = (site_label, site_tag, product)
    rows: Dict[Tuple[str, str, str], Dict[str, Any]] = defaultdict(lambda: {
        "open_crit": 0, "open_high": 0, "open_medium": 0, "open_low": 0, "open_total": 0,
        "new_crit": 0, "new_high": 0, "new_medium": 0, "new_low": 0, "new_total": 0,
        "fixed_crit": 0, "fixed_high": 0, "fixed_medium": 0, "fixed_low": 0, "fixed_total": 0,
        "vendor": None,
        "product_family": None,
    })

    # pull findings (OPEN/REOPENED/FIXED)
    filters = {"state": ["OPEN", "REOPENED", "FIXED"], "severity": ["low", "medium", "high", "critical"]}
    export_uuid = start_export(sess, filters)
    chunks = poll_export(sess, export_uuid)
    if isinstance(chunks, dict):
        chunks = chunks.get("chunks_available") or []


    for f in iter_chunks(sess, export_uuid, chunks):
        state = (f.get("state") or "").upper()
        sev_bucket = classify_sev_bucket(f)
        if not sev_bucket:
            continue

        plugin = f.get("plugin", {}) or {}
        product = product_key_from_cpe(plugin)
        cls = classify_product(product)
        vendor = cls.get("vendor")
        family = cls.get("family")

        asset = f.get("asset", {}) or {}
        aid = asset.get("uuid") or asset.get("id")
        tags = asset_tags.get(aid, [])
        label = site_label_from_tags(tags, site_cfg, tag_cfg, ungrouped)
        site_tag = label_to_tag.get(label, "UNGROUPED" if label == ungrouped else label)

        key = (label, site_tag, product)
        bucket = rows[key]
        bucket["vendor"] = vendor
        bucket["product_family"] = family

        # open/fixed
        if state in ("OPEN", "REOPENED"):
            bucket[f"open_{sev_bucket}"] += 1
            bucket["open_total"] += 1

            # new window (based on first_found/first_seen)
            first_found = f.get("first_found") or f.get("first_seen")
            try:
                if first_found is not None and int(first_found) >= new_cutoff:
                    bucket[f"new_{sev_bucket}"] += 1
                    bucket["new_total"] += 1
            except Exception:
                pass

        elif state == "FIXED":
            bucket[f"fixed_{sev_bucket}"] += 1
            bucket["fixed_total"] += 1

    return rows


def main():
    ap = argparse.ArgumentParser(description="Fill/Backfill public.daily_product_metrics from Tenable exports")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--new-window-days", type=int, default=7, help="Count 'new_*' as first_found within N days")
    ap.add_argument("--days", type=int, default=1, help="How many days to run (1 = today only; N = backfill N days)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    ten = cfg["tenable"]
    sess = tenable_session(ten["base_url"], ten["access_key"], ten["secret_key"])

    conn = pg_connect(cfg)
    try:
        init_daily_product_metrics(conn)

        for i in range(args.days):
            snap = dt.date.today() - dt.timedelta(days=i)
            print(f"[+] Collecting daily_product_metrics for {snap} (new_window_days={args.new_window_days})")
            rows = collect_for_day(sess, cfg, snap, args.new_window_days)
            print(f"[+] Upserting {len(rows)} product rows for {snap}")
            upsert_rows(conn, snap, rows)

        print("[+] Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
