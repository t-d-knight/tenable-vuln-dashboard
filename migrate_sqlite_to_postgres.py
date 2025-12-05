#!/usr/bin/env python3
import sqlite3
from pathlib import Path
from typing import Dict, Any

import psycopg2
from psycopg2.extras import execute_values
import yaml
import os


# ------------------------------------------------------------
#  Config loader (supports secrets_file like main script)
# ------------------------------------------------------------

def load_config(path: str = None) -> Dict[str, Any]:
    """
    Load main config.yaml, then (optionally) merge in secrets from a separate
    secrets file, so callers can still do:
      cfg["tenable"]["access_key"]
      cfg["tenable"]["secret_key"]
      cfg["database"]["user"]
      cfg["database"]["password"]
    """
    if path is None:
        cfg_path = Path(__file__).with_name("config.yaml")
    else:
        cfg_path = Path(path)

    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = cfg_path.parent
        secrets_path = base_dir / secrets_rel

        if not secrets_path.is_file():
            raise FileNotFoundError(f"Secrets file not found: {secrets_path}")

        with secrets_path.open("r", encoding="utf-8") as sf:
            secrets = yaml.safe_load(sf) or {}

        # Merge Tenable creds (if present)
        if "tenable" in secrets:
            cfg.setdefault("tenable", {})
            cfg["tenable"].update(secrets["tenable"])

        # Merge DB creds (if present)
        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

    return cfg


# ------------------------------------------------------------
#  DB helpers
# ------------------------------------------------------------

def get_sqlite_conn(cfg):
    db_path = cfg["reporting"]["db_path"]
    db_path = Path(db_path)
    if not db_path.is_absolute():
        db_path = Path(__file__).with_name(db_path.name)
    print(f"[+] Using SQLite DB at: {db_path}")
    return sqlite3.connect(str(db_path))


def get_pg_conn(db_cfg):
    print(f"[+] Connecting to Postgres {db_cfg['host']}:{db_cfg.get('port', 5432)} / {db_cfg['name']}")
    conn = psycopg2.connect(
        host=db_cfg["host"],
        port=db_cfg.get("port", 5432),
        dbname=db_cfg["name"],
        user=db_cfg["user"],
        password=db_cfg["password"],
    )
    return conn


def init_pg_schema(pg_conn):
    cur = pg_conn.cursor()

    # daily_site_metrics
    cur.execute("""
        CREATE TABLE IF NOT EXISTS daily_site_metrics (
            snapshot_date DATE NOT NULL,
            site_label    TEXT NOT NULL,
            crit          INTEGER NOT NULL,
            high          INTEGER NOT NULL,
            medium        INTEGER NOT NULL,
            low           INTEGER NOT NULL,
            remote_crit   INTEGER NOT NULL,
            remote_high   INTEGER NOT NULL,
            assets        INTEGER NOT NULL,
            total         INTEGER NOT NULL,
            PRIMARY KEY (snapshot_date, site_label)
        )
    """)

    # daily_sla_metrics
    cur.execute("""
        CREATE TABLE IF NOT EXISTS daily_sla_metrics (
            snapshot_date   DATE NOT NULL,
            site_label      TEXT NOT NULL,
            risk            TEXT NOT NULL,
            total           INTEGER NOT NULL,
            breaches        INTEGER NOT NULL,
            remote_total    INTEGER NOT NULL,
            remote_breaches INTEGER NOT NULL,
            PRIMARY KEY (snapshot_date, site_label, risk)
        )
    """)

    pg_conn.commit()
    print("[+] Ensured Postgres tables exist.")


def get_sqlite_columns(conn, table_name):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    rows = cur.fetchall()
    # rows: cid, name, type, notnull, dflt_value, pk
    cols = [r[1] for r in rows]
    print(f"[debug] SQLite columns for {table_name}: {cols}")
    return cols


# ------------------------------------------------------------
#  Migration logic
# ------------------------------------------------------------

def migrate_daily_site_metrics(sqlite_conn, pg_conn):
    table_name = "daily_site_metrics"
    cols = get_sqlite_columns(sqlite_conn, table_name)

    sqlite_cur = sqlite_conn.cursor()
    sqlite_cur.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cur.fetchall()

    if not rows:
        print(f"[!] No rows found in {table_name}, skipping.")
        return

    canonical_rows = []
    for row in rows:
        row_map = dict(zip(cols, row))

        snapshot_date = row_map.get("snapshot_date")
        site_label = row_map.get("site_label")

        crit = row_map.get("crit", 0)
        high = row_map.get("high", 0)
        medium = row_map.get("medium", 0)
        low = row_map.get("low", 0)

        # Handle both new and legacy column names
        remote_crit = row_map.get(
            "remote_crit",
            row_map.get("remote_no_auth_crit", 0)
        )
        remote_high = row_map.get(
            "remote_high",
            row_map.get("remote_no_auth_high", 0)
        )

        assets = row_map.get(
            "assets",
            row_map.get("endpoints", 0)
        )

        total = row_map.get("total", 0)

        canonical_rows.append(
            (
                snapshot_date,
                site_label,
                crit,
                high,
                medium,
                low,
                remote_crit,
                remote_high,
                assets,
                total,
            )
        )

    print(f"[+] Migrating {len(canonical_rows)} rows from {table_name} to Postgres…")

    insert_sql = """
        INSERT INTO daily_site_metrics (
          snapshot_date, site_label,
          crit, high, medium, low,
          remote_crit, remote_high,
          assets, total
        ) VALUES %s
        ON CONFLICT (snapshot_date, site_label) DO UPDATE SET
          crit = EXCLUDED.crit,
          high = EXCLUDED.high,
          medium = EXCLUDED.medium,
          low = EXCLUDED.low,
          remote_crit = EXCLUDED.remote_crit,
          remote_high = EXCLUDED.remote_high,
          assets = EXCLUDED.assets,
          total = EXCLUDED.total;
    """

    with pg_conn.cursor() as pg_cur:
        execute_values(pg_cur, insert_sql, canonical_rows)

    pg_conn.commit()
    print(f"[+] Completed migration for {table_name}.")


def migrate_daily_sla_metrics(sqlite_conn, pg_conn):
    table_name = "daily_sla_metrics"
    cols = get_sqlite_columns(sqlite_conn, table_name)

    sqlite_cur = sqlite_conn.cursor()
    sqlite_cur.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cur.fetchall()

    if not rows:
        print(f"[!] No rows found in {table_name}, skipping.")
        return

    canonical_rows = []
    for row in rows:
        row_map = dict(zip(cols, row))

        snapshot_date = row_map.get("snapshot_date")
        site_label = row_map.get("site_label")
        risk = row_map.get("risk")

        # Support both old and new column names
        total = row_map.get("total", row_map.get("total_vulns", 0))
        breaches = row_map.get("breaches", row_map.get("sla_breaches", 0))
        remote_total = row_map.get("remote_total", row_map.get("remote_no_auth_vulns", 0))
        remote_breaches = row_map.get(
            "remote_breaches",
            row_map.get("remote_no_auth_breaches", 0)
        )

        canonical_rows.append(
            (
                snapshot_date,
                site_label,
                risk,
                total,
                breaches,
                remote_total,
                remote_breaches,
            )
        )

    print(f"[+] Migrating {len(canonical_rows)} rows from {table_name} to Postgres…")

    insert_sql = """
        INSERT INTO daily_sla_metrics (
          snapshot_date, site_label, risk,
          total, breaches,
          remote_total, remote_breaches
        ) VALUES %s
        ON CONFLICT (snapshot_date, site_label, risk) DO UPDATE SET
          total = EXCLUDED.total,
          breaches = EXCLUDED.breaches,
          remote_total = EXCLUDED.remote_total,
          remote_breaches = EXCLUDED.remote_breaches;
    """

    with pg_conn.cursor() as pg_cur:
        execute_values(pg_cur, insert_sql, canonical_rows)

    pg_conn.commit()
    print(f"[+] Completed migration for {table_name}.")


def main():
    cfg = load_config()

    if "database" not in cfg or cfg["database"].get("engine", "").lower() != "postgres":
        raise SystemExit("[!] config.yaml does not have database.engine: postgres configured.")

    db_cfg = cfg["database"]

    sqlite_conn = get_sqlite_conn(cfg)
    pg_conn = get_pg_conn(db_cfg)

    try:
        init_pg_schema(pg_conn)

        migrate_daily_site_metrics(sqlite_conn, pg_conn)
        migrate_daily_sla_metrics(sqlite_conn, pg_conn)

        print("[+] Migration complete.")

    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    main()
