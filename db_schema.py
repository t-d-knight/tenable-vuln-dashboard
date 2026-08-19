#!/usr/bin/env python3
"""
Idempotent schema for the vendor-agnostic findings core: vuln_findings,
vuln_finding_cves, cisa_kev, daily_kev_metrics, and the Power BI-facing
views (fact_vuln_findings_current, dim_site, dim_product).

Does NOT touch daily_site_metrics / daily_sla_metrics / daily_product_metrics
(those keep their existing per-script init_db() for now) or the
asset_inventory schema.
"""
from typing import Any, Dict

from db import pg_connect

DDL_STATEMENTS = [
    # Legacy snapshot tables (previously created by tenable_trend_collector.py
    # and fill_daily_product_metrics.py, now superseded by rollup_daily_metrics.py
    # but kept with their existing shape/types so old Power BI reports don't break).
    """
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
    """,
    """
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
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_product_metrics (
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
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_findings (
        id                   BIGSERIAL PRIMARY KEY,
        source               TEXT NOT NULL,
        source_asset_id      TEXT NOT NULL,
        source_rule_id       TEXT NOT NULL,
        port                 INTEGER NOT NULL DEFAULT 0,
        protocol             TEXT NOT NULL DEFAULT '',

        state                TEXT NOT NULL,
        severity             TEXT NOT NULL,
        cvss_score           NUMERIC(3,1),
        cvss_vector          TEXT,

        title                TEXT,
        plugin_family        TEXT,
        synopsis             TEXT,
        solution             TEXT,

        is_remote_no_auth    BOOLEAN NOT NULL DEFAULT FALSE,
        exploit_available    BOOLEAN,
        exploited_by_malware BOOLEAN,
        has_patch            BOOLEAN,
        patch_published      TIMESTAMPTZ,

        product_key          TEXT,
        product_vendor       TEXT,
        product_family       TEXT,

        site_label           TEXT NOT NULL,
        site_tag             TEXT,
        asset_type           TEXT,
        hostname             TEXT,

        first_found          TIMESTAMPTZ NOT NULL,
        last_found            TIMESTAMPTZ NOT NULL,
        last_fixed             TIMESTAMPTZ,

        unified_asset_id       BIGINT,
        last_seen_in_export    TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

        CONSTRAINT uq_vuln_findings_natural_key
            UNIQUE (source, source_asset_id, source_rule_id, port, protocol)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_state ON vuln_findings (state);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings (severity);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_product_key ON vuln_findings (product_key);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_product_family ON vuln_findings (product_family);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_first_found ON vuln_findings (first_found);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_last_fixed ON vuln_findings (last_fixed);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_source_asset ON vuln_findings (source_asset_id);",
    """
    CREATE INDEX IF NOT EXISTS idx_vuln_findings_open
        ON vuln_findings (site_label, severity)
        WHERE state IN ('OPEN','REOPENED');
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_finding_cves (
        finding_id BIGINT NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
        cve        TEXT NOT NULL,
        PRIMARY KEY (finding_id, cve)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_finding_cves_cve ON vuln_finding_cves (cve);",
    """
    CREATE TABLE IF NOT EXISTS cisa_kev (
        cve_id                          TEXT PRIMARY KEY,
        vendor_project                  TEXT,
        product                         TEXT,
        vulnerability_name              TEXT,
        date_added                      DATE,
        short_description               TEXT,
        required_action                 TEXT,
        due_date                        DATE,
        known_ransomware_campaign_use   TEXT,
        notes                           TEXT,
        cwes                            TEXT[],
        synced_at                       TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_kev_metrics (
        snapshot_date          DATE NOT NULL,
        site_label             TEXT NOT NULL,
        site_tag               TEXT,
        kev_open_total          INTEGER NOT NULL DEFAULT 0,
        kev_open_crit           INTEGER NOT NULL DEFAULT 0,
        kev_open_high           INTEGER NOT NULL DEFAULT 0,
        kev_open_medium         INTEGER NOT NULL DEFAULT 0,
        kev_open_low            INTEGER NOT NULL DEFAULT 0,
        kev_ransomware_total     INTEGER NOT NULL DEFAULT 0,
        kev_past_due_total       INTEGER NOT NULL DEFAULT 0,
        non_kev_open_total       INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    # MTTR trend, per calendar day a finding actually closed (last_fixed's
    # own date -- not a rolling window like daily_product_metrics.fixed_*),
    # broken down by severity so SLA tracking is visible per risk band.
    """
    CREATE TABLE IF NOT EXISTS daily_mttr_metrics (
        snapshot_date            DATE NOT NULL,
        site_label                TEXT NOT NULL,
        site_tag                  TEXT,
        severity                  TEXT NOT NULL,
        fixed_count                 INTEGER NOT NULL DEFAULT 0,
        avg_remediation_days        NUMERIC(10,2),
        median_remediation_days     NUMERIC(10,2),
        sla_compliant_count          INTEGER NOT NULL DEFAULT 0,
        sla_compliance_rate          NUMERIC(5,2),
        PRIMARY KEY (snapshot_date, site_label, severity)
    );
    """,
    # Power BI fact view: currently-open findings, KEV-enriched. Correlated
    # subqueries (not a LEFT JOIN) deliberately used to avoid row fanout
    # when a finding has more than one CVE.
    """
    CREATE OR REPLACE VIEW fact_vuln_findings_current AS
    SELECT
        vf.*,
        EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0 AS age_days,
        CASE vf.severity
            WHEN 'critical' THEN 2 WHEN 'high' THEN 14
            WHEN 'medium'   THEN 30 ELSE 60
        END AS sla_threshold_days,
        (EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0) >
            CASE vf.severity
                WHEN 'critical' THEN 2 WHEN 'high' THEN 14
                WHEN 'medium'   THEN 30 ELSE 60
            END AS sla_breach,
        EXISTS (
            SELECT 1 FROM vuln_finding_cves fc
            JOIN cisa_kev k ON k.cve_id = fc.cve
            WHERE fc.finding_id = vf.id
        ) AS has_kev,
        (SELECT k.cve_id FROM vuln_finding_cves fc JOIN cisa_kev k ON k.cve_id = fc.cve
           WHERE fc.finding_id = vf.id ORDER BY k.date_added DESC LIMIT 1) AS kev_cve_id,
        (SELECT k.date_added FROM vuln_finding_cves fc JOIN cisa_kev k ON k.cve_id = fc.cve
           WHERE fc.finding_id = vf.id ORDER BY k.date_added DESC LIMIT 1) AS kev_date_added,
        (SELECT k.due_date FROM vuln_finding_cves fc JOIN cisa_kev k ON k.cve_id = fc.cve
           WHERE fc.finding_id = vf.id ORDER BY k.date_added DESC LIMIT 1) AS kev_due_date,
        (SELECT k.known_ransomware_campaign_use FROM vuln_finding_cves fc JOIN cisa_kev k ON k.cve_id = fc.cve
           WHERE fc.finding_id = vf.id ORDER BY k.date_added DESC LIMIT 1) AS kev_ransomware_use
    FROM vuln_findings vf
    WHERE vf.state IN ('OPEN','REOPENED');
    """,
    """
    CREATE OR REPLACE VIEW dim_site AS
    SELECT DISTINCT site_label, site_tag FROM vuln_findings;
    """,
    """
    CREATE OR REPLACE VIEW dim_product AS
    SELECT DISTINCT product_key, product_vendor, product_family
    FROM vuln_findings
    WHERE product_key IS NOT NULL;
    """,
    # "Worst devices" hit list: one row per asset, ranked by a weighted
    # risk score. Built on fact_vuln_findings_current so it inherits the
    # same age/SLA/KEV columns for free instead of recomputing them.
    """
    CREATE OR REPLACE VIEW asset_risk_summary AS
    SELECT
        source_asset_id,
        max(hostname) AS hostname,
        max(site_label) AS site_label,
        max(site_tag) AS site_tag,
        max(asset_type) AS asset_type,
        count(*) FILTER (WHERE severity = 'critical') AS open_critical,
        count(*) FILTER (WHERE severity = 'high') AS open_high,
        count(*) FILTER (WHERE severity = 'medium') AS open_medium,
        count(*) FILTER (WHERE severity = 'low') AS open_low,
        count(*) AS open_total,
        count(*) FILTER (WHERE is_remote_no_auth) AS open_remote_no_auth,
        count(*) FILTER (WHERE has_kev) AS open_kev_count,
        count(*) FILTER (WHERE sla_breach) AS open_sla_breaches,
        max(age_days) AS oldest_open_finding_age_days,
        (count(*) FILTER (WHERE severity = 'critical') * 10)
          + (count(*) FILTER (WHERE severity = 'high') * 5)
          + (count(*) FILTER (WHERE severity = 'medium') * 2)
          + (count(*) FILTER (WHERE severity = 'low') * 1)
          + (count(*) FILTER (WHERE has_kev) * 15)
          + (count(*) FILTER (WHERE is_remote_no_auth) * 5) AS risk_score
    FROM fact_vuln_findings_current
    GROUP BY source_asset_id;
    """,
]


def ensure_schema(cfg: Dict[str, Any]) -> None:
    conn = pg_connect(cfg)
    cur = conn.cursor()
    for stmt in DDL_STATEMENTS:
        cur.execute(stmt)
    conn.commit()
    conn.close()
