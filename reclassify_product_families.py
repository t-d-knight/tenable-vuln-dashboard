#!/usr/bin/env python3
"""
Re-classify product families in daily_product_metrics using the latest
product_groups.yaml rules and classify_product() logic.

Usage:
  python3 reclassify_product_families.py --config config.yaml
  python3 reclassify_product_families.py --config config.yaml --only-misc
  python3 reclassify_product_families.py --config config.yaml --dry-run
"""

import argparse
from typing import Dict, Any, List, Tuple

from tenable_product_drivers import (
    load_config,
    pg_connect,
    PRODUCT_RULES,
    classify_product,
)


def get_misc_name() -> str:
    """Return the 'Other / Misc' family name from PRODUCT_RULES defaults."""
    return PRODUCT_RULES.get("defaults", {}).get(
        "unknown_family_name", "Other / Misc"
    )


def fetch_distinct_products(conn, only_misc: bool) -> List[str]:
    """
    Get the list of distinct products from daily_product_metrics.

    If only_misc=True, restrict to rows currently in the misc family or NULL.
    """
    cur = conn.cursor()
    misc_name = get_misc_name()

    if only_misc:
        print(f"[info] Limiting to products where product_family IS NULL or '{misc_name}'")
        cur.execute(
            """
            SELECT DISTINCT product
            FROM daily_product_metrics
            WHERE product_family IS NULL
               OR product_family = %s
            ORDER BY product;
            """,
            (misc_name,),
        )
    else:
        print("[info] Fetching ALL distinct products from daily_product_metrics")
        cur.execute(
            """
            SELECT DISTINCT product
            FROM daily_product_metrics
            ORDER BY product;
            """
        )

    rows = cur.fetchall()
    products = [r[0] for r in rows if r[0] is not None]
    print(f"[info] Found {len(products)} distinct products to reclassify.")
    return products


def build_classification_map(products: List[str]) -> Dict[str, Dict[str, str]]:
    """
    For each product string, run classify_product() and build a mapping:
      product -> {"vendor": ..., "family": ...}
    """
    mapping: Dict[str, Dict[str, str]] = {}

    for p in products:
        cls = classify_product(p)
        vendor = cls.get("vendor", "unknown_vendor")
        family = cls.get("family", get_misc_name())
        mapping[p] = {"vendor": vendor, "family": family}

    return mapping


def apply_mapping(conn, mapping: Dict[str, Dict[str, str]], dry_run: bool = False):
    """
    Apply vendor/family mapping to daily_product_metrics.

    One UPDATE per product to keep it simple and safe.
    """
    cur = conn.cursor()
    total = len(mapping)
    misc_name = get_misc_name()

    changed = 0
    unchanged = 0

    for idx, (product, cls) in enumerate(mapping.items(), start=1):
        vendor = cls["vendor"]
        family = cls["family"]

        # Skip products that already look correct (optional optimisation)
        # We'll still update, but track stats.
        if family == misc_name:
            # still falling into misc – nothing we can do with current rules
            unchanged += 1
        else:
            changed += 1

        print(
            f"[{idx}/{total}] product='{product}' -> "
            f"vendor='{vendor}', family='{family}'"
        )

        if dry_run:
            continue

        cur.execute(
            """
            UPDATE daily_product_metrics
            SET vendor = %s,
                product_family = %s
            WHERE product = %s;
            """,
            (vendor, family, product),
        )

        # Commit every 100 products to avoid holding a huge transaction
        if idx % 100 == 0 and not dry_run:
            conn.commit()
            print(f"[info] Committed batch up to {idx} products…")

    if not dry_run:
        conn.commit()
        print("[info] Final commit complete.")

    print(
        f"[summary] products classified: {total} "
        f"(changed={changed}, still_misc_or_unchanged={unchanged}, dry_run={dry_run})"
    )

yamldef main():
    parser = argparse.ArgumentParser(
        description="Retroactively reclassify product/vender families in daily_product_metrics"
    )
    parser.add_argument("--config", default="config.yaml", help="Config YAML path")
    parser.add_argument(
        "--only-misc",
        action="store_true",
        help="Only reclassify rows where product_family is NULL or the misc name",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write changes, just show what would be updated",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    conn = pg_connect(cfg)

    try:
        products = fetch_distinct_products(conn, args.only_misc)
        mapping = build_classification_map(products)

        if args.dry_run:
            print("[info] DRY RUN mode – no database changes will be made.")

        apply_mapping(conn, mapping, dry_run=args.dry_run)
    finally:
        conn.close()
        print("[info] Connection closed.")


if __name__ == "__main__":
    main()
