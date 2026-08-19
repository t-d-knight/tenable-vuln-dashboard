#!/usr/bin/env python3
"""
Vendor-agnostic site and asset-type classification from a normalized tag
list. Any adapter that can produce a list of {category/key, value} (or
"category:value" strings) tags for an asset can use this.
"""
from typing import Any, Dict, List


def site_label(
    tags: List[Any], site_cfg: Dict[str, str], tag_cfg: Dict[str, Any], ungrouped: str
) -> str:
    """
    Work out the site label for an asset based on its tags.
    site_cfg maps tag value -> human label. tag_cfg.site_category defaults
    to "Sites".
    """
    cat = str(tag_cfg.get("site_category", "Sites"))

    # Dict-style tags
    for t in tags or []:
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
    for t in tags or []:
        if isinstance(t, str):
            s = t.strip()
            if ":" in s:
                s_cat, s_val = s.split(":", 1)
                if s_cat == cat and s_val in site_cfg:
                    return site_cfg[s_val]

    return ungrouped


def asset_type(tags: List[Any], tag_cfg: Dict[str, Any]) -> str:
    """
    Classify an asset as internet/server/workstation/unknown based on its
    AssetType-category tags. Config-driven via tag_cfg's internet_values /
    server_values / workstation_values.
    """
    at_cat = tag_cfg.get("asset_type_category", "AssetType")
    vals = [
        t.get("value")
        for t in (tags or [])
        if isinstance(t, dict) and t.get("key") == at_cat
    ]
    vset = set(vals)

    if vset & set(tag_cfg.get("internet_values", [])):
        return "internet"
    if vset & set(tag_cfg.get("server_values", [])):
        return "server"
    if vset & set(tag_cfg.get("workstation_values", [])):
        return "workstation"

    return "unknown"
