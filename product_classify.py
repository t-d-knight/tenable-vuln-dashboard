#!/usr/bin/env python3
"""
Product/vendor classification from CPE-derived product keys, driven by
product_groups.yaml's ordered rule list (first match wins).
"""
import os
import re
from typing import Any, Dict


def load_product_rules(path: str = "product_groups.yaml") -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {
            "rules": [],
            "defaults": {
                "unknown_family_name": "Other / Misc",
                "vendor_from_prefix": True,
            },
        }
    import yaml

    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("rules", [])
    data.setdefault("defaults", {})
    data["defaults"].setdefault("unknown_family_name", "Other / Misc")
    data["defaults"].setdefault("vendor_from_prefix", True)
    return data


PRODUCT_RULES = load_product_rules()


def classify_product(product_key: str) -> Dict[str, str]:
    pk = (product_key or "").lower()
    family = None

    for r in PRODUCT_RULES.get("rules", []):
        label = r.get("family") or r.get("name")
        if not label:
            continue

        # Legacy "match_any" support (exact/startswith/contains fallback)
        legacy = r.get("match_any")
        if isinstance(legacy, list) and legacy:
            for cand in legacy:
                c = (cand or "").lower()
                if not c:
                    continue
                if pk == c or pk.startswith(c) or c in pk:
                    family = label
                    break
            if family:
                break

        match = r.get("match")
        pat = r.get("pattern")
        pats = r.get("patterns", [])

        if match == "contains" and pat and pat.lower() in pk:
            family = label
        elif match == "startswith" and pat and pk.startswith(pat.lower()):
            family = label
        elif match == "regex" and pat and re.search(pat, product_key or "", flags=re.I):
            family = label
        elif match == "contains_any" and any((p or "").lower() in pk for p in pats):
            family = label
        elif match == "startswith_any" and pats and any(
            pk.startswith((p or "").lower()) for p in pats
        ):
            family = label

        if family:
            break

    if not family:
        family = PRODUCT_RULES["defaults"]["unknown_family_name"]

    vendor = product_key.split(":", 1)[0] if ":" in product_key else "unknown_vendor"
    return {"vendor": vendor, "family": family}


def product_key_from_cpe(plugin: Dict[str, Any]) -> str:
    for c in plugin.get("cpe", []) or []:
        if isinstance(c, str) and c.startswith("cpe:/"):
            p = c.split(":")
            if len(p) >= 4:
                return f"{p[2]}:{p[3]}"
    return f"{plugin.get('family', 'Other')} - {plugin.get('name', 'Unknown')}"
