"""Android Resource-Aware Tools — structured parsing of colors, styles, themes, and drawables.

Unlike raw regex search, these tools understand Android's resource system:
- colors.xml → name→hex mappings
- styles.xml → theme color attributes (colorPrimary, colorAccent, etc.)
- Drawable XMLs → color references
- Bulk replacement across ALL resource files
"""

from __future__ import annotations

import colorsys
import logging
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

logger = logging.getLogger("apk_agent.tools.resources")

# Common third-party resource prefixes to skip
_SKIP_PREFIXES = (
    "com.google.", "com.facebook.", "com.squareup.", "com.android.",
    "androidx.", "android.", "io.flutter.", "com.crashlytics.",
    "com.firebase.", "com.appsflyer.", "io.sentry.",
)


def _hex_to_hue(hex_color: str) -> Optional[float]:
    """Convert #AARRGGBB or #RRGGBB hex color to hue (0-360). Returns None if invalid."""
    c = hex_color.lstrip("#")
    try:
        if len(c) == 8:  # AARRGGBB
            r, g, b = int(c[2:4], 16), int(c[4:6], 16), int(c[6:8], 16)
        elif len(c) == 6:  # RRGGBB
            r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        else:
            return None
        h, _, _ = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
        return h * 360
    except (ValueError, IndexError):
        return None


def _is_color_in_hue_range(hex_color: str, hue_ranges: list[tuple[float, float]]) -> bool:
    """Check if a hex color falls within any of the given hue ranges."""
    hue = _hex_to_hue(hex_color)
    if hue is None:
        return False
    return any(lo <= hue <= hi for lo, hi in hue_ranges)


# Hue ranges for common color families
COLOR_HUE_RANGES: dict[str, list[tuple[float, float]]] = {
    "red": [(0, 15), (345, 360)],
    "orange": [(15, 45)],
    "yellow": [(45, 70)],
    "green": [(70, 170)],
    "cyan": [(170, 200)],
    "blue": [(200, 260)],
    "purple": [(260, 300)],
    "pink": [(300, 345)],
}

# Android color-related style attributes
_COLOR_ATTRS = {
    "colorPrimary", "colorPrimaryDark", "colorPrimaryVariant",
    "colorSecondary", "colorSecondaryVariant", "colorAccent",
    "colorSurface", "colorError", "colorOnPrimary", "colorOnSecondary",
    "colorOnSurface", "colorOnError", "colorOnBackground",
    "android:colorPrimary", "android:colorAccent",
    "android:statusBarColor", "android:navigationBarColor",
    "android:windowBackground", "android:textColor", "android:textColorPrimary",
    "android:colorBackground", "android:colorForeground",
    "colorPrimarySurface", "colorOnPrimarySurface",
}


def find_app_colors(
    apktool_dir: str | Path,
    color_family: Optional[str] = None,
    exclude_third_party: bool = True,
) -> dict:
    """Parse ALL res/values*/colors.xml files and return structured color mappings.

    Args:
        apktool_dir: Path to apktool decompiled directory.
        color_family: Optional filter — "red", "blue", "green", etc. Only returns
                      colors whose hue falls in that range.
        exclude_third_party: If True, skip colors from known third-party prefixes.

    Returns:
        Dict with: success, colors (list of {name, value, file, hue}),
        color_family_filter, total_files_scanned.
    """
    apktool_dir = Path(apktool_dir)
    res_dir = apktool_dir / "res"
    if not res_dir.is_dir():
        return {"success": False, "error": f"res/ directory not found in {apktool_dir}"}

    colors = []
    files_scanned = 0
    hue_ranges = COLOR_HUE_RANGES.get(color_family.lower(), []) if color_family else []

    for values_dir in sorted(res_dir.iterdir()):
        if not values_dir.is_dir() or not values_dir.name.startswith("values"):
            continue

        colors_file = values_dir / "colors.xml"
        if not colors_file.is_file():
            continue

        files_scanned += 1
        try:
            tree = ET.parse(colors_file)
            root = tree.getroot()

            for elem in root.findall("color"):
                name = elem.get("name", "")
                value = (elem.text or "").strip()

                if exclude_third_party and any(name.startswith(p.replace(".", "_")) for p in _SKIP_PREFIXES):
                    continue

                if not value.startswith("#"):
                    continue

                hue = _hex_to_hue(value)
                entry = {
                    "name": name,
                    "value": value,
                    "file": str(colors_file.relative_to(apktool_dir)),
                    "hue": round(hue, 1) if hue is not None else None,
                }

                if hue_ranges:
                    if _is_color_in_hue_range(value, hue_ranges):
                        colors.append(entry)
                else:
                    colors.append(entry)

        except ET.ParseError as e:
            logger.warning("Failed to parse %s: %s", colors_file, e)

    return {
        "success": True,
        "colors": colors,
        "total_colors": len(colors),
        "color_family_filter": color_family,
        "files_scanned": files_scanned,
    }


def find_app_styles(
    apktool_dir: str | Path,
    exclude_third_party: bool = True,
) -> dict:
    """Parse styles.xml/themes.xml and extract theme color attributes.

    Returns structured info about colorPrimary, colorAccent, etc.

    Args:
        apktool_dir: Path to apktool decompiled directory.
        exclude_third_party: If True, skip styles from known third-party names.

    Returns:
        Dict with: success, themes (list of {name, parent, color_attrs}),
        total_styles_scanned.
    """
    apktool_dir = Path(apktool_dir)
    res_dir = apktool_dir / "res"
    if not res_dir.is_dir():
        return {"success": False, "error": f"res/ directory not found in {apktool_dir}"}

    themes = []
    total_scanned = 0

    for values_dir in sorted(res_dir.iterdir()):
        if not values_dir.is_dir() or not values_dir.name.startswith("values"):
            continue

        for fname in ("styles.xml", "themes.xml"):
            style_file = values_dir / fname
            if not style_file.is_file():
                continue

            total_scanned += 1
            try:
                tree = ET.parse(style_file)
                root = tree.getroot()

                for style_elem in root.findall("style"):
                    style_name = style_elem.get("name", "")
                    parent = style_elem.get("parent", "")

                    if exclude_third_party:
                        full = f"{style_name}.{parent}".lower()
                        if any(tp.lower() in full for tp in ["MaterialComponents", "Material3"]):
                            continue

                    color_attrs = {}
                    for item in style_elem.findall("item"):
                        item_name = item.get("name", "")
                        item_value = (item.text or "").strip()
                        # Keep color-related attributes
                        base_name = item_name.split(":")[-1] if ":" in item_name else item_name
                        if base_name in {a.split(":")[-1] for a in _COLOR_ATTRS} or "color" in base_name.lower():
                            color_attrs[item_name] = item_value

                    if color_attrs:
                        themes.append({
                            "name": style_name,
                            "parent": parent,
                            "color_attrs": color_attrs,
                            "file": str(style_file.relative_to(apktool_dir)),
                        })

            except ET.ParseError as e:
                logger.warning("Failed to parse %s: %s", style_file, e)

    return {
        "success": True,
        "themes": themes,
        "total_themes": len(themes),
        "files_scanned": total_scanned,
    }


def replace_colors(
    apktool_dir: str | Path,
    color_map: dict[str, str],
) -> dict:
    """Bulk replace color hex values across ALL resource XML files.

    Replaces exact hex color strings in colors.xml, styles.xml, themes.xml,
    layout XMLs, and drawable XMLs. Case-insensitive matching.

    Args:
        apktool_dir: Path to apktool decompiled directory.
        color_map: Mapping of old→new hex colors, e.g. {"#FFE11C22": "#FF1C22E1"}.
                   Keys and values should include '#' prefix.

    Returns:
        Dict with: success, replacements (per-file counts), total_replacements,
        files_modified.
    """
    apktool_dir = Path(apktool_dir)
    res_dir = apktool_dir / "res"
    if not res_dir.is_dir():
        return {"success": False, "error": f"res/ directory not found in {apktool_dir}"}

    if not color_map:
        return {"success": False, "error": "color_map is empty"}

    # Build case-insensitive regex for all old colors
    patterns = []
    replacement_map = {}
    for old_hex, new_hex in color_map.items():
        patterns.append(re.escape(old_hex))
        replacement_map[old_hex.lower()] = new_hex

    combined_re = re.compile("|".join(patterns), re.IGNORECASE)

    total_replacements = 0
    file_details = []
    files_modified = 0

    # Walk all XML files under res/
    for root_dir, _dirs, files in os.walk(res_dir):
        for fname in files:
            if not fname.endswith(".xml"):
                continue
            fpath = Path(root_dir) / fname
            try:
                content = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            count = 0

            def _replacer(match: re.Match) -> str:
                nonlocal count
                count += 1
                return replacement_map.get(match.group(0).lower(), match.group(0))

            new_content = combined_re.sub(_replacer, content)

            if count > 0:
                if fpath.exists():
                    fpath.chmod(fpath.stat().st_mode | stat.S_IWRITE)
                fpath.write_text(new_content, encoding="utf-8")
                total_replacements += count
                files_modified += 1
                file_details.append({
                    "file": str(fpath.relative_to(apktool_dir)),
                    "replacements": count,
                })

    return {
        "success": True,
        "total_replacements": total_replacements,
        "files_modified": files_modified,
        "details": file_details,
        "color_map": color_map,
    }


def list_drawables(
    apktool_dir: str | Path,
    color_filter: Optional[str] = None,
) -> dict:
    """List drawable XML files, optionally filtering by those that reference specific colors.

    Args:
        apktool_dir: Path to apktool decompiled directory.
        color_filter: Optional hex color (e.g., "#FF0000") — only return drawables
                      that contain this color. Case-insensitive.

    Returns:
        Dict with: success, drawables (list of {file, colors_found}), total.
    """
    apktool_dir = Path(apktool_dir)
    res_dir = apktool_dir / "res"
    if not res_dir.is_dir():
        return {"success": False, "error": f"res/ directory not found in {apktool_dir}"}

    drawables = []
    hex_pattern = re.compile(r"#[0-9a-fA-F]{6,8}")

    for dirpath, _dirs, files in os.walk(res_dir):
        dir_name = Path(dirpath).name
        if not dir_name.startswith("drawable"):
            continue

        for fname in sorted(files):
            if not fname.endswith(".xml"):
                continue
            fpath = Path(dirpath) / fname
            try:
                content = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            colors_found = list(set(hex_pattern.findall(content)))

            if color_filter:
                if not any(c.lower() == color_filter.lower() for c in colors_found):
                    continue

            if colors_found:
                drawables.append({
                    "file": str(fpath.relative_to(apktool_dir)),
                    "colors": colors_found[:20],
                })

    return {
        "success": True,
        "drawables": drawables,
        "total": len(drawables),
        "color_filter": color_filter,
    }
