"""Manifest package-identity rewrite helpers for side-by-side clone installs.

This rewrites the install-time package identity more completely than changing
only ``<manifest package=...>``. Android install conflicts often come from
app-owned provider authorities and custom permissions that still use the
original package prefix.

The helper keeps runtime component class references stable by normalizing
relative component class names to absolute references under the original code
package before flipping the manifest package to the new install identity.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_NS = f"{{{_ANDROID_URI}}}"
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_PLACEHOLDERS = ("${applicationId}", "${packageName}")

_CLASS_ATTRS: dict[str, tuple[str, ...]] = {
    "application": ("name", "backupAgent", "manageSpaceActivity", "appComponentFactory"),
    "activity": ("name", "parentActivityName"),
    "service": ("name",),
    "receiver": ("name",),
    "provider": ("name",),
    "activity-alias": ("targetActivity",),
    "instrumentation": ("name",),
}

_PACKAGE_PREFIX_ATTRS: dict[str, tuple[str, ...]] = {
    "manifest": ("sharedUserId",),
    "application": ("permission", "process", "taskAffinity"),
    "activity": ("permission", "process", "taskAffinity"),
    "activity-alias": ("permission",),
    "service": ("permission", "process"),
    "receiver": ("permission", "process"),
    "provider": ("permission", "readPermission", "writePermission", "process"),
    "permission": ("name", "permissionGroup"),
    "permission-tree": ("name",),
    "permission-group": ("name",),
    "uses-permission": ("name",),
    "uses-permission-sdk-23": ("name",),
    "uses-permission-sdk-m": ("name",),
}


def _android_attr(name: str) -> str:
    return f"{_NS}{name}"


def _replace_app_owned_prefix(value: str, old_package: str, new_package: str) -> tuple[str, bool]:
    if not value:
        return value, False

    updated = value
    changed = False
    for placeholder in _PLACEHOLDERS:
        if placeholder in updated:
            updated = updated.replace(placeholder, new_package)
            changed = True

    if updated == old_package or updated.startswith(old_package + ".") or updated.startswith(old_package + ":"):
        updated = new_package + updated[len(old_package):]
        changed = True

    return updated, changed


def _rewrite_authorities(value: str, old_package: str, new_package: str) -> tuple[str, bool]:
    if not value:
        return value, False

    changed = False
    rewritten: list[str] = []
    for token in value.split(";"):
        part = token.strip()
        updated, part_changed = _replace_app_owned_prefix(part, old_package, new_package)
        rewritten.append(updated)
        changed = changed or part_changed
    return ";".join(rewritten), changed


def _normalize_component_class(value: str, code_package: str) -> tuple[str, bool]:
    if not value:
        return value, False
    if value.startswith("."):
        return code_package + value, True
    if "." not in value:
        return f"{code_package}.{value}", True
    return value, False


def rename_package_identity(
    apktool_dir: str | Path,
    new_package: str,
    *,
    old_package: str | None = None,
) -> dict:
    """Rewrite install-time package identity for side-by-side installation."""
    if not _PACKAGE_RE.fullmatch(str(new_package or "")):
        return {"success": False, "error": f"Invalid Android package name: {new_package}"}

    apktool_dir = Path(apktool_dir)
    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        return {"success": False, "error": f"AndroidManifest.xml not found: {manifest_path}"}

    try:
        ET.register_namespace("android", _ANDROID_URI)
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return {"success": False, "error": f"XML parse error: {exc}"}

    code_package = old_package or root.get("package", "")
    if not code_package:
        return {"success": False, "error": "Manifest package attribute is missing."}

    if code_package == new_package:
        return {
            "success": True,
            "manifest_path": str(manifest_path),
            "old_package": code_package,
            "new_package": new_package,
            "changes_applied": [],
            "counts": {},
            "notes": ["Package name already matches target."],
        }

    counts = {
        "manifest_package": 0,
        "component_class_refs_normalized": 0,
        "provider_authorities": 0,
        "package_tied_identifiers": 0,
    }
    renamed_authorities: list[str] = []
    renamed_permissions: list[str] = []

    root.set("package", new_package)
    counts["manifest_package"] = 1

    for attr_name in _PACKAGE_PREFIX_ATTRS.get("manifest", ()):
        attr_key = _android_attr(attr_name)
        current = root.get(attr_key, "")
        updated, changed = _replace_app_owned_prefix(current, code_package, new_package)
        if changed:
            root.set(attr_key, updated)
            counts["package_tied_identifiers"] += 1

    for tag_name, class_attrs in _CLASS_ATTRS.items():
        for elem in root.iter(tag_name):
            for attr_name in class_attrs:
                attr_key = _android_attr(attr_name)
                current = elem.get(attr_key, "")
                updated, changed = _normalize_component_class(current, code_package)
                if changed:
                    elem.set(attr_key, updated)
                    counts["component_class_refs_normalized"] += 1

            for attr_name in _PACKAGE_PREFIX_ATTRS.get(tag_name, ()):
                attr_key = _android_attr(attr_name)
                current = elem.get(attr_key, "")
                updated, changed = _replace_app_owned_prefix(current, code_package, new_package)
                if changed:
                    elem.set(attr_key, updated)
                    counts["package_tied_identifiers"] += 1
                    if attr_name in {"permission", "readPermission", "writePermission", "name", "permissionGroup"}:
                        renamed_permissions.append(updated)

            if tag_name == "provider":
                auth_key = _android_attr("authorities")
                current = elem.get(auth_key, "")
                updated, changed = _rewrite_authorities(current, code_package, new_package)
                if changed:
                    elem.set(auth_key, updated)
                    counts["provider_authorities"] += 1
                    renamed_authorities.extend([part for part in updated.split(";") if part])

    for tag_name, attr_names in _PACKAGE_PREFIX_ATTRS.items():
        if tag_name == "manifest" or tag_name in _CLASS_ATTRS:
            continue
        for elem in root.iter(tag_name):
            for attr_name in attr_names:
                attr_key = _android_attr(attr_name)
                current = elem.get(attr_key, "")
                updated, changed = _replace_app_owned_prefix(current, code_package, new_package)
                if changed:
                    elem.set(attr_key, updated)
                    counts["package_tied_identifiers"] += 1
                    if attr_name in {"permission", "readPermission", "writePermission", "name", "permissionGroup"}:
                        renamed_permissions.append(updated)

    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

    changes_applied: list[str] = [f"Manifest package updated: {code_package} -> {new_package}"]
    if counts["component_class_refs_normalized"]:
        changes_applied.append(
            f"Normalized {counts['component_class_refs_normalized']} relative component class references to absolute code-package names"
        )
    if counts["provider_authorities"]:
        changes_applied.append(f"Rewrote {counts['provider_authorities']} provider authority attribute(s)")
    if counts["package_tied_identifiers"]:
        changes_applied.append(
            f"Rewrote {counts['package_tied_identifiers']} package-tied manifest identifier(s)"
        )

    return {
        "success": True,
        "manifest_path": str(manifest_path),
        "old_package": code_package,
        "new_package": new_package,
        "changes_applied": changes_applied,
        "counts": counts,
        "renamed_authorities": sorted(set(renamed_authorities))[:20],
        "renamed_permissions": sorted(set(renamed_permissions))[:20],
        "notes": [
            "Component class names keep pointing to the original code package so the cloned APK still boots.",
            "Provider authorities and app-defined permissions are rewritten to avoid install-time package identity collisions.",
        ],
    }