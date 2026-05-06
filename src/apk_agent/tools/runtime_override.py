"""Internal runtime override layer injection for APKs.

This tool adds an in-APK bootstrap helper that re-applies selected overrides at
runtime from inside the app itself. The initial implementation focuses on two
safe, deterministic override types:
  - SharedPreferences values
  - Static field values

The helper is wired into app startup and can optionally be re-applied from the
main entry point's ``onResume`` to counter late revalidation flows.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from apk_agent.tools.code_injector import find_launcher_activity_entry, find_startup_entry, inject_code_in_method
from apk_agent.tools.deep_analysis import validate_smali_syntax


_HELPER_DESCRIPTOR = "Lapkagi/runtime/RuntimeOverrides;"
_BOOTSTRAP_CALL = "Lapkagi/runtime/RuntimeOverrides;->init(Landroid/content/Context;)V"
_BOOTSTRAP_MARKER = "# APK-AGI: RUNTIME OVERRIDE BOOTSTRAP"


def _escape_smali_string(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _helper_file_path(apktool_dir: Path) -> Path:
    smali_root = apktool_dir / "smali"
    return smali_root / "apkagi" / "runtime" / "RuntimeOverrides.smali"


def _backup_file(file_path: Path, apktool_dir: Path, backup_dir: Path | None, backed_up: dict[str, str]) -> str:
    if backup_dir is None:
        return ""
    key = str(file_path.resolve())
    if key in backed_up:
        return backed_up[key]
    try:
        rel = file_path.resolve().relative_to(apktool_dir.resolve())
    except ValueError:
        rel = Path(file_path.name)
    backup_path = backup_dir / rel
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if file_path.exists():
        shutil.copy2(file_path, backup_path)
    backed_up[key] = str(backup_path)
    return str(backup_path)


def _method_exists(smali_file: Path, method_name: str) -> bool:
    if not smali_file.is_file():
        return False
    text = smali_file.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(".method") and method_name in stripped:
            return True
    return False


def _contains_bootstrap(smali_file: Path) -> bool:
    if not smali_file.is_file():
        return False
    text = smali_file.read_text(encoding="utf-8", errors="replace")
    return _BOOTSTRAP_CALL in text


def _method_has_bootstrap(smali_file: Path, method_name: str) -> bool:
    if not smali_file.is_file():
        return False
    lines = smali_file.read_text(encoding="utf-8", errors="replace").splitlines()
    in_method = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(".method"):
            in_method = method_name in stripped
            continue
        if in_method and stripped == ".end method":
            in_method = False
            continue
        if in_method and _BOOTSTRAP_CALL in stripped:
            return True
    return False


def _inject_bootstrap_call(
    target_file: Path,
    method_name: str,
    *,
    apktool_dir: Path,
    backup_root: Path | None,
    backed_up: dict[str, str],
    touched_files: set[str],
    bootstrap_targets: list[dict[str, Any]],
    errors: list[str],
) -> None:
    if not _method_exists(target_file, method_name):
        bootstrap_targets.append({
            "target": str(target_file),
            "method": method_name,
            "result": {"success": False, "status": "method_missing"},
        })
        return

    _backup_file(target_file, apktool_dir, backup_root, backed_up)
    if _method_has_bootstrap(target_file, method_name):
        bootstrap_targets.append({
            "target": str(target_file),
            "method": method_name,
            "result": {"success": True, "status": "already_present"},
        })
        return

    code = f"{_BOOTSTRAP_MARKER}\ninvoke-static {{p0}}, {_BOOTSTRAP_CALL}"
    result = inject_code_in_method(str(target_file), method_name, code, "after_super")
    bootstrap_targets.append({
        "target": str(target_file),
        "method": method_name,
        "result": result,
    })
    if result.get("success"):
        touched_files.add(str(target_file))
    else:
        errors.append(f"{method_name} bootstrap injection failed: {result.get('error', 'unknown error')}")


def _shared_pref_rule_lines(rule: dict[str, Any]) -> list[str]:
    prefs_name = str(rule.get("prefs_name") or rule.get("name") or "app_prefs")
    key = str(rule.get("key") or "")
    value_type = str(rule.get("type") or "boolean").lower()
    value = rule.get("value")
    if not key:
        return []

    lines = [
        f'    const-string v0, "{_escape_smali_string(prefs_name)}"',
        "    const/4 v1, 0x0",
        "    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_escape_smali_string(key)}"',
    ]

    if value_type == "boolean":
        if value is None:
            return []
        val = "0x1" if bool(value) else "0x0"
        lines.extend([
            f"    const/4 v2, {val}",
            "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    elif value_type == "int":
        if value is None:
            return []
        iv = int(value)
        if -8 <= iv <= 7:
            lines.append(f"    const/4 v2, {hex(iv)}")
        elif -32768 <= iv <= 32767:
            lines.append(f"    const/16 v2, {hex(iv)}")
        else:
            lines.append(f"    const v2, {hex(iv)}")
        lines.extend([
            "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    elif value_type == "long":
        if value is None:
            return []
        lines.extend([
            f"    const-wide v2, {hex(int(value))}",
            "    invoke-interface {v0, v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    elif value_type == "string":
        if value is None:
            return []
        lines.extend([
            f'    const-string v2, "{_escape_smali_string(value)}"',
            "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    else:
        return []

    lines.append("    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V")
    return lines


def _static_field_rule_lines(rule: dict[str, Any]) -> list[str]:
    class_descriptor = str(rule.get("class_descriptor") or rule.get("class") or "").strip()
    field = str(rule.get("field") or "").strip()
    ftype = str(rule.get("type") or "").strip()
    value = rule.get("value")
    if not class_descriptor or not field or not ftype:
        return []

    lines: list[str] = []
    if ftype == "Z":
        if value is None:
            return []
        val = "0x1" if bool(value) else "0x0"
        lines.append(f"    const/4 v0, {val}")
        lines.append(f"    sput-boolean v0, {class_descriptor}->{field}:{ftype}")
    elif ftype == "I":
        if value is None:
            return []
        iv = int(value)
        if -8 <= iv <= 7:
            lines.append(f"    const/4 v0, {hex(iv)}")
        elif -32768 <= iv <= 32767:
            lines.append(f"    const/16 v0, {hex(iv)}")
        else:
            lines.append(f"    const v0, {hex(iv)}")
        lines.append(f"    sput v0, {class_descriptor}->{field}:{ftype}")
    elif ftype == "J":
        if value is None:
            return []
        lines.append(f"    const-wide v0, {hex(int(value))}")
        lines.append(f"    sput-wide v0, {class_descriptor}->{field}:{ftype}")
    elif ftype == "Ljava/lang/String;":
        if value is None:
            return []
        lines.append(f'    const-string v0, "{_escape_smali_string(value)}"')
        lines.append(f"    sput-object v0, {class_descriptor}->{field}:{ftype}")
    elif (ftype.startswith("L") or ftype.startswith("[")) and value is None:
        lines.append("    const/4 v0, 0x0")
        lines.append(f"    sput-object v0, {class_descriptor}->{field}:{ftype}")
    return lines


def _generate_helper_smali(rules: list[dict[str, Any]]) -> str:
    pref_rules = [rule for rule in rules if str(rule.get("kind", "")).lower() == "shared_pref"]
    static_rules = [rule for rule in rules if str(rule.get("kind", "")).lower() == "static_field"]

    pref_lines: list[str] = []
    for rule in pref_rules:
        pref_lines.extend(_shared_pref_rule_lines(rule))

    static_lines: list[str] = []
    for rule in static_rules:
        static_lines.extend(_static_field_rule_lines(rule))

    if not pref_lines:
        pref_lines = ["    return-void"]
    else:
        pref_lines.append("    return-void")

    if not static_lines:
        static_lines = ["    return-void"]
    else:
        static_lines.append("    return-void")

    return "\n".join([
        ".class public final Lapkagi/runtime/RuntimeOverrides;",
        ".super Ljava/lang/Object;",
        '.source "RuntimeOverrides.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public static init(Landroid/content/Context;)V",
        "    .locals 1",
        "    invoke-static {}, Lapkagi/runtime/RuntimeOverrides;->applyStaticFields()V",
        "    invoke-static {p0}, Lapkagi/runtime/RuntimeOverrides;->applySharedPrefs(Landroid/content/Context;)V",
        "    return-void",
        ".end method",
        "",
        ".method private static applyStaticFields()V",
        "    .locals 6",
        *static_lines,
        ".end method",
        "",
        ".method private static applySharedPrefs(Landroid/content/Context;)V",
        "    .locals 8",
        *pref_lines,
        ".end method",
        "",
        ".method public static enabled()Z",
        "    .locals 1",
        "    const/4 v0, 0x1",
        "    return v0",
        ".end method",
        "",
    ]) + "\n"


def inject_runtime_override_layer(
    apktool_dir: str | Path,
    rules: list[dict[str, Any]],
    *,
    backup_dir: str | Path | None = None,
    reapply_on_resume: bool = False,
) -> dict[str, Any]:
    """Inject an internal runtime override bootstrap and helper layer."""
    apktool_dir = Path(apktool_dir)
    backup_root = Path(backup_dir) if backup_dir else None
    if not rules:
        return {"success": False, "error": "At least one runtime rule is required"}

    helper_file = _helper_file_path(apktool_dir)
    helper_file.parent.mkdir(parents=True, exist_ok=True)
    helper_smali = _generate_helper_smali(rules)
    backed_up: dict[str, str] = {}
    touched_files: set[str] = set()
    validations: list[dict[str, Any]] = []
    errors: list[str] = []
    bootstrap_targets: list[dict[str, Any]] = []

    try:
        _backup_file(helper_file, apktool_dir, backup_root, backed_up)
        helper_file.write_text(helper_smali, encoding="utf-8")
        touched_files.add(str(helper_file))

        manifest_path = apktool_dir / "AndroidManifest.xml"
        entry = find_startup_entry(str(manifest_path), str(apktool_dir))
        if not entry.get("success"):
            errors.append(str(entry.get("error", "Could not find startup entry")))
        else:
            entry_file = Path(str(entry["smali_file"]))
            if not entry.get("has_onCreate"):
                errors.append(f"Startup entry has no onCreate: {entry.get('class_name', '')}")
            else:
                _inject_bootstrap_call(
                    entry_file,
                    "onCreate",
                    apktool_dir=apktool_dir,
                    backup_root=backup_root,
                    backed_up=backed_up,
                    touched_files=touched_files,
                    bootstrap_targets=bootstrap_targets,
                    errors=errors,
                )

                if reapply_on_resume:
                    lifecycle_targets: list[tuple[Path, str]] = []
                    if entry.get("entry_type") == "LauncherActivity":
                        lifecycle_targets.extend((entry_file, method_name) for method_name in ("onStart", "onResume"))
                    elif _method_exists(entry_file, "onResume"):
                        lifecycle_targets.append((entry_file, "onResume"))

                    launcher_entry = find_launcher_activity_entry(str(manifest_path), str(apktool_dir))
                    launcher_file: Path | None = None
                    if launcher_entry.get("success"):
                        launcher_file = Path(str(launcher_entry["smali_file"]))
                        if launcher_file != entry_file:
                            lifecycle_targets.extend((launcher_file, method_name) for method_name in ("onStart", "onResume"))

                    seen_targets: set[tuple[str, str]] = set()
                    for target_file, method_name in lifecycle_targets:
                        key = (str(target_file.resolve()), method_name)
                        if key in seen_targets:
                            continue
                        seen_targets.add(key)
                        _inject_bootstrap_call(
                            target_file,
                            method_name,
                            apktool_dir=apktool_dir,
                            backup_root=backup_root,
                            backed_up=backed_up,
                            touched_files=touched_files,
                            bootstrap_targets=bootstrap_targets,
                            errors=errors,
                        )

        for file_name in sorted(touched_files):
            validation = validate_smali_syntax(Path(file_name))
            validations.append({"file": file_name, **validation})
            if not validation.get("valid", False):
                backup_path = backed_up.get(str(Path(file_name).resolve()))
                if backup_path and Path(backup_path).exists():
                    shutil.copy2(backup_path, file_name)
                errors.append(f"Syntax validation failed for {file_name}; restored from backup")
    except Exception as exc:
        errors.append(str(exc))

    return {
        "success": len(errors) == 0 and bool(touched_files),
        "helper_class": _HELPER_DESCRIPTOR,
        "helper_file": str(helper_file),
        "rules_applied": len(rules),
        "runtime_modes": sorted({str(rule.get("kind", "")).lower() for rule in rules if rule.get("kind")}),
        "bootstrap_targets": bootstrap_targets,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "errors": errors[:20],
    }