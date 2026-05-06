"""Internal runtime override layer injection for APKs.

This tool adds an in-APK bootstrap helper that re-applies selected overrides at
runtime from inside the app itself. The initial implementation focuses on two
safe, deterministic override types:
  - SharedPreferences values
  - Static field values
    - Static invoke/dispatcher hooks
    - Menu-state-driven reapply rules

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
_DEFAULT_MENU_PREFS_NAME = "apkagi_runtime_menu"


def _escape_smali_string(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _helper_file_path(apktool_dir: Path) -> Path:
    smali_root = apktool_dir / "smali"
    return smali_root / "apkagi" / "runtime" / "RuntimeOverrides.smali"


def _toggle_state_key(action_id: str) -> str:
    return f"toggle_state:{action_id}"


def _slider_state_key(action_id: str) -> str:
    return f"slider_state:{action_id}"


def build_runtime_override_rules_from_menu_spec(
    spec: dict[str, Any],
    *,
    state_prefs_name: str = _DEFAULT_MENU_PREFS_NAME,
) -> list[dict[str, Any]]:
    """Build runtime override rules from a persisted runtime-menu spec."""
    if not isinstance(spec, dict):
        return []

    buttons = list(spec.get("buttons") or [])
    rules: list[dict[str, Any]] = []
    for action in buttons:
        if not isinstance(action, dict):
            continue
        if not action.get("persist_on_resume") or action.get("kind") == "internal_reset":
            continue

        kind = str(action.get("kind") or "").strip().lower()
        ui_kind = str(action.get("ui_kind") or "button").strip().lower()
        action_id = str(action.get("id") or "").strip()
        if not action_id:
            continue

        if kind == "shared_pref":
            rule = {
                "kind": ("shared_pref" if ui_kind == "button" else "shared_pref_state"),
                "prefs_name": str(action.get("prefs_name") or action.get("name") or "app_prefs"),
                "key": str(action.get("key") or ""),
                "type": str(action.get("type") or "boolean").lower(),
            }
            if ui_kind == "button":
                rule["value"] = action.get("value")
            else:
                rule.update({
                    "state_prefs_name": state_prefs_name,
                    "state_key": (_toggle_state_key(action_id) if ui_kind == "toggle" else _slider_state_key(action_id)),
                    "default_value": action.get("default_state" if ui_kind == "toggle" else "initial_value", False if ui_kind == "toggle" else 0),
                })
            rules.append(rule)
            continue

        if kind == "static_field":
            rule = {
                "kind": ("static_field" if ui_kind == "button" else "static_field_state"),
                "class_descriptor": str(action.get("class_descriptor") or action.get("class") or ""),
                "field": str(action.get("field") or ""),
                "type": str(action.get("type") or ""),
            }
            if ui_kind == "button":
                rule["value"] = action.get("value")
            else:
                rule.update({
                    "state_prefs_name": state_prefs_name,
                    "state_key": (_toggle_state_key(action_id) if ui_kind == "toggle" else _slider_state_key(action_id)),
                    "default_value": action.get("default_state" if ui_kind == "toggle" else "initial_value", False if ui_kind == "toggle" else 0),
                })
            rules.append(rule)
            continue

        if kind in {"invoke_static", "dispatcher"}:
            rule = {
                "kind": kind,
                "method_descriptor": str(action.get("method_descriptor") or ""),
            }
            if ui_kind == "button":
                rule.update({
                    "enabled_prefs_name": state_prefs_name,
                    "enabled_key": action_id,
                })
            else:
                rule.update({
                    "state_prefs_name": state_prefs_name,
                    "state_key": (_toggle_state_key(action_id) if ui_kind == "toggle" else _slider_state_key(action_id)),
                    "state_type": ("boolean" if ui_kind == "toggle" else "int"),
                    "default_value": action.get("default_state" if ui_kind == "toggle" else "initial_value", False if ui_kind == "toggle" else 0),
                })
            rules.append(rule)

    return rules


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


def _pref_gate_lines(rule: dict[str, Any], *, jump_label: str) -> list[str]:
    prefs_name = str(rule.get("enabled_prefs_name") or "").strip()
    enabled_key = str(rule.get("enabled_key") or "").strip()
    if not prefs_name or not enabled_key:
        return []
    return [
        f'    const-string v0, "{_escape_smali_string(prefs_name)}"',
        "    const/4 v1, 0x0",
        "    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        f'    const-string v1, "{_escape_smali_string(enabled_key)}"',
        "    const/4 v2, 0x0",
        "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
        "    move-result v0",
        f"    if-eqz v0, {jump_label}",
    ]


def _load_state_pref_lines(rule: dict[str, Any], *, output_register: str = "v4", state_type: str) -> list[str]:
    prefs_name = str(rule.get("state_prefs_name") or _DEFAULT_MENU_PREFS_NAME)
    state_key = str(rule.get("state_key") or "").strip()
    if not state_key:
        return []

    lines = [
        f'    const-string v0, "{_escape_smali_string(prefs_name)}"',
        "    const/4 v1, 0x0",
        "    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        f'    const-string v1, "{_escape_smali_string(state_key)}"',
    ]
    if state_type == "boolean":
        lines.extend([
            f"    const/4 v2, {'0x1' if bool(rule.get('default_value', False)) else '0x0'}",
            "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
            f"    move-result {output_register}",
        ])
        return lines

    default_value = int(rule.get("default_value", 0) or 0)
    if -8 <= default_value <= 7:
        lines.append(f"    const/4 v2, {hex(default_value)}")
    elif -32768 <= default_value <= 32767:
        lines.append(f"    const/16 v2, {hex(default_value)}")
    else:
        lines.append(f"    const v2, {hex(default_value)}")
    lines.extend([
        "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I",
        f"    move-result {output_register}",
    ])
    return lines


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


def _shared_pref_state_rule_lines(rule: dict[str, Any]) -> list[str]:
    value_type = str(rule.get("type") or "boolean").lower()
    state_type = "boolean" if value_type == "boolean" else "int"
    lines = _load_state_pref_lines(rule, output_register="v4", state_type=state_type)
    if not lines:
        return []
    rule_copy = dict(rule)
    rule_copy.pop("value", None)
    lines.extend(_shared_pref_rule_lines(rule_copy)[:-1] if False else [])
    action_lines = _shared_pref_rule_lines(rule_copy | {"value": rule.get("value")})
    # Reuse the existing writer path by feeding the loaded register as the state source.
    return lines + _shared_pref_rule_lines({**rule_copy, "value": rule.get("value")})[:0] + _shared_pref_rule_lines_stateful(rule_copy, value_register="v4")


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


def _shared_pref_rule_lines_stateful(rule: dict[str, Any], *, value_register: str) -> list[str]:
    prefs_name = str(rule.get("prefs_name") or rule.get("name") or "app_prefs")
    key = str(rule.get("key") or "")
    value_type = str(rule.get("type") or "boolean").lower()
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
        lines.extend([
            f"    invoke-interface {{v0, v1, {value_register}}}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    elif value_type == "int":
        lines.extend([
            f"    invoke-interface {{v0, v1, {value_register}}}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    elif value_type == "long":
        lines.extend([
            f"    int-to-long v4, {value_register}",
            "    invoke-interface {v0, v1, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    else:
        return []
    lines.append("    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V")
    return lines


def _static_field_state_rule_lines(rule: dict[str, Any]) -> list[str]:
    field_type = str(rule.get("type") or "")
    state_type = "boolean" if field_type == "Z" else "int"
    lines = _load_state_pref_lines(rule, output_register="v4", state_type=state_type)
    if not lines:
        return []
    return lines + _static_field_rule_lines_stateful(rule, value_register="v4")


def _static_field_rule_lines_stateful(rule: dict[str, Any], *, value_register: str) -> list[str]:
    class_descriptor = str(rule.get("class_descriptor") or rule.get("class") or "").strip()
    field = str(rule.get("field") or "").strip()
    ftype = str(rule.get("type") or "").strip()
    if not class_descriptor or not field or not ftype:
        return []
    if ftype == "Z":
        return [f"    sput-boolean {value_register}, {class_descriptor}->{field}:{ftype}"]
    if ftype == "I":
        return [f"    sput {value_register}, {class_descriptor}->{field}:{ftype}"]
    if ftype == "J":
        return [
            f"    int-to-long v4, {value_register}",
            f"    sput-wide v4, {class_descriptor}->{field}:{ftype}",
        ]
    return []


def _invoke_static_rule_lines(rule: dict[str, Any]) -> list[str]:
    descriptor = str(rule.get("method_descriptor") or "").strip()
    if not descriptor:
        return []
    skip_label = ":apkagi_invoke_static_skip"
    lines = _pref_gate_lines(rule, jump_label=skip_label)
    if descriptor.endswith("()V"):
        lines.append(f"    invoke-static {{}}, {descriptor}")
    else:
        lines.append(f"    invoke-static {{p0}}, {descriptor}")
    if lines:
        lines.append(f"{skip_label}")
    return lines


def _dispatcher_rule_lines(rule: dict[str, Any]) -> list[str]:
    descriptor = str(rule.get("method_descriptor") or "").strip()
    if not descriptor:
        return []

    lines: list[str] = []
    if descriptor.endswith("()V") or descriptor.endswith("(Landroid/content/Context;)V"):
        skip_label = ":apkagi_dispatcher_skip"
        lines.extend(_pref_gate_lines(rule, jump_label=skip_label))
        if descriptor.endswith("()V"):
            lines.append(f"    invoke-static {{}}, {descriptor}")
        else:
            lines.append(f"    invoke-static {{p0}}, {descriptor}")
        if lines:
            lines.append(f"{skip_label}")
        return lines

    state_type = str(rule.get("state_type") or "boolean").lower()
    value_register = "v4"
    lines.extend(_load_state_pref_lines(rule, output_register=value_register, state_type=state_type))
    if descriptor.endswith("(Z)V"):
        lines.append(f"    invoke-static {{{value_register}}}, {descriptor}")
    elif descriptor.endswith("(Landroid/content/Context;Z)V"):
        lines.append(f"    invoke-static {{p0, {value_register}}}, {descriptor}")
    elif descriptor.endswith("(I)V"):
        lines.append(f"    invoke-static {{{value_register}}}, {descriptor}")
    elif descriptor.endswith("(Landroid/content/Context;I)V"):
        lines.append(f"    invoke-static {{p0, {value_register}}}, {descriptor}")
    return lines


def _generate_helper_smali(rules: list[dict[str, Any]]) -> str:
    pref_rules = [rule for rule in rules if str(rule.get("kind", "")).lower() in {"shared_pref", "shared_pref_state"}]
    static_rules = [rule for rule in rules if str(rule.get("kind", "")).lower() in {"static_field", "static_field_state"}]
    runtime_rules = [rule for rule in rules if str(rule.get("kind", "")).lower() in {"invoke_static", "dispatcher"}]

    pref_lines: list[str] = []
    for rule in pref_rules:
        if str(rule.get("kind", "")).lower() == "shared_pref_state":
            pref_lines.extend(_shared_pref_state_rule_lines(rule))
        else:
            pref_lines.extend(_shared_pref_rule_lines(rule))

    static_lines: list[str] = []
    for rule in static_rules:
        if str(rule.get("kind", "")).lower() == "static_field_state":
            static_lines.extend(_static_field_state_rule_lines(rule))
        else:
            static_lines.extend(_static_field_rule_lines(rule))

    runtime_lines: list[str] = []
    for rule in runtime_rules:
        if str(rule.get("kind", "")).lower() == "invoke_static":
            runtime_lines.extend(_invoke_static_rule_lines(rule))
        else:
            runtime_lines.extend(_dispatcher_rule_lines(rule))

    if not pref_lines:
        pref_lines = ["    return-void"]
    else:
        pref_lines.append("    return-void")

    if not static_lines:
        static_lines = ["    return-void"]
    else:
        static_lines.append("    return-void")

    if not runtime_lines:
        runtime_lines = ["    return-void"]
    else:
        runtime_lines.append("    return-void")

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
        "    invoke-static {p0}, Lapkagi/runtime/RuntimeOverrides;->applyStaticFields(Landroid/content/Context;)V",
        "    invoke-static {p0}, Lapkagi/runtime/RuntimeOverrides;->applySharedPrefs(Landroid/content/Context;)V",
        "    invoke-static {p0}, Lapkagi/runtime/RuntimeOverrides;->applyRuntimeActions(Landroid/content/Context;)V",
        "    return-void",
        ".end method",
        "",
        ".method private static applyStaticFields(Landroid/content/Context;)V",
        "    .locals 8",
        *static_lines,
        ".end method",
        "",
        ".method private static applySharedPrefs(Landroid/content/Context;)V",
        "    .locals 8",
        *pref_lines,
        ".end method",
        "",
        ".method private static applyRuntimeActions(Landroid/content/Context;)V",
        "    .locals 8",
        *runtime_lines,
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