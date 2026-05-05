"""Runtime mod-menu scaffold generation for APK patch projects.

This module adds a first-class, typed runtime-menu layer on top of the
existing startup/runtime override infrastructure. The first implementation
focuses on an in-app overlay menu that is attached to the foreground Activity
and can trigger runtime actions when the user presses menu buttons.

Supported action kinds:
  - shared_pref
  - static_field
  - invoke_static

The generated menu is intentionally programmatic (no XML resources yet) so the
scaffold can be injected safely into arbitrary apktool trees without requiring
resource-id bookkeeping.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from apk_agent.tools.code_injector import find_startup_entry, inject_code_in_method
from apk_agent.tools.deep_analysis import validate_smali_syntax
from apk_agent.tools.manifest_parser import parse_manifest


_BRIDGE_DESCRIPTOR = "Lapkagi/menu/InAppMenuBridge;"
_ACTIONS_DESCRIPTOR = "Lapkagi/menu/MenuActions;"
_CLICK_DESCRIPTOR = "Lapkagi/menu/MenuActionClickListener;"
_LIFECYCLE_DESCRIPTOR = "Lapkagi/menu/MenuLifecycleCallbacks;"
_BOOTSTRAP_CALL = "Lapkagi/menu/InAppMenuBridge;->install(Landroid/content/Context;)V"
_BOOTSTRAP_MARKER = "# APK-AGI: RUNTIME MENU BOOTSTRAP"
_MENU_PREFS_NAME = "apkagi_runtime_menu"
_RESET_ACTION_ID = "__apkagi_reset_runtime_menu"
_RESET_ACTION_LABEL = "Reset Runtime Actions"
_SUPPORTED_OVERLAY_MODES = {"in_app", "system_overlay", "hybrid"}
_SUPPORTED_ACTION_KINDS = {"shared_pref", "static_field", "invoke_static"}
_TIER_B_WARNINGS = [
    "Tier B system overlays require android.permission.SYSTEM_ALERT_WINDOW and a runtime approval flow; this creates real permission friction.",
    "Tier B overlays typically depend on WindowManager + TYPE_APPLICATION_OVERLAY, which increases detectability compared with the in-app panel.",
    "Tier B is more crash-prone across OEM/API variants because overlay windows are validated more aggressively than in-app views.",
]


def _escape_smali_string(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _slugify(value: str, *, fallback: str) -> str:
    lowered = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return lowered or fallback


def _helper_file_path(apktool_dir: Path, relative_name: str) -> Path:
    return apktool_dir / "smali" / "apkagi" / "menu" / relative_name


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


def _method_exists(smali_file: Path, method_name: str) -> bool:
    if not smali_file.is_file():
        return False
    for line in smali_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith(".method") and method_name in stripped:
            return True
    return False


def _validate_method_descriptor(descriptor: str) -> tuple[bool, str]:
    pattern = re.compile(r"^L[^;]+;->[\w$<>-]+\((?:|Landroid/content/Context;)\)V$")
    if not pattern.match(descriptor):
        return False, (
            "invoke_static method_descriptor must be a full static void descriptor "
            "with ()V or (Landroid/content/Context;)V, e.g. "
            "Lcom/example/Hooks;->enableVip(Landroid/content/Context;)V"
        )
    return True, ""


def _normalize_action(raw_action: dict[str, Any], index: int, default_persist: bool) -> dict[str, Any]:
    if not isinstance(raw_action, dict):
        raise ValueError(f"buttons[{index}] must be a JSON object")

    kind = str(raw_action.get("kind") or raw_action.get("action_kind") or "").strip().lower()
    if kind not in _SUPPORTED_ACTION_KINDS:
        raise ValueError(
            f"buttons[{index}] kind must be one of {sorted(_SUPPORTED_ACTION_KINDS)}"
        )

    label = str(raw_action.get("label") or raw_action.get("title") or "").strip()
    if not label:
        raise ValueError(f"buttons[{index}] label is required")

    action_id = str(raw_action.get("id") or "").strip()
    if not action_id:
        action_id = _slugify(label, fallback=f"action_{index + 1}")

    normalized: dict[str, Any] = {
        "id": action_id,
        "label": label,
        "kind": kind,
        "persist_on_resume": bool(raw_action.get("persist_on_resume", default_persist)),
        "success_message": str(raw_action.get("success_message") or f"Applied: {label}").strip(),
    }

    if kind == "shared_pref":
        key = str(raw_action.get("key") or "").strip()
        value_type = str(raw_action.get("type") or "boolean").strip().lower()
        if not key:
            raise ValueError(f"buttons[{index}] shared_pref actions require key")
        if value_type not in {"boolean", "int", "long", "string"}:
            raise ValueError(f"buttons[{index}] shared_pref type must be boolean|int|long|string")
        if "value" not in raw_action:
            raise ValueError(f"buttons[{index}] shared_pref actions require value")
        normalized.update({
            "prefs_name": str(raw_action.get("prefs_name") or raw_action.get("name") or "app_prefs"),
            "key": key,
            "type": value_type,
            "value": raw_action.get("value"),
        })
    elif kind == "static_field":
        class_descriptor = str(raw_action.get("class_descriptor") or raw_action.get("class") or "").strip()
        field_name = str(raw_action.get("field") or "").strip()
        field_type = str(raw_action.get("type") or "").strip()
        if not class_descriptor or not field_name or not field_type:
            raise ValueError(
                f"buttons[{index}] static_field actions require class_descriptor/class, field, and type"
            )
        normalized.update({
            "class_descriptor": class_descriptor,
            "field": field_name,
            "type": field_type,
            "value": raw_action.get("value"),
        })
    else:
        method_descriptor = str(raw_action.get("method_descriptor") or raw_action.get("callback") or "").strip()
        is_valid, error = _validate_method_descriptor(method_descriptor)
        if not is_valid:
            raise ValueError(f"buttons[{index}] {error}")
        normalized.update({"method_descriptor": method_descriptor})

    return normalized


def _normalize_menu_spec(spec: dict[str, Any], overlay_mode: str) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("spec_json must decode to a JSON object")

    chosen_mode = str(spec.get("overlay_mode") or overlay_mode or "in_app").strip().lower()
    if chosen_mode not in _SUPPORTED_OVERLAY_MODES:
        raise ValueError(f"overlay_mode must be one of {sorted(_SUPPORTED_OVERLAY_MODES)}")

    buttons_raw = spec.get("buttons") or spec.get("actions")
    if not isinstance(buttons_raw, list) or not buttons_raw:
        raise ValueError("spec must contain a non-empty buttons array")
    if len(buttons_raw) > 8:
        raise ValueError("buttons array is capped at 8 entries for the first runtime-menu scaffold")

    default_persist = bool(spec.get("persist_on_resume", True))
    title = str(spec.get("title") or spec.get("menu_title") or "APK AGI MOD MENU").strip() or "APK AGI MOD MENU"
    normalized_buttons = [
        _normalize_action(raw_action, idx, default_persist)
        for idx, raw_action in enumerate(buttons_raw)
    ]

    ids = [button["id"] for button in normalized_buttons]
    if len(set(ids)) != len(ids):
        raise ValueError("button ids must be unique within the runtime menu spec")

    has_persistent = any(button.get("persist_on_resume") for button in normalized_buttons)
    if has_persistent:
        normalized_buttons.append({
            "id": _RESET_ACTION_ID,
            "label": _RESET_ACTION_LABEL,
            "kind": "internal_reset",
            "persist_on_resume": False,
            "success_message": "Runtime menu state reset",
        })

    return {
        "overlay_mode": chosen_mode,
        "title": title,
        "buttons": normalized_buttons,
        "user_buttons": len(buttons_raw),
        "persistent_buttons": sum(1 for button in normalized_buttons if button.get("persist_on_resume")),
    }


def _effective_overlay_mode(requested_mode: str) -> str:
    """Return the actual scaffold mode implemented by the current generator."""
    if requested_mode == "in_app":
        return "in_app"
    return "in_app"


def _runtime_menu_requirements(requested_mode: str, require_foreground_service: bool = False) -> dict[str, Any]:
    """Describe the real platform/runtime requirements implied by the requested mode."""
    permissions: list[str] = []
    android_apis: list[str] = []
    warnings: list[str] = []

    if requested_mode in {"system_overlay", "hybrid"}:
        permissions.append("android.permission.SYSTEM_ALERT_WINDOW")
        android_apis.extend([
            "android.view.WindowManager",
            "android.view.WindowManager$LayoutParams.TYPE_APPLICATION_OVERLAY",
            "android.provider.Settings.canDrawOverlays",
            "android.settings.action.MANAGE_OVERLAY_PERMISSION",
        ])
        warnings.extend(_TIER_B_WARNINGS)

    if require_foreground_service:
        permissions.append("android.permission.FOREGROUND_SERVICE")
        android_apis.extend([
            "android.app.Service",
            "android.app.Notification",
            "android.app.NotificationChannel",
        ])
        warnings.append(
            "Foreground-service-backed overlays need a stable notification path; missing it can trigger crashes or OS kills on newer Android versions."
        )

    return {
        "permissions": permissions,
        "android_apis": android_apis,
        "warnings": warnings,
    }


def _shared_pref_action_lines(action: dict[str, Any]) -> list[str]:
    prefs_name = _escape_smali_string(action.get("prefs_name") or "app_prefs")
    key = _escape_smali_string(action["key"])
    value_type = action["type"]
    value = action.get("value")
    lines = [
        f'    const-string v2, "{prefs_name}"',
        "    const/4 v3, 0x0",
        "    invoke-virtual {p0, v2, v3}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "    move-result-object v2",
        "    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v2",
        f'    const-string v3, "{key}"',
    ]

    if value_type == "boolean":
        lines.extend([
            f"    const/4 v4, {'0x1' if bool(value) else '0x0'}",
            "    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    elif value_type == "int":
        int_value = int(value)
        if -8 <= int_value <= 7:
            lines.append(f"    const/4 v4, {hex(int_value)}")
        elif -32768 <= int_value <= 32767:
            lines.append(f"    const/16 v4, {hex(int_value)}")
        else:
            lines.append(f"    const v4, {hex(int_value)}")
        lines.extend([
            "    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    elif value_type == "long":
        lines.extend([
            f"    const-wide v4, {hex(int(value))}",
            "    invoke-interface {v2, v3, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    else:
        lines.extend([
            f'    const-string v4, "{_escape_smali_string(value)}"',
            "    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])

    lines.append("    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V")
    return lines


def _static_field_action_lines(action: dict[str, Any]) -> list[str]:
    class_descriptor = action["class_descriptor"]
    field_name = action["field"]
    field_type = action["type"]
    value = action.get("value")
    lines: list[str] = []

    if field_type == "Z":
        lines.append(f"    const/4 v2, {'0x1' if bool(value) else '0x0'}")
        lines.append(f"    sput-boolean v2, {class_descriptor}->{field_name}:{field_type}")
    elif field_type == "I":
        int_value = int(value)
        if -8 <= int_value <= 7:
            lines.append(f"    const/4 v2, {hex(int_value)}")
        elif -32768 <= int_value <= 32767:
            lines.append(f"    const/16 v2, {hex(int_value)}")
        else:
            lines.append(f"    const v2, {hex(int_value)}")
        lines.append(f"    sput v2, {class_descriptor}->{field_name}:{field_type}")
    elif field_type == "J":
        lines.append(f"    const-wide v2, {hex(int(value))}")
        lines.append(f"    sput-wide v2, {class_descriptor}->{field_name}:{field_type}")
    elif field_type == "Ljava/lang/String;":
        lines.append(f'    const-string v2, "{_escape_smali_string(value)}"')
        lines.append(f"    sput-object v2, {class_descriptor}->{field_name}:{field_type}")
    elif (field_type.startswith("L") or field_type.startswith("[")) and value is None:
        lines.append("    const/4 v2, 0x0")
        lines.append(f"    sput-object v2, {class_descriptor}->{field_name}:{field_type}")
    else:
        raise ValueError(
            "static_field actions currently support Z, I, J, Ljava/lang/String;, or object-null writes"
        )

    return lines


def _invoke_static_action_lines(action: dict[str, Any]) -> list[str]:
    descriptor = action["method_descriptor"]
    if descriptor.endswith("()V"):
        return [f"    invoke-static {{}}, {descriptor}"]
    return [f"    invoke-static {{p0}}, {descriptor}"]


def _action_lines(action: dict[str, Any]) -> list[str]:
    kind = action["kind"]
    if kind == "shared_pref":
        return _shared_pref_action_lines(action)
    if kind == "static_field":
        return _static_field_action_lines(action)
    if kind == "invoke_static":
        return _invoke_static_action_lines(action)
    if kind == "internal_reset":
        return ["    invoke-static {p0}, Lapkagi/menu/MenuActions;->clearAll(Landroid/content/Context;)V"]
    raise ValueError(f"Unsupported runtime-menu action kind: {kind}")


def _generate_actions_smali(spec: dict[str, Any]) -> str:
    apply_lines: list[str] = []
    reapply_lines: list[str] = []

    for index, action in enumerate(spec["buttons"]):
        next_label = f":apkagi_menu_next_{index}"
        action_id = _escape_smali_string(action["id"])
        apply_lines.extend([
            f'    const-string v0, "{action_id}"',
            "    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
            "    move-result v1",
            f"    if-eqz v1, {next_label}",
        ])
        if action.get("persist_on_resume"):
            apply_lines.extend([
                "    const/4 v2, 0x1",
                "    invoke-static {p0, v0, v2}, Lapkagi/menu/MenuActions;->setEnabled(Landroid/content/Context;Ljava/lang/String;Z)V",
            ])
        apply_lines.extend(_action_lines(action))
        apply_lines.extend([
            f'    const-string v0, "{_escape_smali_string(action.get("success_message") or action["label"])}"',
            "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
            "    return-void",
            f"{next_label}",
        ])

        if action.get("persist_on_resume"):
            reapply_next_label = f":apkagi_reapply_next_{index}"
            reapply_lines.extend([
                f'    const-string v0, "{action_id}"',
                "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->isEnabled(Landroid/content/Context;Ljava/lang/String;)Z",
                "    move-result v1",
                f"    if-eqz v1, {reapply_next_label}",
            ])
            reapply_lines.extend(_action_lines(action))
            reapply_lines.append(reapply_next_label)

    if not reapply_lines:
        reapply_lines = ["    return-void"]
    else:
        reapply_lines.append("    return-void")

    apply_lines.extend([
        '    const-string v0, "Unknown mod action"',
        "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
        "    return-void",
    ])

    return "\n".join([
        ".class public final Lapkagi/menu/MenuActions;",
        ".super Ljava/lang/Object;",
        '.source "MenuActions.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method private static prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    .locals 2",
        f'    const-string v0, "{_MENU_PREFS_NAME}"',
        "    const/4 v1, 0x0",
        "    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    return-object v0",
        ".end method",
        "",
        ".method private static setEnabled(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
        ".end method",
        "",
        ".method private static isEnabled(Landroid/content/Context;Ljava/lang/String;)Z",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    const/4 v1, 0x0",
        "    invoke-interface {v0, p1, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static clearAll(Landroid/content/Context;)V",
        "    .locals 2",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
        ".end method",
        "",
        ".method public static toast(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 2",
        "    const/4 v0, 0x0",
        "    invoke-static {p0, p1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;",
        "    move-result-object v0",
        "    invoke-virtual {v0}, Landroid/widget/Toast;->show()V",
        "    return-void",
        ".end method",
        "",
        ".method public static reapplyEnabled(Landroid/content/Context;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_reapply_done",
        *reapply_lines,
        ":apkagi_reapply_done",
        "    return-void",
        ".end method",
        "",
        ".method public static apply(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_apply_done",
        "    if-eqz p1, :apkagi_apply_done",
        *apply_lines,
        ":apkagi_apply_done",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_click_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuActionClickListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/view/View$OnClickListener;",
        '.source "MenuActionClickListener.java"',
        "",
        ".field private final actionId:Ljava/lang/String;",
        ".field private final appContext:Landroid/content/Context;",
        "",
        ".method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;",
        "    move-result-object v0",
        "    iput-object v0, p0, Lapkagi/menu/MenuActionClickListener;->appContext:Landroid/content/Context;",
        "    iput-object p2, p0, Lapkagi/menu/MenuActionClickListener;->actionId:Ljava/lang/String;",
        "    return-void",
        ".end method",
        "",
        ".method public onClick(Landroid/view/View;)V",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/MenuActionClickListener;->appContext:Landroid/content/Context;",
        "    iget-object v1, p0, Lapkagi/menu/MenuActionClickListener;->actionId:Ljava/lang/String;",
        "    invoke-static {v0, v1}, Lapkagi/menu/MenuActions;->apply(Landroid/content/Context;Ljava/lang/String;)V",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_lifecycle_callbacks_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuLifecycleCallbacks;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/app/Application$ActivityLifecycleCallbacks;",
        '.source "MenuLifecycleCallbacks.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityStarted(Landroid/app/Activity;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityResumed(Landroid/app/Activity;)V",
        "    .locals 0",
        "    invoke-static {p1}, Lapkagi/menu/InAppMenuBridge;->attach(Landroid/app/Activity;)V",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityPaused(Landroid/app/Activity;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityStopped(Landroid/app/Activity;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onActivityDestroyed(Landroid/app/Activity;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_bridge_smali(spec: dict[str, Any]) -> str:
    button_lines: list[str] = []
    for action in spec["buttons"]:
        button_lines.extend([
            "    new-instance v3, Landroid/widget/Button;",
            "    invoke-direct {v3, p0}, Landroid/widget/Button;-><init>(Landroid/content/Context;)V",
            f'    const-string v4, "{_escape_smali_string(action["label"])}"',
            "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
            "    new-instance v4, Lapkagi/menu/MenuActionClickListener;",
            f'    const-string v5, "{_escape_smali_string(action["id"])}"',
            "    invoke-direct {v4, p0, v5}, Lapkagi/menu/MenuActionClickListener;-><init>(Landroid/content/Context;Ljava/lang/String;)V",
            "    invoke-virtual {v3, v4}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
            "    invoke-virtual {v2, v3}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        ])

    return "\n".join([
        ".class public final Lapkagi/menu/InAppMenuBridge;",
        ".super Ljava/lang/Object;",
        '.source "InAppMenuBridge.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public static install(Landroid/content/Context;)V",
        "    .locals 3",
        "    if-eqz p0, :apkagi_install_done",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabled(Landroid/content/Context;)V",
        "    instance-of v0, p0, Landroid/app/Application;",
        "    if-eqz v0, :apkagi_install_activity",
        "    new-instance v0, Lapkagi/menu/MenuLifecycleCallbacks;",
        "    invoke-direct {v0}, Lapkagi/menu/MenuLifecycleCallbacks;-><init>()V",
        "    move-object v1, p0",
        "    check-cast v1, Landroid/app/Application;",
        "    invoke-virtual {v1, v0}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V",
        "    return-void",
        ":apkagi_install_activity",
        "    instance-of v0, p0, Landroid/app/Activity;",
        "    if-eqz v0, :apkagi_install_done",
        "    move-object v1, p0",
        "    check-cast v1, Landroid/app/Activity;",
        "    invoke-static {v1}, Lapkagi/menu/InAppMenuBridge;->attach(Landroid/app/Activity;)V",
        ":apkagi_install_done",
        "    return-void",
        ".end method",
        "",
        ".method public static attach(Landroid/app/Activity;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_attach_done",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabled(Landroid/content/Context;)V",
        "    const v0, 0x1020002",
        "    invoke-virtual {p0, v0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;",
        "    move-result-object v0",
        "    if-eqz v0, :apkagi_attach_done",
        "    check-cast v0, Landroid/view/ViewGroup;",
        '    const-string v1, "APKAGI_MOD_MENU_PANEL"',
        "    invoke-virtual {v0, v1}, Landroid/view/View;->findViewWithTag(Ljava/lang/Object;)Landroid/view/View;",
        "    move-result-object v7",
        "    if-nez v7, :apkagi_attach_done",
        "    new-instance v2, Landroid/widget/LinearLayout;",
        "    invoke-direct {v2, p0}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        "    invoke-virtual {v2, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    const/4 v3, 0x1",
        "    invoke-virtual {v2, v3}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    const/16 v4, 0x10",
        "    invoke-virtual {v2, v4, v4, v4, v4}, Landroid/view/View;->setPadding(IIII)V",
        "    const v5, 0x66000000",
        "    invoke-virtual {v2, v5}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v3, Landroid/widget/TextView;",
        "    invoke-direct {v3, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        f'    const-string v4, "{_escape_smali_string(spec["title"])}"',
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    invoke-virtual {v2, v3}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        *button_lines,
        "    new-instance v3, Landroid/widget/FrameLayout$LayoutParams;",
        "    const/4 v4, -0x2",
        "    invoke-direct {v3, v4, v4}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V",
        "    const v4, 0x800033",
        "    iput v4, v3, Landroid/widget/FrameLayout$LayoutParams;->gravity:I",
        "    const/16 v4, 0x18",
        "    iput v4, v3, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    iput v4, v3, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    invoke-virtual {v0, v2, v3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V",
        ":apkagi_attach_done",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def inject_runtime_menu_scaffold(
    apktool_dir: str | Path,
    spec: dict[str, Any],
    *,
    overlay_mode: str = "in_app",
    backup_dir: str | Path | None = None,
    reapply_on_resume: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generate and inject a first-pass runtime mod-menu scaffold into an APK tree."""
    apktool_dir = Path(apktool_dir)
    backup_root = Path(backup_dir) if backup_dir else None
    normalized_spec = _normalize_menu_spec(spec, overlay_mode)
    requested_mode = normalized_spec["overlay_mode"]
    effective_mode = _effective_overlay_mode(requested_mode)
    requirements = _runtime_menu_requirements(requested_mode)

    helper_files = {
        "InAppMenuBridge.smali": _generate_bridge_smali(normalized_spec),
        "MenuLifecycleCallbacks.smali": _generate_lifecycle_callbacks_smali(),
        "MenuActionClickListener.smali": _generate_click_listener_smali(),
        "MenuActions.smali": _generate_actions_smali(normalized_spec),
    }

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "requested_overlay_mode": requested_mode,
            "effective_overlay_mode": effective_mode,
            "menu_title": normalized_spec["title"],
            "actions_generated": [button["id"] for button in normalized_spec["buttons"]],
            "helper_files": sorted(helper_files),
            "tier_b_requirements": requirements,
            "notes": [
                "Dry run only: no smali files or bootstrap hooks were written.",
                "The first implementation generates an in-app overlay panel scaffold.",
            ],
        }

    backed_up: dict[str, str] = {}
    touched_files: set[str] = set()
    validations: list[dict[str, Any]] = []
    errors: list[str] = []
    bootstrap_targets: list[dict[str, Any]] = []

    try:
        for relative_name, content in helper_files.items():
            helper_path = _helper_file_path(apktool_dir, relative_name)
            helper_path.parent.mkdir(parents=True, exist_ok=True)
            _backup_file(helper_path, apktool_dir, backup_root, backed_up)
            helper_path.write_text(content, encoding="utf-8")
            touched_files.add(str(helper_path))

        manifest_path = apktool_dir / "AndroidManifest.xml"
        entry = find_startup_entry(str(manifest_path), str(apktool_dir))
        if not entry.get("success"):
            errors.append(str(entry.get("error", "Could not find startup entry")))
        elif not entry.get("has_onCreate"):
            errors.append(f"Startup entry has no onCreate: {entry.get('class_name', '')}")
        else:
            entry_file = Path(str(entry["smali_file"]))
            _backup_file(entry_file, apktool_dir, backup_root, backed_up)
            if not _method_has_bootstrap(entry_file, "onCreate"):
                code = f"{_BOOTSTRAP_MARKER}\ninvoke-static {{p0}}, {_BOOTSTRAP_CALL}"
                result = inject_code_in_method(str(entry_file), "onCreate", code, "after_super")
                bootstrap_targets.append({"target": str(entry_file), "method": "onCreate", "result": result})
                if result.get("success"):
                    touched_files.add(str(entry_file))
                else:
                    errors.append(f"Startup bootstrap injection failed: {result.get('error', 'unknown error')}")
            else:
                bootstrap_targets.append({
                    "target": str(entry_file),
                    "method": "onCreate",
                    "result": {"success": True, "status": "already_present"},
                })

            if reapply_on_resume and entry.get("entry_type") == "LauncherActivity" and _method_exists(entry_file, "onResume"):
                if not _method_has_bootstrap(entry_file, "onResume"):
                    code = f"{_BOOTSTRAP_MARKER}\ninvoke-static {{p0}}, {_BOOTSTRAP_CALL}"
                    result = inject_code_in_method(str(entry_file), "onResume", code, "after_super")
                    bootstrap_targets.append({"target": str(entry_file), "method": "onResume", "result": result})
                    if result.get("success"):
                        touched_files.add(str(entry_file))
                    else:
                        errors.append(f"Resume bootstrap injection failed: {result.get('error', 'unknown error')}")

        for file_name in sorted(touched_files):
            if not file_name.endswith(".smali"):
                continue
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
        "requested_overlay_mode": requested_mode,
        "effective_overlay_mode": effective_mode,
        "menu_title": normalized_spec["title"],
        "actions_generated": [button["id"] for button in normalized_spec["buttons"]],
        "user_buttons": normalized_spec["user_buttons"],
        "persistent_buttons": normalized_spec["persistent_buttons"],
        "tier_b_requirements": requirements,
        "helper_classes": [_BRIDGE_DESCRIPTOR, _CLICK_DESCRIPTOR, _ACTIONS_DESCRIPTOR, _LIFECYCLE_DESCRIPTOR],
        "bootstrap_targets": bootstrap_targets,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "notes": [
            "The first scaffold generates an in-app overlay panel attached to the current Activity content view.",
            "Persistent actions are re-applied on future attaches/resumes until the generated reset button is pressed.",
            "If system_overlay or hybrid is requested, the current scaffold still falls back to the in-app panel until a full WindowManager service layer is implemented.",
        ],
        "errors": errors[:20],
    }


def _insert_permissions_block(manifest_text: str, missing_permissions: list[str]) -> str:
    if not missing_permissions:
        return manifest_text

    block = "\n".join(
        f'    <uses-permission android:name="{permission}" />'
        for permission in missing_permissions
    ) + "\n"

    application_idx = manifest_text.find("<application")
    if application_idx == -1:
        closing_idx = manifest_text.rfind("</manifest>")
        if closing_idx == -1:
            raise ValueError("AndroidManifest.xml has no <application> or </manifest> tag")
        return manifest_text[:closing_idx] + block + manifest_text[closing_idx:]
    return manifest_text[:application_idx] + block + manifest_text[application_idx:]


def configure_runtime_menu_manifest(
    apktool_dir: str | Path,
    *,
    overlay_mode: str = "in_app",
    backup_dir: str | Path | None = None,
    add_overlay_permission: bool = False,
    require_foreground_service: bool = False,
) -> dict[str, Any]:
    """Ensure the manifest declares the permissions needed for runtime menus."""
    apktool_dir = Path(apktool_dir)
    backup_root = Path(backup_dir) if backup_dir else None
    manifest_path = apktool_dir / "AndroidManifest.xml"
    parsed_before = parse_manifest(manifest_path)
    if not parsed_before.get("success"):
        return {"success": False, "error": parsed_before.get("error", "Manifest parse failed")}

    mode = str(overlay_mode or "in_app").strip().lower()
    if mode not in _SUPPORTED_OVERLAY_MODES:
        return {"success": False, "error": f"overlay_mode must be one of {sorted(_SUPPORTED_OVERLAY_MODES)}"}
    requirements = _runtime_menu_requirements(mode, require_foreground_service=require_foreground_service)

    existing_permissions = set(parsed_before.get("permissions") or [])
    target_sdk_text = str(parsed_before.get("target_sdk") or "").strip()
    target_sdk = int(target_sdk_text) if target_sdk_text.isdigit() else 0
    desired_permissions: list[str] = []

    if add_overlay_permission or mode in {"system_overlay", "hybrid"}:
        desired_permissions.append("android.permission.SYSTEM_ALERT_WINDOW")
    if require_foreground_service:
        desired_permissions.append("android.permission.FOREGROUND_SERVICE")
        if target_sdk >= 33:
            desired_permissions.append("android.permission.POST_NOTIFICATIONS")

    missing_permissions = [permission for permission in desired_permissions if permission not in existing_permissions]
    if not missing_permissions:
        return {
            "success": True,
            "requested_overlay_mode": mode,
            "effective_overlay_mode": _effective_overlay_mode(mode),
            "permissions_added": [],
            "already_present": desired_permissions,
            "manifest_file": str(manifest_path),
            "tier_b_requirements": requirements,
            "risk_level": "high" if mode in {"system_overlay", "hybrid"} else "low",
            "notes": [
                "No manifest permission changes were needed.",
                "SYSTEM_ALERT_WINDOW still requires user approval at runtime on supported Android versions."
                if any(permission.endswith("SYSTEM_ALERT_WINDOW") for permission in desired_permissions)
                else "",
            ],
        }

    backed_up: dict[str, str] = {}
    try:
        _backup_file(manifest_path, apktool_dir, backup_root, backed_up)
        original = manifest_path.read_text(encoding="utf-8", errors="replace")
        updated = _insert_permissions_block(original, missing_permissions)
        manifest_path.write_text(updated, encoding="utf-8")
        parsed_after = parse_manifest(manifest_path)
        if not parsed_after.get("success"):
            backup_path = backed_up.get(str(manifest_path.resolve()))
            if backup_path and Path(backup_path).exists():
                shutil.copy2(backup_path, manifest_path)
            return {
                "success": False,
                "error": parsed_after.get("error", "Manifest parse failed after patch"),
                "rollback_file": backup_path,
            }
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    notes = []
    if "android.permission.SYSTEM_ALERT_WINDOW" in missing_permissions:
        notes.append(
            "SYSTEM_ALERT_WINDOW is declared, but Android still requires an explicit runtime approval flow before true system overlays can draw."
        )
    if "android.permission.FOREGROUND_SERVICE" in missing_permissions:
        notes.append(
            "Foreground services require a notification path at runtime; this tool only declares the manifest permission."
        )

    return {
        "success": True,
        "requested_overlay_mode": mode,
        "effective_overlay_mode": _effective_overlay_mode(mode),
        "permissions_added": missing_permissions,
        "already_present": [permission for permission in desired_permissions if permission in existing_permissions],
        "manifest_file": str(manifest_path),
        "rollback_file": backed_up.get(str(manifest_path.resolve()), ""),
        "tier_b_requirements": requirements,
        "risk_level": "high" if mode in {"system_overlay", "hybrid"} else "low",
        "notes": notes,
    }