"""Runtime mod-menu scaffold generation for APK patch projects.

This module adds a first-class, typed runtime-menu layer on top of the
existing startup/runtime override infrastructure. The current scaffold now
supports a real floating UI layer with draggable panels and three control
types: button, toggle, and slider.

Supported action kinds:
    - shared_pref
    - static_field
    - invoke_static
    - dispatcher

The dispatcher action kind binds UI events directly to static runtime-hook
methods, so button presses, toggle changes, and slider commits can drive
runtime hooks without requiring extra handwritten glue inside the target app.

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
_TOGGLE_DESCRIPTOR = "Lapkagi/menu/MenuToggleCheckedChangeListener;"
_SLIDER_DESCRIPTOR = "Lapkagi/menu/MenuSliderChangeListener;"
_PANEL_DRAG_DESCRIPTOR = "Lapkagi/menu/MenuPanelDragTouchListener;"
_OVERLAY_DRAG_DESCRIPTOR = "Lapkagi/menu/OverlayMenuDragTouchListener;"
_LIFECYCLE_DESCRIPTOR = "Lapkagi/menu/MenuLifecycleCallbacks;"
_OVERLAY_SERVICE_DESCRIPTOR = "Lapkagi/menu/OverlayMenuService;"
_OVERLAY_SERVICE_FQCN = "apkagi.menu.OverlayMenuService"
_BOOTSTRAP_CALL = "Lapkagi/menu/InAppMenuBridge;->install(Landroid/content/Context;)V"
_BOOTSTRAP_MARKER = "# APK-AGI: RUNTIME MENU BOOTSTRAP"
_MENU_PREFS_NAME = "apkagi_runtime_menu"
_RESET_ACTION_ID = "__apkagi_reset_runtime_menu"
_RESET_ACTION_LABEL = "Reset Runtime Actions"
_SUPPORTED_OVERLAY_MODES = {"in_app", "system_overlay", "hybrid"}
_SUPPORTED_UI_KINDS = {"button", "toggle", "slider"}
_SUPPORTED_ACTION_KINDS = {"shared_pref", "static_field", "invoke_static", "dispatcher"}
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


def _validate_dispatcher_method_descriptor(descriptor: str, ui_kind: str) -> tuple[bool, str]:
    patterns = {
        "button": re.compile(r"^L[^;]+;->[\w$<>-]+\((?:|Landroid/content/Context;)\)V$"),
        "toggle": re.compile(r"^L[^;]+;->[\w$<>-]+\((?:Z|Landroid/content/Context;Z)\)V$"),
        "slider": re.compile(r"^L[^;]+;->[\w$<>-]+\((?:I|Landroid/content/Context;I)\)V$"),
    }
    if patterns[ui_kind].match(descriptor):
        return True, ""
    expected = {
        "button": "()V or (Landroid/content/Context;)V",
        "toggle": "(Z)V or (Landroid/content/Context;Z)V",
        "slider": "(I)V or (Landroid/content/Context;I)V",
    }
    return False, (
        f"dispatcher method_descriptor for {ui_kind} controls must be a static void descriptor with "
        f"{expected[ui_kind]}"
    )


def _coerce_int(raw_value: Any, *, field_name: str, index: int) -> int:
    try:
        return int(raw_value)
    except Exception as exc:  # pragma: no cover - defensive normalization path
        raise ValueError(f"buttons[{index}] {field_name} must be an integer") from exc


def _normalize_action(raw_action: dict[str, Any], index: int, default_persist: bool) -> dict[str, Any]:
    if not isinstance(raw_action, dict):
        raise ValueError(f"buttons[{index}] must be a JSON object")

    ui_kind = str(raw_action.get("ui_kind") or raw_action.get("control") or raw_action.get("widget") or "button").strip().lower()
    if ui_kind not in _SUPPORTED_UI_KINDS:
        raise ValueError(f"buttons[{index}] ui_kind must be one of {sorted(_SUPPORTED_UI_KINDS)}")

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
        "ui_kind": ui_kind,
        "kind": kind,
        "persist_on_resume": bool(raw_action.get("persist_on_resume", default_persist)),
        "success_message": str(raw_action.get("success_message") or f"Applied: {label}").strip(),
    }

    if ui_kind == "toggle":
        normalized.update({
            "default_state": bool(raw_action.get("default_state", raw_action.get("default_value", raw_action.get("initial_value", raw_action.get("value", False))))),
            "enabled_message": str(raw_action.get("enabled_message") or f"Enabled: {label}").strip(),
            "disabled_message": str(raw_action.get("disabled_message") or f"Disabled: {label}").strip(),
        })
    elif ui_kind == "slider":
        min_value = _coerce_int(raw_action.get("min_value", raw_action.get("min", 0)), field_name="min_value", index=index)
        max_value = _coerce_int(raw_action.get("max_value", raw_action.get("max", 100)), field_name="max_value", index=index)
        initial_value = _coerce_int(raw_action.get("initial_value", raw_action.get("value", min_value)), field_name="initial_value", index=index)
        if max_value < min_value:
            raise ValueError(f"buttons[{index}] slider max_value must be >= min_value")
        if not min_value <= initial_value <= max_value:
            raise ValueError(f"buttons[{index}] slider initial_value must be within min_value..max_value")
        normalized.update({
            "min_value": min_value,
            "max_value": max_value,
            "initial_value": initial_value,
        })

    if kind == "shared_pref":
        key = str(raw_action.get("key") or "").strip()
        value_type = str(raw_action.get("type") or "boolean").strip().lower()
        if not key:
            raise ValueError(f"buttons[{index}] shared_pref actions require key")
        if value_type not in {"boolean", "int", "long", "string"}:
            raise ValueError(f"buttons[{index}] shared_pref type must be boolean|int|long|string")
        if ui_kind == "button" and "value" not in raw_action:
            raise ValueError(f"buttons[{index}] shared_pref actions require value")
        if ui_kind == "toggle" and value_type != "boolean":
            raise ValueError(f"buttons[{index}] toggle shared_pref actions require type=boolean")
        if ui_kind == "slider" and value_type not in {"int", "long"}:
            raise ValueError(f"buttons[{index}] slider shared_pref actions require type=int|long")
        normalized.update({
            "prefs_name": str(raw_action.get("prefs_name") or raw_action.get("name") or "app_prefs"),
            "key": key,
            "type": value_type,
        })
        if ui_kind == "button":
            normalized["value"] = raw_action.get("value")
    elif kind == "static_field":
        class_descriptor = str(raw_action.get("class_descriptor") or raw_action.get("class") or "").strip()
        field_name = str(raw_action.get("field") or "").strip()
        field_type = str(raw_action.get("type") or "").strip()
        if not class_descriptor or not field_name or not field_type:
            raise ValueError(
                f"buttons[{index}] static_field actions require class_descriptor/class, field, and type"
            )
        if ui_kind == "toggle" and field_type != "Z":
            raise ValueError(f"buttons[{index}] toggle static_field actions require type=Z")
        if ui_kind == "slider" and field_type not in {"I", "J"}:
            raise ValueError(f"buttons[{index}] slider static_field actions require type=I|J")
        normalized.update({
            "class_descriptor": class_descriptor,
            "field": field_name,
            "type": field_type,
        })
        if ui_kind == "button":
            normalized["value"] = raw_action.get("value")
    elif kind == "invoke_static":
        if ui_kind != "button":
            raise ValueError(f"buttons[{index}] invoke_static is button-only; use kind=dispatcher for toggle/slider hooks")
        method_descriptor = str(raw_action.get("method_descriptor") or raw_action.get("callback") or "").strip()
        is_valid, error = _validate_method_descriptor(method_descriptor)
        if not is_valid:
            raise ValueError(f"buttons[{index}] {error}")
        normalized.update({"method_descriptor": method_descriptor})
    else:
        method_descriptor = str(raw_action.get("method_descriptor") or raw_action.get("callback") or raw_action.get("hook") or "").strip()
        is_valid, error = _validate_dispatcher_method_descriptor(method_descriptor, ui_kind)
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

    buttons_raw = spec.get("buttons") or spec.get("actions") or spec.get("items")
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
            "ui_kind": "button",
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
        "control_types": sorted({button.get("ui_kind", "button") for button in normalized_buttons if button.get("kind") != "internal_reset"}),
    }


def _effective_overlay_mode(requested_mode: str) -> str:
    """Return the actual scaffold mode implemented by the current generator."""
    return requested_mode


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


def _const_int_lines(register: str, value: int) -> list[str]:
    if -8 <= value <= 7:
        return [f"    const/4 {register}, {hex(value)}"]
    if -32768 <= value <= 32767:
        return [f"    const/16 {register}, {hex(value)}"]
    return [f"    const {register}, {hex(value)}"]


def _toggle_state_key(action: dict[str, Any]) -> str:
    return f"toggle_state:{action['id']}"


def _slider_state_key(action: dict[str, Any]) -> str:
    return f"slider_state:{action['id']}"


def _shared_pref_action_lines(action: dict[str, Any], *, value_register: str | None = None) -> list[str]:
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

    if value_register is not None and value_type == "boolean":
        lines.extend([
            f"    invoke-interface {{v2, v3, {value_register}}}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    elif value_register is not None and value_type == "int":
        lines.extend([
            f"    invoke-interface {{v2, v3, {value_register}}}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    elif value_register is not None and value_type == "long":
        lines.extend([
            f"    int-to-long v4, {value_register}",
            "    invoke-interface {v2, v3, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    elif value_type == "boolean":
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
    elif value_register is None:
        lines.extend([
            f'    const-string v4, "{_escape_smali_string(value)}"',
            "    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v2",
        ])
    else:
        raise ValueError("Stateful shared_pref controls support boolean, int, or long values only")

    lines.append("    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V")
    return lines


def _static_field_action_lines(action: dict[str, Any], *, value_register: str | None = None) -> list[str]:
    class_descriptor = action["class_descriptor"]
    field_name = action["field"]
    field_type = action["type"]
    value = action.get("value")
    lines: list[str] = []

    if value_register is not None and field_type == "Z":
        lines.append(f"    sput-boolean {value_register}, {class_descriptor}->{field_name}:{field_type}")
    elif value_register is not None and field_type == "I":
        lines.append(f"    sput {value_register}, {class_descriptor}->{field_name}:{field_type}")
    elif value_register is not None and field_type == "J":
        lines.extend([
            f"    int-to-long v2, {value_register}",
            f"    sput-wide v2, {class_descriptor}->{field_name}:{field_type}",
        ])
    elif field_type == "Z":
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


def _dispatcher_action_lines(action: dict[str, Any], *, value_register: str | None = None) -> list[str]:
    descriptor = action["method_descriptor"]
    if value_register is None:
        if descriptor.endswith("()V"):
            return [f"    invoke-static {{}}, {descriptor}"]
        return [f"    invoke-static {{p0}}, {descriptor}"]
    if descriptor.endswith("(Z)V") or descriptor.endswith("(I)V"):
        return [f"    invoke-static {{{value_register}}}, {descriptor}"]
    return [f"    invoke-static {{p0, {value_register}}}, {descriptor}"]


def _button_action_lines(action: dict[str, Any]) -> list[str]:
    kind = action["kind"]
    if kind == "shared_pref":
        return _shared_pref_action_lines(action)
    if kind == "static_field":
        return _static_field_action_lines(action)
    if kind == "invoke_static":
        return _invoke_static_action_lines(action)
    if kind == "dispatcher":
        return _dispatcher_action_lines(action)
    if kind == "internal_reset":
        return ["    invoke-static {p0}, Lapkagi/menu/MenuActions;->clearAll(Landroid/content/Context;)V"]
    raise ValueError(f"Unsupported runtime-menu action kind: {kind}")


def _toggle_action_lines(action: dict[str, Any], value_register: str) -> list[str]:
    kind = action["kind"]
    if kind == "shared_pref":
        return _shared_pref_action_lines(action, value_register=value_register)
    if kind == "static_field":
        return _static_field_action_lines(action, value_register=value_register)
    if kind == "dispatcher":
        return _dispatcher_action_lines(action, value_register=value_register)
    raise ValueError(f"Unsupported toggle runtime-menu action kind: {kind}")


def _slider_action_lines(action: dict[str, Any], value_register: str) -> list[str]:
    kind = action["kind"]
    if kind == "shared_pref":
        return _shared_pref_action_lines(action, value_register=value_register)
    if kind == "static_field":
        return _static_field_action_lines(action, value_register=value_register)
    if kind == "dispatcher":
        return _dispatcher_action_lines(action, value_register=value_register)
    raise ValueError(f"Unsupported slider runtime-menu action kind: {kind}")


def _generate_actions_smali(spec: dict[str, Any]) -> str:
    click_lines: list[str] = []
    toggle_lines: list[str] = []
    slider_lines: list[str] = []
    reapply_lines: list[str] = []

    for index, action in enumerate(spec["buttons"]):
        ui_kind = action.get("ui_kind", "button")
        action_id = _escape_smali_string(action["id"])

        if ui_kind == "button":
            next_label = f":apkagi_click_next_{index}"
            click_lines.extend([
                f'    const-string v0, "{action_id}"',
                "    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
                "    move-result v1",
                f"    if-eqz v1, {next_label}",
            ])
            if action.get("persist_on_resume"):
                click_lines.extend([
                    "    const/4 v2, 0x1",
                    "    invoke-static {p0, v0, v2}, Lapkagi/menu/MenuActions;->setEnabled(Landroid/content/Context;Ljava/lang/String;Z)V",
                ])
            click_lines.extend(_button_action_lines(action))
            click_lines.extend([
                f'    const-string v0, "{_escape_smali_string(action.get("success_message") or action["label"])}"',
                "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
                "    return-void",
                f"{next_label}",
            ])

            if action.get("persist_on_resume"):
                reapply_next_label = f":apkagi_reapply_button_next_{index}"
                reapply_lines.extend([
                    f'    const-string v0, "{action_id}"',
                    "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->isEnabled(Landroid/content/Context;Ljava/lang/String;)Z",
                    "    move-result v1",
                    f"    if-eqz v1, {reapply_next_label}",
                ])
                reapply_lines.extend(_button_action_lines(action))
                reapply_lines.append(reapply_next_label)
            continue

        if ui_kind == "toggle":
            next_label = f":apkagi_toggle_next_{index}"
            toggle_lines.extend([
                f'    const-string v0, "{action_id}"',
                "    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
                "    move-result v1",
                f"    if-eqz v1, {next_label}",
            ])
            if action.get("persist_on_resume"):
                toggle_lines.extend([
                    f'    const-string v0, "{_escape_smali_string(_toggle_state_key(action))}"',
                    "    invoke-static {p0, v0, p2}, Lapkagi/menu/MenuActions;->setToggleState(Landroid/content/Context;Ljava/lang/String;Z)V",
                ])
            toggle_lines.extend(_toggle_action_lines(action, "p2"))
            toggle_lines.extend([
                f"    if-eqz p2, :apkagi_toggle_disabled_{index}",
                f'    const-string v0, "{_escape_smali_string(action.get("enabled_message") or action["label"])}"',
                "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
                "    return-void",
                f":apkagi_toggle_disabled_{index}",
                f'    const-string v0, "{_escape_smali_string(action.get("disabled_message") or action["label"])}"',
                "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
                "    return-void",
                f"{next_label}",
            ])

            if action.get("persist_on_resume"):
                reapply_next_label = f":apkagi_reapply_toggle_next_{index}"
                state_key = _escape_smali_string(_toggle_state_key(action))
                reapply_lines.extend([
                    f'    const-string v0, "{state_key}"',
                    "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->hasState(Landroid/content/Context;Ljava/lang/String;)Z",
                    "    move-result v1",
                    f"    if-eqz v1, {reapply_next_label}",
                    "    const/4 v2, 0x0",
                    "    invoke-static {p0, v0, v2}, Lapkagi/menu/MenuActions;->getToggleState(Landroid/content/Context;Ljava/lang/String;Z)Z",
                    "    move-result v2",
                ])
                reapply_lines.extend(_toggle_action_lines(action, "v2"))
                reapply_lines.append(reapply_next_label)
            continue

        next_label = f":apkagi_slider_next_{index}"
        slider_lines.extend([
            f'    const-string v0, "{action_id}"',
            "    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
            "    move-result v1",
            f"    if-eqz v1, {next_label}",
        ])
        if action.get("persist_on_resume"):
            slider_lines.extend([
                f'    const-string v0, "{_escape_smali_string(_slider_state_key(action))}"',
                "    invoke-static {p0, v0, p2}, Lapkagi/menu/MenuActions;->setSliderState(Landroid/content/Context;Ljava/lang/String;I)V",
            ])
        slider_lines.extend(_slider_action_lines(action, "p2"))
        slider_lines.extend([
            f'    const-string v0, "{_escape_smali_string(action.get("success_message") or action["label"])}"',
            "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
            "    return-void",
            f"{next_label}",
        ])

        if action.get("persist_on_resume"):
            reapply_next_label = f":apkagi_reapply_slider_next_{index}"
            state_key = _escape_smali_string(_slider_state_key(action))
            reapply_lines.extend([
                f'    const-string v0, "{state_key}"',
                "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->hasState(Landroid/content/Context;Ljava/lang/String;)Z",
                "    move-result v1",
                f"    if-eqz v1, {reapply_next_label}",
                *_const_int_lines("v2", int(action.get("initial_value", 0))),
                "    invoke-static {p0, v0, v2}, Lapkagi/menu/MenuActions;->getSliderState(Landroid/content/Context;Ljava/lang/String;I)I",
                "    move-result v2",
            ])
            reapply_lines.extend(_slider_action_lines(action, "v2"))
            reapply_lines.append(reapply_next_label)

    if not reapply_lines:
        reapply_lines = ["    return-void"]
    else:
        reapply_lines.append("    return-void")

    click_lines.extend([
        '    const-string v0, "Unknown mod action"',
        "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
        "    return-void",
    ])

    if not toggle_lines:
        toggle_lines = ["    return-void"]
    else:
        toggle_lines.extend([
            '    const-string v0, "Unknown toggle action"',
            "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
            "    return-void",
        ])

    if not slider_lines:
        slider_lines = ["    return-void"]
    else:
        slider_lines.extend([
            '    const-string v0, "Unknown slider action"',
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
        ".method private static hasState(Landroid/content/Context;Ljava/lang/String;)Z",
        "    .locals 2",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z",
        "    move-result v0",
        "    return v0",
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
        ".method private static setToggleState(Landroid/content/Context;Ljava/lang/String;Z)V",
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
        ".method private static getToggleState(Landroid/content/Context;Ljava/lang/String;Z)Z",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method private static setSliderState(Landroid/content/Context;Ljava/lang/String;I)V",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
        ".end method",
        "",
        ".method private static getSliderState(Landroid/content/Context;Ljava/lang/String;I)I",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I",
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
        ".method public static dispatchClick(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_apply_done",
        "    if-eqz p1, :apkagi_apply_done",
        *click_lines,
        ":apkagi_apply_done",
        "    return-void",
        ".end method",
        "",
        ".method public static dispatchToggle(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    .locals 6",
        "    if-eqz p0, :apkagi_toggle_done",
        "    if-eqz p1, :apkagi_toggle_done",
        *toggle_lines,
        ":apkagi_toggle_done",
        "    return-void",
        ".end method",
        "",
        ".method public static dispatchSlider(Landroid/content/Context;Ljava/lang/String;I)V",
        "    .locals 6",
        "    if-eqz p0, :apkagi_slider_done",
        "    if-eqz p1, :apkagi_slider_done",
        *slider_lines,
        ":apkagi_slider_done",
        "    return-void",
        ".end method",
        "",
        ".method public static apply(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 0",
        "    invoke-static {p0, p1}, Lapkagi/menu/MenuActions;->dispatchClick(Landroid/content/Context;Ljava/lang/String;)V",
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
        "    invoke-static {v0, v1}, Lapkagi/menu/MenuActions;->dispatchClick(Landroid/content/Context;Ljava/lang/String;)V",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_toggle_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuToggleCheckedChangeListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/widget/CompoundButton$OnCheckedChangeListener;",
        '.source "MenuToggleCheckedChangeListener.java"',
        "",
        ".field private final actionId:Ljava/lang/String;",
        ".field private final appContext:Landroid/content/Context;",
        "",
        ".method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;",
        "    move-result-object v0",
        "    iput-object v0, p0, Lapkagi/menu/MenuToggleCheckedChangeListener;->appContext:Landroid/content/Context;",
        "    iput-object p2, p0, Lapkagi/menu/MenuToggleCheckedChangeListener;->actionId:Ljava/lang/String;",
        "    return-void",
        ".end method",
        "",
        ".method public onCheckedChanged(Landroid/widget/CompoundButton;Z)V",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/MenuToggleCheckedChangeListener;->appContext:Landroid/content/Context;",
        "    iget-object v1, p0, Lapkagi/menu/MenuToggleCheckedChangeListener;->actionId:Ljava/lang/String;",
        "    invoke-static {v0, v1, p2}, Lapkagi/menu/MenuActions;->dispatchToggle(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_slider_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuSliderChangeListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/widget/SeekBar$OnSeekBarChangeListener;",
        '.source "MenuSliderChangeListener.java"',
        "",
        ".field private final actionId:Ljava/lang/String;",
        ".field private final appContext:Landroid/content/Context;",
        ".field private final minValue:I",
        "",
        ".method public constructor <init>(Landroid/content/Context;Ljava/lang/String;I)V",
        "    .locals 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;",
        "    move-result-object v0",
        "    iput-object v0, p0, Lapkagi/menu/MenuSliderChangeListener;->appContext:Landroid/content/Context;",
        "    iput-object p2, p0, Lapkagi/menu/MenuSliderChangeListener;->actionId:Ljava/lang/String;",
        "    iput p3, p0, Lapkagi/menu/MenuSliderChangeListener;->minValue:I",
        "    return-void",
        ".end method",
        "",
        ".method public onProgressChanged(Landroid/widget/SeekBar;IZ)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onStartTrackingTouch(Landroid/widget/SeekBar;)V",
        "    .locals 0",
        "    return-void",
        ".end method",
        "",
        ".method public onStopTrackingTouch(Landroid/widget/SeekBar;)V",
        "    .locals 3",
        "    invoke-virtual {p1}, Landroid/widget/SeekBar;->getProgress()I",
        "    move-result v0",
        "    iget v1, p0, Lapkagi/menu/MenuSliderChangeListener;->minValue:I",
        "    add-int/2addr v0, v1",
        "    iget-object v1, p0, Lapkagi/menu/MenuSliderChangeListener;->appContext:Landroid/content/Context;",
        "    iget-object v2, p0, Lapkagi/menu/MenuSliderChangeListener;->actionId:Ljava/lang/String;",
        "    invoke-static {v1, v2, v0}, Lapkagi/menu/MenuActions;->dispatchSlider(Landroid/content/Context;Ljava/lang/String;I)V",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_panel_drag_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuPanelDragTouchListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/view/View$OnTouchListener;",
        '.source "MenuPanelDragTouchListener.java"',
        "",
        ".field private startLeft:I",
        ".field private startRawX:F",
        ".field private startRawY:F",
        ".field private startTop:I",
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z",
        "    .locals 8",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getAction()I",
        "    move-result v0",
        "    if-nez v0, :apkagi_drag_check_move",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawX()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawX:F",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawY()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawY:F",
        "    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;",
        "    move-result-object v1",
        "    instance-of v2, v1, Landroid/widget/FrameLayout$LayoutParams;",
        "    if-eqz v2, :apkagi_drag_handled",
        "    check-cast v1, Landroid/widget/FrameLayout$LayoutParams;",
        "    iget v2, v1, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    iput v2, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startLeft:I",
        "    iget v2, v1, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    iput v2, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startTop:I",
        ":apkagi_drag_handled",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_drag_check_move",
        "    const/4 v1, 0x2",
        "    if-ne v0, v1, :apkagi_drag_unhandled",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawX()F",
        "    move-result v2",
        "    iget v3, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawX:F",
        "    sub-float/2addr v2, v3",
        "    float-to-int v2, v2",
        "    iget v3, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startLeft:I",
        "    add-int/2addr v2, v3",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawY()F",
        "    move-result v3",
        "    iget v4, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawY:F",
        "    sub-float/2addr v3, v4",
        "    float-to-int v3, v3",
        "    iget v4, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startTop:I",
        "    add-int/2addr v3, v4",
        "    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;",
        "    move-result-object v4",
        "    instance-of v5, v4, Landroid/widget/FrameLayout$LayoutParams;",
        "    if-eqz v5, :apkagi_drag_return_true",
        "    check-cast v4, Landroid/widget/FrameLayout$LayoutParams;",
        "    iput v2, v4, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    iput v3, v4, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    invoke-virtual {p1, v4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V",
        ":apkagi_drag_return_true",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_drag_unhandled",
        "    const/4 v0, 0x0",
        "    return v0",
        ".end method",
        "",
    ]) + "\n"


def _generate_overlay_drag_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/OverlayMenuDragTouchListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/view/View$OnTouchListener;",
        '.source "OverlayMenuDragTouchListener.java"',
        "",
        ".field private final service:Lapkagi/menu/OverlayMenuService;",
        ".field private startRawX:F",
        ".field private startRawY:F",
        ".field private startX:I",
        ".field private startY:I",
        "",
        ".method public constructor <init>(Lapkagi/menu/OverlayMenuService;)V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    iput-object p1, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->service:Lapkagi/menu/OverlayMenuService;",
        "    return-void",
        ".end method",
        "",
        ".method public onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z",
        "    .locals 8",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getAction()I",
        "    move-result v0",
        "    if-nez v0, :apkagi_overlay_drag_check_move",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawX()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startRawX:F",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawY()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startRawY:F",
        "    iget-object v1, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->service:Lapkagi/menu/OverlayMenuService;",
        "    invoke-virtual {v1}, Lapkagi/menu/OverlayMenuService;->currentOverlayX()I",
        "    move-result v2",
        "    iput v2, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startX:I",
        "    invoke-virtual {v1}, Lapkagi/menu/OverlayMenuService;->currentOverlayY()I",
        "    move-result v2",
        "    iput v2, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startY:I",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_overlay_drag_check_move",
        "    const/4 v1, 0x2",
        "    if-ne v0, v1, :apkagi_overlay_drag_unhandled",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawX()F",
        "    move-result v2",
        "    iget v3, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startRawX:F",
        "    sub-float/2addr v2, v3",
        "    float-to-int v2, v2",
        "    iget v3, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startX:I",
        "    add-int/2addr v2, v3",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawY()F",
        "    move-result v3",
        "    iget v4, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startRawY:F",
        "    sub-float/2addr v3, v4",
        "    float-to-int v3, v3",
        "    iget v4, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->startY:I",
        "    add-int/2addr v3, v4",
        "    iget-object v4, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->service:Lapkagi/menu/OverlayMenuService;",
        "    invoke-virtual {v4, v2, v3}, Lapkagi/menu/OverlayMenuService;->updateOverlayPosition(II)V",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_overlay_drag_unhandled",
        "    const/4 v0, 0x0",
        "    return v0",
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


def _generate_widget_lines(spec: dict[str, Any], *, context_register: str, container_register: str) -> list[str]:
    widget_lines: list[str] = []
    for action in spec["buttons"]:
        ui_kind = action.get("ui_kind", "button")
        if ui_kind == "button":
            widget_lines.extend([
                "    new-instance v3, Landroid/widget/Button;",
                f"    invoke-direct {{v3, {context_register}}}, Landroid/widget/Button;-><init>(Landroid/content/Context;)V",
                f'    const-string v4, "{_escape_smali_string(action["label"])}"',
                "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
                "    new-instance v4, Lapkagi/menu/MenuActionClickListener;",
                f'    const-string v5, "{_escape_smali_string(action["id"])}"',
                f"    invoke-direct {{v4, {context_register}, v5}}, Lapkagi/menu/MenuActionClickListener;-><init>(Landroid/content/Context;Ljava/lang/String;)V",
                "    invoke-virtual {v3, v4}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
                f"    invoke-virtual {{{container_register}, v3}}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
            ])
            continue

        if ui_kind == "toggle":
            widget_lines.extend([
                "    new-instance v3, Landroid/widget/Switch;",
                f"    invoke-direct {{v3, {context_register}}}, Landroid/widget/Switch;-><init>(Landroid/content/Context;)V",
                f'    const-string v4, "{_escape_smali_string(action["label"])}"',
                "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
                f'    const-string v4, "{_escape_smali_string(_toggle_state_key(action))}"',
                f"    const/4 v5, {'0x1' if bool(action.get('default_state')) else '0x0'}",
                f"    invoke-static {{{context_register}, v4, v5}}, Lapkagi/menu/MenuActions;->getToggleState(Landroid/content/Context;Ljava/lang/String;Z)Z",
                "    move-result v5",
                "    invoke-virtual {v3, v5}, Landroid/widget/CompoundButton;->setChecked(Z)V",
                "    new-instance v4, Lapkagi/menu/MenuToggleCheckedChangeListener;",
                f'    const-string v5, "{_escape_smali_string(action["id"])}"',
                f"    invoke-direct {{v4, {context_register}, v5}}, Lapkagi/menu/MenuToggleCheckedChangeListener;-><init>(Landroid/content/Context;Ljava/lang/String;)V",
                "    invoke-virtual {v3, v4}, Landroid/widget/CompoundButton;->setOnCheckedChangeListener(Landroid/widget/CompoundButton$OnCheckedChangeListener;)V",
                f"    invoke-virtual {{{container_register}, v3}}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
            ])
            continue

        slider_min = int(action.get("min_value", 0))
        slider_max = int(action.get("max_value", slider_min))
        slider_initial = int(action.get("initial_value", slider_min))
        slider_span = slider_max - slider_min
        widget_lines.extend([
            "    new-instance v3, Landroid/widget/TextView;",
            f"    invoke-direct {{v3, {context_register}}}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
            f'    const-string v4, "{_escape_smali_string(action["label"])}"',
            "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
            "    const/4 v4, -0x1",
            "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
            f"    invoke-virtual {{{container_register}, v3}}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
            "    new-instance v3, Landroid/widget/SeekBar;",
            f"    invoke-direct {{v3, {context_register}}}, Landroid/widget/SeekBar;-><init>(Landroid/content/Context;)V",
            *_const_int_lines("v4", slider_span),
            "    invoke-virtual {v3, v4}, Landroid/widget/ProgressBar;->setMax(I)V",
            f'    const-string v4, "{_escape_smali_string(_slider_state_key(action))}"',
            *_const_int_lines("v5", slider_initial),
            f"    invoke-static {{{context_register}, v4, v5}}, Lapkagi/menu/MenuActions;->getSliderState(Landroid/content/Context;Ljava/lang/String;I)I",
            "    move-result v5",
            *_const_int_lines("v6", slider_min),
            "    sub-int/2addr v5, v6",
            "    invoke-virtual {v3, v5}, Landroid/widget/ProgressBar;->setProgress(I)V",
            "    new-instance v4, Lapkagi/menu/MenuSliderChangeListener;",
            f'    const-string v5, "{_escape_smali_string(action["id"])}"',
            *_const_int_lines("v6", slider_min),
            f"    invoke-direct {{v4, {context_register}, v5, v6}}, Lapkagi/menu/MenuSliderChangeListener;-><init>(Landroid/content/Context;Ljava/lang/String;I)V",
            "    invoke-virtual {v3, v4}, Landroid/widget/SeekBar;->setOnSeekBarChangeListener(Landroid/widget/SeekBar$OnSeekBarChangeListener;)V",
            f"    invoke-virtual {{{container_register}, v3}}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        ])

    return widget_lines


def _generate_bridge_smali(spec: dict[str, Any]) -> str:
    overlay_mode = str(spec.get("overlay_mode") or "in_app")
    include_in_app = overlay_mode in {"in_app", "hybrid"}
    include_system_overlay = overlay_mode in {"system_overlay", "hybrid"}
    widget_lines = _generate_widget_lines(spec, context_register="p0", container_register="v2")

    install_lines: list[str] = [
        "    if-eqz p0, :apkagi_install_done",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabled(Landroid/content/Context;)V",
    ]
    if include_system_overlay:
        install_lines.append("    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->ensureSystemOverlay(Landroid/content/Context;)V")
    if include_in_app:
        install_lines.extend([
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
        ])

    helper_lines = [
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
        *install_lines,
        ":apkagi_install_done",
        "    return-void",
        ".end method",
        "",
        ".method public static attach(Landroid/app/Activity;)V",
        "    .locals 12",
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
        "    new-instance v5, Lapkagi/menu/MenuPanelDragTouchListener;",
        "    invoke-direct {v5}, Lapkagi/menu/MenuPanelDragTouchListener;-><init>()V",
        "    invoke-virtual {v3, v5}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v2, v3}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        *widget_lines,
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
    ]

    if include_system_overlay:
        helper_lines.extend([
            ".method public static hasOverlayPermission(Landroid/content/Context;)Z",
            "    .locals 2",
            "    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I",
            "    const/16 v1, 0x17",
            "    if-lt v0, v1, :apkagi_overlay_legacy",
            "    invoke-static {p0}, Landroid/provider/Settings;->canDrawOverlays(Landroid/content/Context;)Z",
            "    move-result v0",
            "    return v0",
            ":apkagi_overlay_legacy",
            "    const/4 v0, 0x1",
            "    return v0",
            ".end method",
            "",
            ".method private static requestOverlayPermission(Landroid/content/Context;)V",
            "    .locals 4",
            "    # APK-AGI: ACTION_MANAGE_OVERLAY_PERMISSION request flow",
            "    new-instance v0, Landroid/content/Intent;",
            '    const-string v1, "android.settings.action.MANAGE_OVERLAY_PERMISSION"',
            "    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V",
            "    new-instance v1, Ljava/lang/StringBuilder;",
            "    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V",
            '    const-string v2, "package:"',
            "    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            "    move-result-object v1",
            "    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;",
            "    move-result-object v2",
            "    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            "    move-result-object v1",
            "    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;",
            "    move-result-object v1",
            "    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;",
            "    move-result-object v1",
            "    invoke-virtual {v0, v1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;",
            "    move-result-object v0",
            "    const/high16 v1, 0x1000",
            "    invoke-virtual {v0, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;",
            "    move-result-object v0",
            "    invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V",
            '    const-string v0, "Grant overlay permission to enable floating menu"',
            "    invoke-static {p0, v0}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
            "    return-void",
            ".end method",
            "",
            ".method private static startOverlayService(Landroid/content/Context;)V",
            "    .locals 3",
            "    new-instance v0, Landroid/content/Intent;",
            "    const-class v1, Lapkagi/menu/OverlayMenuService;",
            "    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
            "    invoke-virtual {p0, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;",
            "    return-void",
            ".end method",
            "",
            ".method private static ensureSystemOverlay(Landroid/content/Context;)V",
            "    .locals 1",
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->hasOverlayPermission(Landroid/content/Context;)Z",
            "    move-result v0",
            "    if-eqz v0, :apkagi_request_overlay",
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->startOverlayService(Landroid/content/Context;)V",
            "    return-void",
            ":apkagi_request_overlay",
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->requestOverlayPermission(Landroid/content/Context;)V",
            "    return-void",
            ".end method",
            "",
        ])

    return "\n".join(helper_lines) + "\n"


def _generate_overlay_service_smali(spec: dict[str, Any]) -> str:
    widget_lines = _generate_widget_lines(spec, context_register="p1", container_register="v2")

    return "\n".join([
        ".class public Lapkagi/menu/OverlayMenuService;",
        ".super Landroid/app/Service;",
        '.source "OverlayMenuService.java"',
        "",
        ".field private overlayParams:Landroid/view/WindowManager$LayoutParams;",
        ".field private overlayRoot:Landroid/view/View;",
        ".field private windowManager:Landroid/view/WindowManager;",
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Landroid/app/Service;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;",
        "    .locals 1",
        "    const/4 v0, 0x0",
        "    return-object v0",
        ".end method",
        "",
        ".method public onStartCommand(Landroid/content/Intent;II)I",
        "    .locals 1",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->hasOverlayPermission(Landroid/content/Context;)Z",
        "    move-result v0",
        "    if-eqz v0, :apkagi_overlay_no_permission",
        "    invoke-direct {p0}, Lapkagi/menu/OverlayMenuService;->ensureOverlayShown()V",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_overlay_no_permission",
        "    const/4 v0, 0x2",
        "    return v0",
        ".end method",
        "",
        ".method public onDestroy()V",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    iget-object v1, p0, Lapkagi/menu/OverlayMenuService;->windowManager:Landroid/view/WindowManager;",
        "    if-eqz v0, :apkagi_overlay_destroy_super",
        "    if-eqz v1, :apkagi_overlay_destroy_super",
        "    invoke-interface {v1, v0}, Landroid/view/WindowManager;->removeView(Landroid/view/View;)V",
        "    const/4 v0, 0x0",
        "    iput-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    iput-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    iput-object v0, p0, Lapkagi/menu/OverlayMenuService;->windowManager:Landroid/view/WindowManager;",
        ":apkagi_overlay_destroy_super",
        "    invoke-super {p0}, Landroid/app/Service;->onDestroy()V",
        "    return-void",
        ".end method",
        "",
        ".method public currentOverlayX()I",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    if-eqz v0, :apkagi_overlay_x_default",
        "    iget v0, v0, Landroid/view/WindowManager$LayoutParams;->x:I",
        "    return v0",
        ":apkagi_overlay_x_default",
        "    const/4 v0, 0x0",
        "    return v0",
        ".end method",
        "",
        ".method public currentOverlayY()I",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    if-eqz v0, :apkagi_overlay_y_default",
        "    iget v0, v0, Landroid/view/WindowManager$LayoutParams;->y:I",
        "    return v0",
        ":apkagi_overlay_y_default",
        "    const/4 v0, 0x0",
        "    return v0",
        ".end method",
        "",
        ".method public updateOverlayPosition(II)V",
        "    .locals 3",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    iget-object v1, p0, Lapkagi/menu/OverlayMenuService;->windowManager:Landroid/view/WindowManager;",
        "    iget-object v2, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    if-eqz v0, :apkagi_overlay_update_done",
        "    if-eqz v1, :apkagi_overlay_update_done",
        "    if-eqz v2, :apkagi_overlay_update_done",
        "    iput p1, v0, Landroid/view/WindowManager$LayoutParams;->x:I",
        "    iput p2, v0, Landroid/view/WindowManager$LayoutParams;->y:I",
        "    invoke-interface {v1, v2, v0}, Landroid/view/WindowManager;->updateViewLayout(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V",
        ":apkagi_overlay_update_done",
        "    return-void",
        ".end method",
        "",
        ".method private ensureOverlayShown()V",
        "    .locals 8",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    if-nez v0, :apkagi_overlay_done",
        '    const-string v0, "window"',
        "    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
        "    move-result-object v0",
        "    check-cast v0, Landroid/view/WindowManager;",
        "    iput-object v0, p0, Lapkagi/menu/OverlayMenuService;->windowManager:Landroid/view/WindowManager;",
        "    if-eqz v0, :apkagi_overlay_done",
        "    invoke-direct {p0, p0}, Lapkagi/menu/OverlayMenuService;->buildOverlayView(Landroid/content/Context;)Landroid/view/View;",
        "    move-result-object v1",
        "    iput-object v1, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I",
        "    const/16 v3, 0x1a",
        "    if-lt v2, v3, :apkagi_legacy_overlay_type",
        "    # APK-AGI: TYPE_APPLICATION_OVERLAY on API 26+",
        "    const/16 v2, 0x7f6",
        "    goto :apkagi_overlay_type_ready",
        ":apkagi_legacy_overlay_type",
        "    const/16 v2, 0x7d2",
        ":apkagi_overlay_type_ready",
        "    const/4 v3, -0x2",
        "    const/4 v4, -0x2",
        "    const/16 v5, 0x8",
        "    const/4 v6, -0x3",
        "    new-instance v7, Landroid/view/WindowManager$LayoutParams;",
        "    invoke-direct {v7}, Landroid/view/WindowManager$LayoutParams;-><init>()V",
        "    iput v3, v7, Landroid/view/ViewGroup$LayoutParams;->width:I",
        "    iput v4, v7, Landroid/view/ViewGroup$LayoutParams;->height:I",
        "    iput v2, v7, Landroid/view/WindowManager$LayoutParams;->type:I",
        "    iput v5, v7, Landroid/view/WindowManager$LayoutParams;->flags:I",
        "    iput v6, v7, Landroid/view/WindowManager$LayoutParams;->format:I",
        "    const v2, 0x800033",
        "    iput v2, v7, Landroid/view/WindowManager$LayoutParams;->gravity:I",
        "    const/16 v2, 0x18",
        "    iput v2, v7, Landroid/view/WindowManager$LayoutParams;->x:I",
        "    iput v2, v7, Landroid/view/WindowManager$LayoutParams;->y:I",
        "    iput-object v7, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    invoke-interface {v0, v1, v7}, Landroid/view/WindowManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V",
        ":apkagi_overlay_done",
        "    return-void",
        ".end method",
        "",
        ".method private buildOverlayView(Landroid/content/Context;)Landroid/view/View;",
        "    .locals 10",
        "    new-instance v2, Landroid/widget/LinearLayout;",
        "    invoke-direct {v2, p1}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        '    const-string v0, "APKAGI_SYSTEM_OVERLAY_PANEL"',
        "    invoke-virtual {v2, v0}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    const/4 v0, 0x1",
        "    invoke-virtual {v2, v0}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    const/16 v0, 0x10",
        "    invoke-virtual {v2, v0, v0, v0, v0}, Landroid/view/View;->setPadding(IIII)V",
        "    const v0, 0x66000000",
        "    invoke-virtual {v2, v0}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v3, Landroid/widget/TextView;",
        "    invoke-direct {v3, p1}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        f'    const-string v4, "{_escape_smali_string(spec["title"])}"',
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    new-instance v5, Lapkagi/menu/OverlayMenuDragTouchListener;",
        "    invoke-direct {v5, p0}, Lapkagi/menu/OverlayMenuDragTouchListener;-><init>(Lapkagi/menu/OverlayMenuService;)V",
        "    invoke-virtual {v3, v5}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v2, v3}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        *widget_lines,
        "    return-object v2",
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
    has_toggle = "toggle" in normalized_spec["control_types"]
    has_slider = "slider" in normalized_spec["control_types"]

    helper_files = {
        "InAppMenuBridge.smali": _generate_bridge_smali(normalized_spec),
        "MenuLifecycleCallbacks.smali": _generate_lifecycle_callbacks_smali(),
        "MenuActionClickListener.smali": _generate_click_listener_smali(),
        "MenuActions.smali": _generate_actions_smali(normalized_spec),
    }
    if requested_mode in {"in_app", "hybrid"}:
        helper_files["MenuPanelDragTouchListener.smali"] = _generate_panel_drag_listener_smali()
    if has_toggle:
        helper_files["MenuToggleCheckedChangeListener.smali"] = _generate_toggle_listener_smali()
    if has_slider:
        helper_files["MenuSliderChangeListener.smali"] = _generate_slider_listener_smali()
    if requested_mode in {"system_overlay", "hybrid"}:
        helper_files["OverlayMenuService.smali"] = _generate_overlay_service_smali(normalized_spec)
        helper_files["OverlayMenuDragTouchListener.smali"] = _generate_overlay_drag_listener_smali()

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "requested_overlay_mode": requested_mode,
            "effective_overlay_mode": effective_mode,
            "menu_title": normalized_spec["title"],
            "actions_generated": [button["id"] for button in normalized_spec["buttons"]],
            "control_types": normalized_spec["control_types"],
            "helper_files": sorted(helper_files),
            "tier_b_requirements": requirements,
            "notes": [
                "Dry run only: no smali files or bootstrap hooks were written.",
                "The current implementation generates draggable button/toggle/slider controls plus direct dispatcher bindings for runtime hooks.",
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
        "control_types": normalized_spec["control_types"],
        "tier_b_requirements": requirements,
        "helper_classes": [
            _BRIDGE_DESCRIPTOR,
            _CLICK_DESCRIPTOR,
            _ACTIONS_DESCRIPTOR,
            _LIFECYCLE_DESCRIPTOR,
            *([_PANEL_DRAG_DESCRIPTOR] if requested_mode in {"in_app", "hybrid"} else []),
            *([_TOGGLE_DESCRIPTOR] if has_toggle else []),
            *([_SLIDER_DESCRIPTOR] if has_slider else []),
            *([_OVERLAY_SERVICE_DESCRIPTOR] if requested_mode in {"system_overlay", "hybrid"} else []),
            *([_OVERLAY_DRAG_DESCRIPTOR] if requested_mode in {"system_overlay", "hybrid"} else []),
        ],
        "bootstrap_targets": bootstrap_targets,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "notes": [
            "The runtime-menu scaffold now generates a draggable floating panel with button, toggle, and slider controls.",
            "Persistent button/toggle/slider state is re-applied on later attaches/resumes until the generated reset button is pressed.",
            "kind=dispatcher binds controls directly to static runtime-hook methods without extra app-side glue.",
            "When system_overlay or hybrid is requested, the scaffold generates a real WindowManager overlay service and overlay-permission request flow.",
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


def _insert_service_declaration(manifest_text: str, service_fqcn: str) -> tuple[str, bool]:
    if f'android:name="{service_fqcn}"' in manifest_text:
        return manifest_text, False

    service_block = (
        f'        <service android:name="{service_fqcn}" '
        'android:exported="false" android:stopWithTask="false" />\n'
    )
    closing_idx = manifest_text.rfind("</application>")
    if closing_idx == -1:
        app_match = re.search(r"<application\b([^>]*)/>", manifest_text, re.DOTALL)
        if not app_match:
            raise ValueError("AndroidManifest.xml has no </application> tag")
        replacement = f"<application{app_match.group(1)}>\n{service_block}    </application>"
        return manifest_text[:app_match.start()] + replacement + manifest_text[app_match.end():], True
    return manifest_text[:closing_idx] + service_block + manifest_text[closing_idx:], True


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
    desired_services: list[str] = []

    if add_overlay_permission or mode in {"system_overlay", "hybrid"}:
        desired_permissions.append("android.permission.SYSTEM_ALERT_WINDOW")
        desired_services.append(_OVERLAY_SERVICE_FQCN)
    if require_foreground_service:
        desired_permissions.append("android.permission.FOREGROUND_SERVICE")
        if target_sdk >= 33:
            desired_permissions.append("android.permission.POST_NOTIFICATIONS")

    missing_permissions = [permission for permission in desired_permissions if permission not in existing_permissions]
    existing_services = {service.get("name", "") for service in parsed_before.get("services") or []}
    missing_services = [service for service in desired_services if service not in existing_services]
    if not missing_permissions and not missing_services:
        return {
            "success": True,
            "requested_overlay_mode": mode,
            "effective_overlay_mode": _effective_overlay_mode(mode),
            "permissions_added": [],
            "components_added": [],
            "already_present": desired_permissions,
            "already_present_components": desired_services,
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
        components_added: list[str] = []
        for service in missing_services:
            updated, added = _insert_service_declaration(updated, service)
            if added:
                components_added.append(service)
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
        "components_added": components_added,
        "already_present": [permission for permission in desired_permissions if permission in existing_permissions],
        "already_present_components": [service for service in desired_services if service in existing_services],
        "manifest_file": str(manifest_path),
        "rollback_file": backed_up.get(str(manifest_path.resolve()), ""),
        "tier_b_requirements": requirements,
        "risk_level": "high" if mode in {"system_overlay", "hybrid"} else "low",
        "notes": notes,
    }