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

import json
import re
import shutil
from pathlib import Path
from typing import Any

from apk_agent.tools.code_injector import find_startup_entry, inject_code_in_method
from apk_agent.tools.dex_engine import normalize_smali_root_name, plan_dex_injection
from apk_agent.tools.deep_analysis import validate_smali_syntax
from apk_agent.tools.manifest_parser import parse_manifest


_BRIDGE_DESCRIPTOR = "Lapkagi/menu/InAppMenuBridge;"
_ACTIONS_DESCRIPTOR = "Lapkagi/menu/MenuActions;"
_CLICK_DESCRIPTOR = "Lapkagi/menu/MenuActionClickListener;"
_VISIBILITY_DESCRIPTOR = "Lapkagi/menu/MenuVisibilityClickListener;"
_HOOK_BINDINGS_DESCRIPTOR = "Lapkagi/menu/RuntimeHookBindings;"
_TOGGLE_DESCRIPTOR = "Lapkagi/menu/MenuToggleCheckedChangeListener;"
_SLIDER_DESCRIPTOR = "Lapkagi/menu/MenuSliderChangeListener;"
_PANEL_DRAG_DESCRIPTOR = "Lapkagi/menu/MenuPanelDragTouchListener;"
_OVERLAY_DRAG_DESCRIPTOR = "Lapkagi/menu/OverlayMenuDragTouchListener;"
_COMPAT_DESCRIPTOR = "Lapkagi/menu/MenuCompat;"
_ATTACH_RUNNABLE_DESCRIPTOR = "Lapkagi/menu/MenuAttachRunnable;"
_LIFECYCLE_DESCRIPTOR = "Lapkagi/menu/MenuLifecycleCallbacks;"
_OVERLAY_SERVICE_DESCRIPTOR = "Lapkagi/menu/OverlayMenuService;"
_OVERLAY_SERVICE_FQCN = "apkagi.menu.OverlayMenuService"
_BOOTSTRAP_CALL = "Lapkagi/menu/InAppMenuBridge;->install(Landroid/content/Context;)V"
_BOOTSTRAP_MARKER = "# APK-AGI: RUNTIME MENU BOOTSTRAP"
_MENU_PREFS_NAME = "apkagi_runtime_menu"
_RESET_ACTION_ID = "__apkagi_reset_runtime_menu"
_RESET_ACTION_LABEL = "Reset Runtime Actions"
_MENU_HELPER_SECTION_TITLE = "Menu Tools"
_RESET_POSITION_ACTION_ID = "__apkagi_reset_menu_position"
_REQUEST_OVERLAY_ACCESS_ACTION_ID = "__apkagi_request_overlay_access"
_OPEN_OVERLAY_SETTINGS_ACTION_ID = "__apkagi_open_overlay_settings"
_RESTART_OVERLAY_SERVICE_ACTION_ID = "__apkagi_restart_overlay_service"
_SUPPORTED_OVERLAY_MODES = {"in_app", "system_overlay", "hybrid"}
_SUPPORTED_UI_KINDS = {"button", "toggle", "slider"}
_SUPPORTED_ACTION_KINDS = {"shared_pref", "static_field", "invoke_static", "dispatcher"}
_DEFAULT_ATTACH_DELAY_MS = 150
_DEFAULT_ATTACH_RETRY_COUNT = 2
_DEFAULT_ATTACH_RETRY_DELAY_MS = 250
_DIRECT_BINDING_UI_KIND = {
    tuple(): "button",
    ("Landroid/content/Context;",): "button",
    ("Z",): "toggle",
    ("Landroid/content/Context;", "Z"): "toggle",
    ("I",): "slider",
    ("Landroid/content/Context;", "I"): "slider",
}
_REFLECTIVE_BINDING_UI_KIND = {
    **_DIRECT_BINDING_UI_KIND,
    ("Ljava/lang/Boolean;",): "toggle",
    ("Landroid/content/Context;", "Ljava/lang/Boolean;"): "toggle",
    ("Ljava/lang/Integer;",): "slider",
    ("Landroid/content/Context;", "Ljava/lang/Integer;"): "slider",
    ("J",): "slider",
    ("Landroid/content/Context;", "J"): "slider",
    ("Ljava/lang/Long;",): "slider",
    ("Landroid/content/Context;", "Ljava/lang/Long;"): "slider",
}
_WRAPPER_PARAMS_BY_UI_KIND = {
    "button": "Landroid/content/Context;",
    "toggle": "Landroid/content/Context;Z",
    "slider": "Landroid/content/Context;I",
}
_ADAPTIVE_MODE_BY_SIGNATURE = {
    "button": {
        tuple(): 0,
        ("Landroid/content/Context;",): 1,
    },
    "toggle": {
        ("Z",): 0,
        ("Landroid/content/Context;", "Z"): 1,
        ("Ljava/lang/Boolean;",): 2,
        ("Landroid/content/Context;", "Ljava/lang/Boolean;"): 3,
    },
    "slider": {
        ("I",): 0,
        ("Landroid/content/Context;", "I"): 1,
        ("Ljava/lang/Integer;",): 2,
        ("Landroid/content/Context;", "Ljava/lang/Integer;"): 3,
        ("J",): 4,
        ("Landroid/content/Context;", "J"): 5,
        ("Ljava/lang/Long;",): 6,
        ("Landroid/content/Context;", "Ljava/lang/Long;"): 7,
    },
}
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


def _helper_file_path(apktool_dir: Path, relative_name: str, *, target_smali_root: str = "smali") -> Path:
    return apktool_dir / target_smali_root / "apkagi" / "menu" / relative_name


def _owning_smali_root_name(apktool_dir: Path, path: Path) -> str:
    rel = path.resolve().relative_to(apktool_dir.resolve())
    return normalize_smali_root_name(str(rel.parts[0]))


def _normalize_custom_helper_files(raw_files: Any) -> dict[str, str]:
    if raw_files in (None, ""):
        return {}
    if not isinstance(raw_files, dict):
        raise ValueError("custom_helper_files must be a JSON object mapping relative .smali paths to file contents")

    normalized: dict[str, str] = {}
    for raw_name, raw_content in raw_files.items():
        relative_name = str(raw_name or "").strip().replace("\\", "/")
        if not relative_name:
            raise ValueError("custom_helper_files keys must be non-empty relative .smali paths")
        path_obj = Path(relative_name)
        if path_obj.is_absolute() or ".." in path_obj.parts:
            raise ValueError(f"custom_helper_files path must stay under apkagi/menu: {relative_name}")
        if path_obj.suffix.lower() != ".smali":
            raise ValueError(f"custom_helper_files path must end with .smali: {relative_name}")
        normalized[path_obj.as_posix()] = str(raw_content)
    return normalized


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


def _restore_backup_entry(file_path: Path, backup_path: str) -> None:
    if backup_path and Path(backup_path).exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, file_path)
        return
    if file_path.exists():
        file_path.unlink()


def _rollback_runtime_menu_changes(touched_files: set[str], backed_up: dict[str, str]) -> list[str]:
    restored_files: list[str] = []
    for file_name in sorted(touched_files):
        file_path = Path(file_name)
        backup_path = backed_up.get(str(file_path.resolve()), "")
        _restore_backup_entry(file_path, backup_path)
        restored_files.append(str(file_path))
    return restored_files


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


def _parse_method_descriptor(descriptor: str) -> dict[str, Any] | None:
    match = re.match(r"^(L[^;]+;)->([\w$<>-]+)\((.*?)\)(\S+)$", str(descriptor or "").strip())
    if not match:
        return None
    return {
        "class_descriptor": match.group(1),
        "method_name": match.group(2),
        "params_blob": match.group(3),
        "param_types": _smali_param_descriptors(match.group(3)),
        "return_type": match.group(4),
    }


def _validate_dispatcher_method_descriptor(descriptor: str, ui_kind: str) -> tuple[bool, str]:
    parsed = _parse_method_descriptor(descriptor)
    if parsed is not None and str(parsed.get("return_type") or "") == "V":
        param_types = list(parsed.get("param_types") or [])
        direct_ui_kind = _ui_kind_for_params(param_types, allow_reflective=False)
        reflective_ui_kind = _ui_kind_for_params(param_types, allow_reflective=True)
        if direct_ui_kind == ui_kind or reflective_ui_kind == ui_kind:
            return True, ""
    expected = {
        "button": "()V or (Landroid/content/Context;)V",
        "toggle": "(Z)V, (Landroid/content/Context;Z)V, (Ljava/lang/Boolean;)V, or (Landroid/content/Context;Ljava/lang/Boolean;)V",
        "slider": "(I)V, (Landroid/content/Context;I)V, (Ljava/lang/Integer;)V, (Landroid/content/Context;Ljava/lang/Integer;)V, (J)V, (Landroid/content/Context;J)V, (Ljava/lang/Long;)V, or (Landroid/content/Context;Ljava/lang/Long;)V",
    }
    return False, (
        f"dispatcher method_descriptor for {ui_kind} controls must be a static void descriptor with "
        f"{expected[ui_kind]}"
    )


def _build_manual_dispatcher_binding(descriptor: str, ui_kind: str, *, binding_name: str) -> dict[str, Any] | None:
    parsed = _parse_method_descriptor(descriptor)
    if parsed is None or str(parsed.get("return_type") or "") != "V":
        return None

    param_types = list(parsed.get("param_types") or [])
    direct_ui_kind = _ui_kind_for_params(param_types, allow_reflective=False)
    reflective_ui_kind = _ui_kind_for_params(param_types, allow_reflective=True)
    if direct_ui_kind != ui_kind and reflective_ui_kind != ui_kind:
        return None

    binding_mode = "direct_static" if direct_ui_kind == ui_kind else "reflect_exact"
    binding_status = "resolved_static_target" if binding_mode == "direct_static" else "reflection_target"
    wrapper_params = _wrapper_params_for_ui_kind(ui_kind)
    class_descriptor = str(parsed.get("class_descriptor") or "")
    binding: dict[str, Any] = {
        "success": True,
        "binding_status": binding_status,
        "binding_mode": binding_mode,
        "ui_kind": ui_kind,
        "wrapper_method_descriptor": f"{_HOOK_BINDINGS_DESCRIPTOR}->{binding_name}({wrapper_params})V",
        "target_method_descriptor": descriptor,
        "target_param_types": param_types,
        "target_is_static": True,
        "target_java_class": _java_class_name(class_descriptor),
        "hook_target_class": class_descriptor,
        "hook_target_method": str(parsed.get("method_name") or ""),
        "persist_on_resume": False,
    }
    if binding_mode == "reflect_exact":
        binding["adaptive_mode"] = _adaptive_mode_for_signature(ui_kind, param_types)
    return binding


def _attach_manual_dispatcher_bindings(
    buttons: list[dict[str, Any]],
    existing_bindings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bindings = list(existing_bindings)
    known_wrappers = {
        str(binding.get("wrapper_method_descriptor") or "").strip()
        for binding in bindings
        if isinstance(binding, dict)
    }
    manual_index = 1

    for button in buttons:
        if str(button.get("kind") or "") != "dispatcher":
            continue
        descriptor = str(button.get("method_descriptor") or "").strip()
        parsed = _parse_method_descriptor(descriptor)
        if parsed is None:
            continue
        if str(parsed.get("class_descriptor") or "") == _HOOK_BINDINGS_DESCRIPTOR:
            continue
        param_types = list(parsed.get("param_types") or [])
        if _ui_kind_for_params(param_types, allow_reflective=False) == str(button.get("ui_kind") or "button"):
            continue

        while True:
            binding_name = f"manual_hook_{manual_index}"
            wrapper_descriptor = f"{_HOOK_BINDINGS_DESCRIPTOR}->{binding_name}({_wrapper_params_for_ui_kind(str(button.get('ui_kind') or 'button'))})V"
            if wrapper_descriptor not in known_wrappers:
                break
            manual_index += 1

        binding = _build_manual_dispatcher_binding(descriptor, str(button.get("ui_kind") or "button"), binding_name=binding_name)
        if binding is None:
            continue
        button["method_descriptor"] = str(binding["wrapper_method_descriptor"])
        bindings.append(binding)
        known_wrappers.add(str(binding["wrapper_method_descriptor"]))
        manual_index += 1

    return bindings


def _coerce_int(raw_value: Any, *, field_name: str, index: int) -> int:
    try:
        return int(raw_value)
    except Exception as exc:  # pragma: no cover - defensive normalization path
        raise ValueError(f"buttons[{index}] {field_name} must be an integer") from exc


def _default_persist_for_action(kind: str, *, spec_default: bool) -> bool:
    return spec_default if kind == "shared_pref" else False


def _is_generated_helper_action(action: dict[str, Any]) -> bool:
    return bool(action.get("generated_helper", False))


def _is_internal_action_kind(kind: str) -> bool:
    return str(kind or "").startswith("internal_")


def _helper_button_entry(
    action_id: str,
    label: str,
    *,
    kind: str,
    section: str,
    success_message: str,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "label": label,
        "ui_kind": "button",
        "kind": kind,
        "section": section,
        "persist_on_resume": False,
        "success_message": success_message,
        "generated_helper": True,
    }


def _append_builtin_helper_buttons(
    normalized_buttons: list[dict[str, Any]],
    *,
    runtime_settings: dict[str, Any],
    overlay_mode: str,
) -> None:
    if not bool(runtime_settings.get("include_helper_actions", True)):
        return

    helper_section = str(runtime_settings.get("helper_section_title") or _MENU_HELPER_SECTION_TITLE).strip() or _MENU_HELPER_SECTION_TITLE
    existing_ids = {str(button.get("id") or "") for button in normalized_buttons}

    helper_entries: list[dict[str, Any]] = []
    if overlay_mode in {"system_overlay", "hybrid"}:
        if bool(runtime_settings.get("add_overlay_permission_button", False)) and _REQUEST_OVERLAY_ACCESS_ACTION_ID not in existing_ids:
            helper_entries.append(_helper_button_entry(
                _REQUEST_OVERLAY_ACCESS_ACTION_ID,
                "Grant Overlay Permission / Start Overlay",
                kind="internal_overlay_grant",
                section=helper_section,
                success_message="Overlay helper launched",
            ))
            existing_ids.add(_REQUEST_OVERLAY_ACCESS_ACTION_ID)
        if bool(runtime_settings.get("add_overlay_settings_button", False)) and _OPEN_OVERLAY_SETTINGS_ACTION_ID not in existing_ids:
            helper_entries.append(_helper_button_entry(
                _OPEN_OVERLAY_SETTINGS_ACTION_ID,
                "Open Overlay Settings",
                kind="internal_overlay_settings",
                section=helper_section,
                success_message="Overlay settings opened",
            ))
            existing_ids.add(_OPEN_OVERLAY_SETTINGS_ACTION_ID)
        if bool(runtime_settings.get("add_restart_overlay_button", False)) and _RESTART_OVERLAY_SERVICE_ACTION_ID not in existing_ids:
            helper_entries.append(_helper_button_entry(
                _RESTART_OVERLAY_SERVICE_ACTION_ID,
                "Restart Overlay Service",
                kind="internal_restart_overlay",
                section=helper_section,
                success_message="Overlay service restart requested",
            ))
            existing_ids.add(_RESTART_OVERLAY_SERVICE_ACTION_ID)

    if bool(runtime_settings.get("add_reset_position_button", False)) and _RESET_POSITION_ACTION_ID not in existing_ids:
        helper_entries.append(_helper_button_entry(
            _RESET_POSITION_ACTION_ID,
            "Reset Menu Position",
            kind="internal_reset_position",
            section=helper_section,
            success_message="Stored menu position reset",
        ))

    normalized_buttons.extend(helper_entries)


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

    persist_on_resume = raw_action.get(
        "persist_on_resume",
        _default_persist_for_action(kind, spec_default=default_persist),
    )

    normalized: dict[str, Any] = {
        "id": action_id,
        "label": label,
        "ui_kind": ui_kind,
        "kind": kind,
        "section": str(raw_action.get("section") or raw_action.get("group") or "").strip(),
        "persist_on_resume": bool(persist_on_resume),
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


def _normalize_menu_runtime_settings(spec: dict[str, Any], overlay_mode: str) -> dict[str, Any]:
    raw_settings = spec.get("menu_settings") or spec.get("runtime_settings") or {}
    if raw_settings in (None, ""):
        raw_settings = {}
    if not isinstance(raw_settings, dict):
        raise ValueError("menu_settings must be a JSON object when provided")

    attach_delay_source = raw_settings.get("attach_delay_ms", spec.get("delayed_attach_ms", _DEFAULT_ATTACH_DELAY_MS))
    attach_retry_count_source = raw_settings.get(
        "attach_retry_count",
        spec.get("attach_retry_count", _DEFAULT_ATTACH_RETRY_COUNT),
    )
    attach_retry_delay_source = raw_settings.get(
        "attach_retry_delay_ms",
        spec.get("attach_retry_delay_ms", _DEFAULT_ATTACH_RETRY_DELAY_MS),
    )
    attach_root_strategy = str(
        raw_settings.get("attach_root_strategy", spec.get("attach_root_strategy", "auto")) or "auto"
    ).strip().lower()
    if attach_root_strategy not in {"auto", "content_first", "decor_first"}:
        raise ValueError("attach_root_strategy must be one of ['auto', 'content_first', 'decor_first']")

    overlay_fallback_default = overlay_mode == "hybrid"
    overlay_permission_default = overlay_mode in {"system_overlay", "hybrid"}

    attach_delay_ms = max(0, min(int(attach_delay_source or 0), 5000))
    attach_retry_count = max(0, min(int(attach_retry_count_source or 0), 5))
    attach_retry_delay_ms = max(0, min(int(attach_retry_delay_source or 0), 3000))
    overlay_fallback_on_attach_failure = bool(
        raw_settings.get(
            "overlay_fallback_on_attach_failure",
            spec.get("overlay_fallback_on_attach_failure", overlay_fallback_default),
        )
    )
    request_overlay_permission_on_fallback = bool(
        raw_settings.get(
            "request_overlay_permission_on_fallback",
            spec.get("request_overlay_permission_on_fallback", overlay_permission_default),
        )
    )
    auto_start_overlay = bool(raw_settings.get("auto_start_overlay", spec.get("auto_start_overlay", False)))
    include_helper_actions = bool(raw_settings.get("include_helper_actions", spec.get("include_helper_actions", True)))
    helper_section_title = str(
        raw_settings.get("helper_section_title", spec.get("helper_section_title", _MENU_HELPER_SECTION_TITLE))
        or _MENU_HELPER_SECTION_TITLE
    ).strip() or _MENU_HELPER_SECTION_TITLE
    overlay_helper_default = include_helper_actions and overlay_mode in {"system_overlay", "hybrid"}
    add_reset_position_button = bool(
        raw_settings.get(
            "add_reset_position_button",
            spec.get("add_reset_position_button", include_helper_actions),
        )
    ) if include_helper_actions else False
    add_overlay_permission_button = bool(
        raw_settings.get(
            "add_overlay_permission_button",
            spec.get("add_overlay_permission_button", overlay_helper_default),
        )
    ) if overlay_helper_default else False
    add_overlay_settings_button = bool(
        raw_settings.get(
            "add_overlay_settings_button",
            spec.get("add_overlay_settings_button", overlay_helper_default),
        )
    ) if overlay_helper_default else False
    add_restart_overlay_button = bool(
        raw_settings.get(
            "add_restart_overlay_button",
            spec.get("add_restart_overlay_button", overlay_helper_default),
        )
    ) if overlay_helper_default else False

    return {
        "attach_delay_ms": attach_delay_ms,
        "attach_retry_count": attach_retry_count,
        "attach_retry_delay_ms": attach_retry_delay_ms,
        "attach_root_strategy": attach_root_strategy,
        "overlay_fallback_on_attach_failure": overlay_fallback_on_attach_failure,
        "request_overlay_permission_on_fallback": request_overlay_permission_on_fallback,
        "auto_start_overlay": auto_start_overlay,
        "include_helper_actions": include_helper_actions,
        "helper_section_title": helper_section_title,
        "add_reset_position_button": add_reset_position_button,
        "add_overlay_permission_button": add_overlay_permission_button,
        "add_overlay_settings_button": add_overlay_settings_button,
        "add_restart_overlay_button": add_restart_overlay_button,
    }


def _normalize_menu_spec(spec: dict[str, Any], overlay_mode: str) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("spec_json must decode to a JSON object")

    chosen_mode = str(spec.get("overlay_mode") or overlay_mode or "in_app").strip().lower()
    if chosen_mode not in _SUPPORTED_OVERLAY_MODES:
        raise ValueError(f"overlay_mode must be one of {sorted(_SUPPORTED_OVERLAY_MODES)}")

    include_default_helpers = bool(spec.get("include_default_helpers", True))
    custom_helper_files = _normalize_custom_helper_files(
        spec.get("custom_helper_files") or spec.get("custom_smali_files")
    )
    buttons_raw = spec.get("buttons") or spec.get("actions") or spec.get("items")
    if buttons_raw in (None, ""):
        buttons_raw = []
    if not isinstance(buttons_raw, list):
        raise ValueError("spec must contain a buttons array when provided")
    if not buttons_raw and not custom_helper_files:
        raise ValueError("spec must contain a non-empty buttons array")
    if not include_default_helpers and "InAppMenuBridge.smali" not in custom_helper_files:
        raise ValueError(
            "custom runtime-menu injection without generated helpers must provide custom_helper_files['InAppMenuBridge.smali']"
        )

    default_persist = bool(spec.get("persist_on_resume", True))
    title = str(spec.get("title") or spec.get("menu_title") or "APK AGI MOD MENU").strip() or "APK AGI MOD MENU"
    launcher_label = str(spec.get("launcher_label") or spec.get("floating_icon_label") or spec.get("bubble_label") or "MOD").strip() or "MOD"
    start_collapsed = bool(spec.get("start_collapsed", True))
    auto_reapply_actions = bool(spec.get("auto_reapply_actions", False))
    restore_open_state = bool(spec.get("restore_open_state", False))
    runtime_settings = _normalize_menu_runtime_settings(spec, chosen_mode)
    target_smali_root = normalize_smali_root_name(
        spec.get("target_smali_root") or spec.get("helper_smali_root") or spec.get("target_dex_root") or "auto"
    )
    normalized_buttons = [
        _normalize_action(raw_action, idx, default_persist)
        for idx, raw_action in enumerate(buttons_raw)
    ]

    ids = [button["id"] for button in normalized_buttons]
    if len(set(ids)) != len(ids):
        raise ValueError("button ids must be unique within the runtime menu spec")

    hook_bindings = _attach_manual_dispatcher_bindings(
        normalized_buttons,
        [binding for binding in list(spec.get("hook_bindings") or []) if isinstance(binding, dict)],
    )

    _append_builtin_helper_buttons(
        normalized_buttons,
        runtime_settings=runtime_settings,
        overlay_mode=chosen_mode,
    )

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

    visible_buttons = [button for button in normalized_buttons if not _is_generated_helper_action(button)]

    return {
        "overlay_mode": chosen_mode,
        "title": title,
        "launcher_label": launcher_label,
        "start_collapsed": start_collapsed,
        "auto_reapply_actions": auto_reapply_actions,
        "restore_open_state": restore_open_state,
        "delayed_attach_ms": runtime_settings["attach_delay_ms"],
        "attach_retry_count": runtime_settings["attach_retry_count"],
        "attach_retry_delay_ms": runtime_settings["attach_retry_delay_ms"],
        "attach_root_strategy": runtime_settings["attach_root_strategy"],
        "auto_start_overlay": runtime_settings["auto_start_overlay"],
        "overlay_fallback_on_attach_failure": runtime_settings["overlay_fallback_on_attach_failure"],
        "request_overlay_permission_on_fallback": runtime_settings["request_overlay_permission_on_fallback"],
        "menu_settings": runtime_settings,
        "target_smali_root": target_smali_root,
        "buttons": normalized_buttons,
        "hook_bindings": hook_bindings,
        "custom_helper_files": custom_helper_files,
        "include_default_helpers": include_default_helpers,
        "user_buttons": len(buttons_raw),
        "persistent_buttons": sum(1 for button in normalized_buttons if button.get("persist_on_resume")),
        "section_count": len({button.get("section", "") for button in visible_buttons if button.get("section")}),
        "control_types": sorted({
            button.get("ui_kind", "button")
            for button in visible_buttons
            if not _is_internal_action_kind(str(button.get("kind") or ""))
        }),
    }


def _pretty_class_name(descriptor: str) -> str:
    cleaned = str(descriptor or "").strip()
    if cleaned.startswith("L") and cleaned.endswith(";"):
        cleaned = cleaned[1:-1]
    if "/" in cleaned:
        cleaned = cleaned.rsplit("/", 1)[-1]
    return cleaned or "RuntimeHook"


def _humanize_runtime_strategy(strategy: str) -> str:
    label = str(strategy or "runtime_hooks").replace("_", " ").strip()
    return label.title() or "Runtime Hooks"


def _smali_param_descriptors(params_blob: str) -> list[str]:
    params: list[str] = []
    index = 0
    while index < len(params_blob):
        token = params_blob[index]
        if token in "ZBCSIFJD":
            params.append(token)
            index += 1
            continue
        if token == "L":
            end = params_blob.find(";", index)
            if end == -1:
                break
            params.append(params_blob[index:end + 1])
            index = end + 1
            continue
        if token == "[":
            start = index
            index += 1
            while index < len(params_blob) and params_blob[index] == "[":
                index += 1
            if index < len(params_blob) and params_blob[index] == "L":
                end = params_blob.find(";", index)
                if end == -1:
                    break
                index = end + 1
            else:
                index += 1
            params.append(params_blob[start:index])
            continue
        index += 1
    return params


def _extract_method_name(method_query: str) -> str:
    query = str(method_query or "").strip()
    if "->" in query:
        query = query.split("->", 1)[1]
    if "(" in query:
        query = query.split("(", 1)[0]
    return query


def _method_header_matches(header_line: str, query: str) -> bool:
    stripped = header_line.strip()
    if not stripped.startswith(".method"):
        return False
    if "(" in query:
        return query in stripped
    method_name = _extract_method_name(query)
    match = re.search(r"([\w$<>-]+)\(", stripped)
    return bool(match and match.group(1) == method_name)


def _class_descriptor_from_smali(smali_file: Path) -> str:
    for line in smali_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith(".class "):
            match = re.search(r"(L[^;]+;)", stripped)
            if match:
                return match.group(1)
    return ""


def _java_class_name(class_descriptor: str) -> str:
    cleaned = str(class_descriptor or "").strip()
    if cleaned.startswith("L") and cleaned.endswith(";"):
        cleaned = cleaned[1:-1]
    return cleaned.replace("/", ".")


def _wrapper_params_for_ui_kind(ui_kind: str) -> str:
    return _WRAPPER_PARAMS_BY_UI_KIND.get(ui_kind, "Landroid/content/Context;")


def _ui_kind_for_params(param_types: list[str], *, allow_reflective: bool) -> str:
    lookup = _REFLECTIVE_BINDING_UI_KIND if allow_reflective else _DIRECT_BINDING_UI_KIND
    return lookup.get(tuple(param_types), "")


def _adaptive_mode_for_signature(ui_kind: str, param_types: list[str]) -> int:
    return int(_ADAPTIVE_MODE_BY_SIGNATURE.get(ui_kind, {}).get(tuple(param_types), -1))


def _has_default_constructor(smali_file: Path) -> bool:
    for line in smali_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped.startswith(".method"):
            continue
        if " constructor " not in f" {stripped} ":
            continue
        if "<init>()V" in stripped:
            return True
    return False


def _scan_hook_method_candidates(smali_file: Path, method_query: str) -> list[dict[str, Any]]:
    has_default_ctor = _has_default_constructor(smali_file)
    candidates: list[dict[str, Any]] = []
    for line in smali_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not _method_header_matches(stripped, method_query):
            continue
        signature_match = re.search(r"([\w$<>-]+)\((.*?)\)(\S+)$", stripped)
        if not signature_match:
            continue
        params_blob = signature_match.group(2)
        param_types = _smali_param_descriptors(params_blob)
        candidates.append({
            "header": stripped,
            "method_name": signature_match.group(1),
            "params_blob": params_blob,
            "param_types": param_types,
            "return_type": signature_match.group(3),
            "is_static": " static " in f" {stripped} ",
            "default_constructible": has_default_ctor,
            "direct_ui_kind": _ui_kind_for_params(param_types, allow_reflective=False),
            "reflective_ui_kind": _ui_kind_for_params(param_types, allow_reflective=True),
        })
    return candidates


def _binding_candidate_score(candidate: dict[str, Any]) -> tuple[int, int, int, int]:
    params = list(candidate.get("param_types") or [])
    has_context = int(bool(params and params[0] == "Landroid/content/Context;"))
    prefers_primitive = int(not any(param in {"Ljava/lang/Boolean;", "Ljava/lang/Integer;", "Ljava/lang/Long;"} for param in params))
    prefers_narrow = int(not any(param in {"J", "Ljava/lang/Long;"} for param in params))
    return (
        int(bool(candidate.get("is_static"))),
        has_context,
        prefers_primitive,
        prefers_narrow,
    )


def _pick_binding_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not candidates:
        return None
    ranked = sorted(candidates, key=_binding_candidate_score, reverse=True)
    if len(ranked) == 1:
        return ranked[0]
    if _binding_candidate_score(ranked[0]) == _binding_candidate_score(ranked[1]):
        return None
    return ranked[0]


def _build_binding_from_candidate(
    class_descriptor: str,
    smali_file: Path,
    candidate: dict[str, Any],
    *,
    index: int,
    binding_status: str,
) -> dict[str, Any]:
    ui_kind = str(candidate.get("direct_ui_kind") or candidate.get("reflective_ui_kind") or "button")
    wrapper_params = _wrapper_params_for_ui_kind(ui_kind)
    target_param_types = list(candidate.get("param_types") or [])
    binding: dict[str, Any] = {
        "success": True,
        "binding_status": binding_status,
        "binding_mode": ("direct_static" if binding_status == "resolved_static_target" else "reflect_exact"),
        "ui_kind": ui_kind,
        "wrapper_method_descriptor": f"{_HOOK_BINDINGS_DESCRIPTOR}->hook_{index}({wrapper_params})V",
        "target_method_descriptor": f"{class_descriptor}->{candidate['method_name']}({candidate['params_blob']})V",
        "target_param_types": target_param_types,
        "target_is_static": bool(candidate.get("is_static")),
        "target_java_class": _java_class_name(class_descriptor),
        "hook_smali_file": str(smali_file),
        "hook_target_class": class_descriptor,
        "hook_target_method": str(candidate.get("method_name") or ""),
        "persist_on_resume": False,
    }
    if binding_status == "reflection_target":
        binding["adaptive_mode"] = _adaptive_mode_for_signature(ui_kind, target_param_types)
    if ui_kind == "slider":
        binding.update({"min_value": 0, "max_value": 10, "initial_value": 1})
    return binding


def _infer_deferred_ui_kind(method_query: str) -> str:
    query = str(method_query or "").strip()
    if "(" not in query:
        return "button"
    params_blob = query.split("(", 1)[1].split(")", 1)[0]
    return _ui_kind_for_params(_smali_param_descriptors(params_blob), allow_reflective=True) or "button"


def _build_deferred_binding(class_descriptor: str, method_query: str, *, index: int) -> dict[str, Any]:
    ui_kind = _infer_deferred_ui_kind(method_query)
    wrapper_params = _wrapper_params_for_ui_kind(ui_kind)
    binding: dict[str, Any] = {
        "success": True,
        "binding_status": "deferred_lookup_target",
        "binding_mode": "reflect_search",
        "ui_kind": ui_kind,
        "wrapper_method_descriptor": f"{_HOOK_BINDINGS_DESCRIPTOR}->hook_{index}({wrapper_params})V",
        "target_java_class": _java_class_name(class_descriptor),
        "hook_target_class": class_descriptor,
        "hook_target_method": _extract_method_name(method_query),
        "persist_on_resume": False,
    }
    if ui_kind == "slider":
        binding.update({"min_value": 0, "max_value": 10, "initial_value": 1})
    return binding


def _resolve_hook_smali_file(apktool_dir: Path, hook: dict[str, Any]) -> Path | None:
    hook_file = str(hook.get("file") or "").strip()
    candidate_paths: list[Path] = []
    if hook_file:
        raw_path = Path(hook_file)
        candidate_paths.append(raw_path)
        if not raw_path.is_absolute():
            candidate_paths.append(apktool_dir / raw_path)
            candidate_paths.append(apktool_dir / raw_path.as_posix())

    class_descriptor = str(hook.get("class") or "").strip()
    if class_descriptor.startswith("L") and class_descriptor.endswith(";"):
        class_tail = class_descriptor[1:-1].replace("/", "\\") + ".smali"
        for smali_dir in sorted(apktool_dir.glob("smali*")):
            candidate_paths.append(smali_dir / class_tail)

    for candidate in candidate_paths:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _resolve_static_hook_binding(apktool_dir: Path, hook: dict[str, Any], *, index: int) -> dict[str, Any]:
    method_query = str(hook.get("method") or "").strip()
    if not method_query:
        return {"success": False, "binding_status": "missing_method_name", "error": "Hook candidate had no method name"}

    smali_file = _resolve_hook_smali_file(apktool_dir, hook)
    class_descriptor = str(hook.get("class") or "").strip()
    if smali_file is None:
        if class_descriptor:
            binding = _build_deferred_binding(class_descriptor, method_query, index=index)
            binding["error"] = f"Using deferred reflection lookup for unresolved hook: {class_descriptor}->{method_query}"
            return binding
        return {"success": False, "binding_status": "smali_file_not_found", "error": f"Could not locate smali file for hook: {method_query}"}

    class_descriptor = class_descriptor or _class_descriptor_from_smali(smali_file)
    if not class_descriptor:
        return {"success": False, "binding_status": "class_descriptor_missing", "error": f"Could not determine class descriptor for {smali_file.name}"}

    candidates = _scan_hook_method_candidates(smali_file, method_query)
    direct_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("return_type") == "V" and candidate.get("is_static") and candidate.get("direct_ui_kind")
    ]
    chosen_direct = _pick_binding_candidate(direct_candidates)
    if chosen_direct is not None:
        return _build_binding_from_candidate(
            class_descriptor,
            smali_file,
            chosen_direct,
            index=index,
            binding_status="resolved_static_target",
        )

    adaptive_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("return_type") == "V"
        and candidate.get("reflective_ui_kind")
        and (candidate.get("is_static") or candidate.get("default_constructible"))
    ]
    chosen_adaptive = _pick_binding_candidate(adaptive_candidates)
    if chosen_adaptive is not None:
        binding = _build_binding_from_candidate(
            class_descriptor,
            smali_file,
            chosen_adaptive,
            index=index,
            binding_status="reflection_target",
        )
        if int(binding.get("adaptive_mode", -1)) >= 0:
            return binding

    if class_descriptor:
        binding = _build_deferred_binding(class_descriptor, method_query, index=index)
        binding["hook_smali_file"] = str(smali_file)
        binding["error"] = f"Falling back to deferred runtime lookup for hook: {class_descriptor}->{method_query}"
        return binding

    if direct_candidates:
        return {
            "success": False,
            "binding_status": "ambiguous_supported_overloads",
            "error": f"Multiple supported static overloads found for hook: {class_descriptor}->{method_query}",
            "hook_smali_file": str(smali_file),
            "candidates": [f"{class_descriptor}->{candidate['method_name']}({candidate['params_blob']})V" for candidate in direct_candidates],
        }
    return {
        "success": False,
        "binding_status": "no_supported_static_signature",
        "error": f"No supported or adaptable signature found for hook: {class_descriptor}->{method_query}",
        "hook_smali_file": str(smali_file),
    }


def build_runtime_menu_spec_from_hook_plan(
    hook_plan: dict[str, Any],
    *,
    title: str = "",
    overlay_mode: str = "in_app",
    launcher_label: str = "HOOK",
    start_collapsed: bool = True,
    max_items: int = 6,
    apktool_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Build a grouped runtime-menu spec draft from behavior-engine runtime hook candidates."""
    if not hook_plan.get("success"):
        return {"success": False, "error": hook_plan.get("error", "Runtime hook plan failed")}

    hooks = list(hook_plan.get("runtime_hooks") or [])
    if not hooks:
        return {"success": False, "error": "No runtime hook candidates were available for runtime-menu drafting"}

    selected_hooks = hooks[: max(1, int(max_items))]
    buttons: list[dict[str, Any]] = []
    binding_hints: list[dict[str, Any]] = []
    hook_bindings: list[dict[str, Any]] = []
    apktool_root = Path(apktool_dir) if apktool_dir else None

    for index, hook in enumerate(selected_hooks, start=1):
        short_class = _pretty_class_name(str(hook.get("class", "")))
        method_name = str(hook.get("method") or "runtime_probe").strip() or "runtime_probe"
        section = _humanize_runtime_strategy(str(hook.get("strategy", "runtime_hooks")))
        action_id = _slugify(f"hook_{short_class}_{method_name}_{index}", fallback=f"hook_{index}")
        resolved_binding = (
            _resolve_static_hook_binding(apktool_root, hook, index=index)
            if apktool_root is not None else None
        )
        binding_status = str((resolved_binding or {}).get("binding_status") or "placeholder_dispatcher_descriptor")
        ui_kind = str((resolved_binding or {}).get("ui_kind") or "button")
        method_descriptor = str((resolved_binding or {}).get("wrapper_method_descriptor") or f"{_HOOK_BINDINGS_DESCRIPTOR}->hook_{index}(Landroid/content/Context;)V")
        button_entry: dict[str, Any] = {
            "id": action_id,
            "label": f"{short_class}.{method_name}",
            "section": section,
            "ui_kind": ui_kind,
            "kind": "dispatcher",
            "method_descriptor": method_descriptor,
            "persist_on_resume": bool((resolved_binding or {}).get("persist_on_resume", False)),
            "success_message": f"Triggered hook draft: {short_class}.{method_name}",
        }
        if ui_kind == "slider":
            button_entry.update({
                "min_value": int((resolved_binding or {}).get("min_value", 0)),
                "max_value": int((resolved_binding or {}).get("max_value", 10)),
                "initial_value": int((resolved_binding or {}).get("initial_value", 1)),
            })
        buttons.append({
            **button_entry,
        })
        binding_hint = {
            "success": bool((resolved_binding or {}).get("success", False)),
            "id": action_id,
            "placeholder_method_descriptor": f"{_HOOK_BINDINGS_DESCRIPTOR}->hook_{index}(Landroid/content/Context;)V",
            "hook_target_class": str(hook.get("class", "")),
            "hook_target_method": method_name,
            "strategy": str(hook.get("strategy", "")),
            "recommended_tools": list(hook.get("recommended_tools") or []),
            "observe": list(hook.get("observe") or []),
            "mutate": list(hook.get("mutate") or []),
            "reasons": list(hook.get("reasons") or [])[:5],
            "binding_status": binding_status,
        }
        if resolved_binding is not None:
            binding_hint.update({
                "resolved_wrapper_method_descriptor": resolved_binding.get("wrapper_method_descriptor", ""),
                "resolved_target_method_descriptor": resolved_binding.get("target_method_descriptor", ""),
                "ui_kind": resolved_binding.get("ui_kind", "button"),
            })
            if resolved_binding.get("success"):
                hook_bindings.append(dict(resolved_binding))
            elif resolved_binding.get("error"):
                binding_hint["error"] = resolved_binding["error"]
        binding_hints.append(binding_hint)

    spec = {
        "title": title or (f"{_pretty_class_name(str(selected_hooks[0].get('class', '')))} Runtime Hooks"),
        "overlay_mode": overlay_mode,
        "launcher_label": launcher_label,
        "start_collapsed": bool(start_collapsed),
        "buttons": buttons,
        "hook_bindings": hook_bindings,
    }
    real_bindings = sum(1 for hint in binding_hints if hint.get("success"))
    return {
        "success": True,
        "focus_hint": hook_plan.get("focus_hint", ""),
        "class_name": hook_plan.get("class_name", ""),
        "draft_mode": "real_dispatcher_bindings" if real_bindings else "placeholder_dispatchers",
        "resolved_bindings": real_bindings,
        "unsupported_bindings": [hint for hint in binding_hints if not hint.get("success")],
        "spec": spec,
        "spec_json": json.dumps(spec, ensure_ascii=False, indent=2),
        "binding_hints": binding_hints,
        "notes": [
            "This draft auto-groups runtime-hook candidates into a floating-menu spec.",
            "Supported static, reflective, and deferred runtime-hook candidates are rebound to real generated RuntimeHookBindings methods automatically.",
            "Only hook candidates that still fail binding remain listed in binding_hints/unsupported_bindings for manual follow-up.",
        ],
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


def _menu_open_key() -> str:
    return "ui:menu_open"


def _menu_left_key() -> str:
    return "ui:menu_left"


def _menu_top_key() -> str:
    return "ui:menu_top"


def _generate_direct_hook_binding_method(binding: dict[str, Any]) -> list[str]:
    wrapper = str(binding.get("wrapper_method_descriptor") or "").strip()
    target = str(binding.get("target_method_descriptor") or "").strip()
    ui_kind = str(binding.get("ui_kind") or "button")
    if not wrapper or not target or "->" not in wrapper or "->" not in target:
        return []

    wrapper_sig = wrapper.split("->", 1)[1]
    wrapper_name = _extract_method_name(wrapper_sig)
    wrapper_params = wrapper_sig.split("(", 1)[1].rsplit(")", 1)[0]
    target_params = list(binding.get("target_param_types") or [])
    invoke_blob = "{}"
    if ui_kind == "button":
        invoke_blob = "{p0}" if target_params == ["Landroid/content/Context;"] else "{}"
    elif ui_kind == "toggle":
        invoke_blob = "{p0, p1}" if target_params == ["Landroid/content/Context;", "Z"] else "{p1}"
    elif ui_kind == "slider":
        invoke_blob = "{p0, p1}" if target_params == ["Landroid/content/Context;", "I"] else "{p1}"

    return [
        f".method public static {wrapper_name}({wrapper_params})V",
        "    .locals 0",
        f"    invoke-static {invoke_blob}, {target}",
        "    return-void",
        ".end method",
        "",
    ]


def _generate_reflective_hook_binding_method(binding: dict[str, Any]) -> list[str]:
    wrapper = str(binding.get("wrapper_method_descriptor") or "").strip()
    ui_kind = str(binding.get("ui_kind") or "button")
    if not wrapper or "->" not in wrapper:
        return []

    wrapper_sig = wrapper.split("->", 1)[1]
    wrapper_name = _extract_method_name(wrapper_sig)
    wrapper_params = wrapper_sig.split("(", 1)[1].rsplit(")", 1)[0]
    class_name = _escape_smali_string(str(binding.get("target_java_class") or ""))
    method_name = _escape_smali_string(str(binding.get("hook_target_method") or ""))
    binding_status = str(binding.get("binding_status") or "reflection_target")
    is_static = "0x1" if bool(binding.get("target_is_static")) else "0x0"
    adaptive_mode = int(binding.get("adaptive_mode", 0))

    lines = [
        f".method public static {wrapper_name}({wrapper_params})V",
        "    .locals 4",
        f'    const-string v0, "{class_name}"',
        f'    const-string v1, "{method_name}"',
    ]
    if binding_status == "deferred_lookup_target":
        if ui_kind == "button":
            lines.extend([
                f"    invoke-static {{p0, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeDeferredButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V",
            ])
        elif ui_kind == "toggle":
            lines.extend([
                f"    invoke-static {{p0, v0, v1, p1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeDeferredToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Z)V",
            ])
        else:
            lines.extend([
                f"    invoke-static {{p0, v0, v1, p1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeDeferredSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;I)V",
            ])
    else:
        lines.extend([
            f"    const/4 v2, {is_static}",
            f"    const/4 v3, {hex(adaptive_mode)}",
        ])
        if ui_kind == "button":
            lines.extend([
                f"    invoke-static {{p0, v0, v1, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
            ])
        elif ui_kind == "toggle":
            lines.extend([
                f"    invoke-static {{p0, v0, v1, p1, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
            ])
        else:
            lines.extend([
                f"    invoke-static {{p0, v0, v1, p1, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
            ])
        lines.append("    move-result v0")

    lines.extend([
        "    return-void",
        ".end method",
        "",
    ])
    return lines


def _generate_runtime_hook_reflection_helpers() -> list[str]:
    return [
        ".method private static newInstanceOrNull(Ljava/lang/Class;)Ljava/lang/Object;",
        "    .locals 4",
        "    :try_start_0",
        "    const/4 v0, 0x0",
        "    new-array v1, v0, [Ljava/lang/Class;",
        "    invoke-virtual {p0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;",
        "    move-result-object v1",
        "    const/4 v2, 0x1",
        "    invoke-virtual {v1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V",
        "    new-array v2, v0, [Ljava/lang/Object;",
        "    invoke-virtual {v1, v2}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
        "    move-result-object v3",
        "    return-object v3",
        "    :try_end_0",
        "    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0",
        "    :catch_0",
        "    const/4 v0, 0x0",
        "    return-object v0",
        ".end method",
        "",
        ".method private static invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    .locals 5",
        "    :try_start_0",
        "    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
        "    move-result-object v0",
        "    invoke-virtual {v0, p1, p3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        "    move-result-object v1",
        "    const/4 v2, 0x1",
        "    invoke-virtual {v1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V",
        "    if-eqz p2, :apkagi_invoke_exact_instance",
        "    const/4 v2, 0x0",
        "    goto :apkagi_invoke_exact_ready",
        "    :apkagi_invoke_exact_instance",
        f"    invoke-static {{v0}}, {_HOOK_BINDINGS_DESCRIPTOR}->newInstanceOrNull(Ljava/lang/Class;)Ljava/lang/Object;",
        "    move-result-object v2",
        "    if-nez v2, :apkagi_invoke_exact_ready",
        "    const/4 v3, 0x0",
        "    return v3",
        "    :apkagi_invoke_exact_ready",
        "    invoke-virtual {v1, v2, p4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
        "    const/4 v3, 0x1",
        "    return v3",
        "    :try_end_0",
        "    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0",
        "    :catch_0",
        "    const/4 v3, 0x0",
        "    return v3",
        ".end method",
        "",
        ".method private static invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
        "    .locals 6",
        "    const/4 v0, 0x1",
        "    if-ne p4, v0, :apkagi_button_no_context",
        "    new-array v1, v0, [Ljava/lang/Class;",
        "    const-class v2, Landroid/content/Context;",
        "    const/4 v3, 0x0",
        "    aput-object v2, v1, v3",
        "    new-array v2, v0, [Ljava/lang/Object;",
        "    aput-object p0, v2, v3",
        f"    invoke-static {{p1, p2, p3, v1, v2}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v4",
        "    return v4",
        "    :apkagi_button_no_context",
        "    const/4 v0, 0x0",
        "    new-array v1, v0, [Ljava/lang/Class;",
        "    new-array v2, v0, [Ljava/lang/Object;",
        f"    invoke-static {{p1, p2, p3, v1, v2}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v4",
        "    return v4",
        ".end method",
        "",
        ".method private static invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    .locals 8",
        "    invoke-static {p3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;",
        "    move-result-object v0",
        "    const/4 v1, 0x3",
        "    if-ne p5, v1, :apkagi_toggle_mode2",
        "    const/4 v1, 0x2",
        "    new-array v2, v1, [Ljava/lang/Class;",
        "    const-class v3, Landroid/content/Context;",
        "    const/4 v4, 0x0",
        "    aput-object v3, v2, v4",
        "    const-class v3, Ljava/lang/Boolean;",
        "    const/4 v5, 0x1",
        "    aput-object v3, v2, v5",
        "    new-array v3, v1, [Ljava/lang/Object;",
        "    aput-object p0, v3, v4",
        "    aput-object v0, v3, v5",
        f"    invoke-static {{p1, p2, p4, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v6",
        "    return v6",
        "    :apkagi_toggle_mode2",
        "    const/4 v1, 0x2",
        "    if-ne p5, v1, :apkagi_toggle_mode1",
        "    const/4 v1, 0x1",
        "    new-array v2, v1, [Ljava/lang/Class;",
        "    const-class v3, Ljava/lang/Boolean;",
        "    const/4 v4, 0x0",
        "    aput-object v3, v2, v4",
        "    new-array v3, v1, [Ljava/lang/Object;",
        "    aput-object v0, v3, v4",
        f"    invoke-static {{p1, p2, p4, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v6",
        "    return v6",
        "    :apkagi_toggle_mode1",
        "    const/4 v1, 0x1",
        "    if-ne p5, v1, :apkagi_toggle_mode0",
        "    const/4 v1, 0x2",
        "    new-array v2, v1, [Ljava/lang/Class;",
        "    const-class v3, Landroid/content/Context;",
        "    const/4 v4, 0x0",
        "    aput-object v3, v2, v4",
        "    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;",
        "    const/4 v5, 0x1",
        "    aput-object v3, v2, v5",
        "    new-array v3, v1, [Ljava/lang/Object;",
        "    aput-object p0, v3, v4",
        "    aput-object v0, v3, v5",
        f"    invoke-static {{p1, p2, p4, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v6",
        "    return v6",
        "    :apkagi_toggle_mode0",
        "    const/4 v1, 0x1",
        "    new-array v2, v1, [Ljava/lang/Class;",
        "    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;",
        "    const/4 v4, 0x0",
        "    aput-object v3, v2, v4",
        "    new-array v3, v1, [Ljava/lang/Object;",
        "    aput-object v0, v3, v4",
        f"    invoke-static {{p1, p2, p4, v2, v3}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v6",
        "    return v6",
        ".end method",
        "",
        ".method private static invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    .locals 9",
        "    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;",
        "    move-result-object v0",
        "    int-to-long v1, p3",
        "    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;",
        "    move-result-object v3",
        "    const/4 v4, 0x7",
        "    if-ne p5, v4, :apkagi_slider_mode6",
        "    const/4 v4, 0x2",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Landroid/content/Context;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    const-class v6, Ljava/lang/Long;",
        "    const/4 v8, 0x1",
        "    aput-object v6, v5, v8",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object p0, v6, v7",
        "    aput-object v3, v6, v8",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode6",
        "    const/4 v4, 0x6",
        "    if-ne p5, v4, :apkagi_slider_mode5",
        "    const/4 v4, 0x1",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Ljava/lang/Long;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object v3, v6, v7",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode5",
        "    const/4 v4, 0x5",
        "    if-ne p5, v4, :apkagi_slider_mode4",
        "    const/4 v4, 0x2",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Landroid/content/Context;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    sget-object v6, Ljava/lang/Long;->TYPE:Ljava/lang/Class;",
        "    const/4 v8, 0x1",
        "    aput-object v6, v5, v8",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object p0, v6, v7",
        "    aput-object v3, v6, v8",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode4",
        "    const/4 v4, 0x4",
        "    if-ne p5, v4, :apkagi_slider_mode3",
        "    const/4 v4, 0x1",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    sget-object v6, Ljava/lang/Long;->TYPE:Ljava/lang/Class;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object v3, v6, v7",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode3",
        "    const/4 v4, 0x3",
        "    if-ne p5, v4, :apkagi_slider_mode2",
        "    const/4 v4, 0x2",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Landroid/content/Context;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    const-class v6, Ljava/lang/Integer;",
        "    const/4 v8, 0x1",
        "    aput-object v6, v5, v8",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object p0, v6, v7",
        "    aput-object v0, v6, v8",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode2",
        "    const/4 v4, 0x2",
        "    if-ne p5, v4, :apkagi_slider_mode1",
        "    const/4 v4, 0x1",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Ljava/lang/Integer;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object v0, v6, v7",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode1",
        "    const/4 v4, 0x1",
        "    if-ne p5, v4, :apkagi_slider_mode0",
        "    const/4 v4, 0x2",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    const-class v6, Landroid/content/Context;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    sget-object v6, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;",
        "    const/4 v8, 0x1",
        "    aput-object v6, v5, v8",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object p0, v6, v7",
        "    aput-object v0, v6, v8",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        "    :apkagi_slider_mode0",
        "    const/4 v4, 0x1",
        "    new-array v5, v4, [Ljava/lang/Class;",
        "    sget-object v6, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;",
        "    const/4 v7, 0x0",
        "    aput-object v6, v5, v7",
        "    new-array v6, v4, [Ljava/lang/Object;",
        "    aput-object v0, v6, v7",
        f"    invoke-static {{p1, p2, p4, v5, v6}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeExact(Ljava/lang/String;Ljava/lang/String;Z[Ljava/lang/Class;[Ljava/lang/Object;)Z",
        "    move-result v8",
        "    return v8",
        ".end method",
        "",
        ".method private static invokeDeferredButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V",
        "    .locals 2",
        "    const/4 v0, 0x1",
        f"    invoke-static {{p0, p1, p2, v0, v0}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
        "    move-result v1",
        "    if-nez v1, :apkagi_deferred_button_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x1",
        f"    invoke-static {{p0, p1, p2, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
        "    move-result v1",
        "    if-nez v1, :apkagi_deferred_button_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
        "    move-result v1",
        "    if-nez v1, :apkagi_deferred_button_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedButton(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZI)Z",
        "    move-result v1",
        "    :apkagi_deferred_button_done",
        "    return-void",
        ".end method",
        "",
        ".method private static invokeDeferredToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Z)V",
        "    .locals 3",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x1",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x1",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x3",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x3",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x2",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_toggle_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x2",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedToggle(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ZZI)Z",
        "    move-result v2",
        "    :apkagi_deferred_toggle_done",
        "    return-void",
        ".end method",
        "",
        ".method private static invokeDeferredSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;I)V",
        "    .locals 3",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x1",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x1",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x0",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x3",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x3",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x2",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x2",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x5",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x5",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x4",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x4",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x7",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x7",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x1",
        "    const/4 v1, 0x6",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    if-nez v2, :apkagi_deferred_slider_done",
        "    const/4 v0, 0x0",
        "    const/4 v1, 0x6",
        f"    invoke-static {{p0, p1, p2, p3, v0, v1}}, {_HOOK_BINDINGS_DESCRIPTOR}->invokeResolvedSlider(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZI)Z",
        "    move-result v2",
        "    :apkagi_deferred_slider_done",
        "    return-void",
        ".end method",
        "",
    ]


def _generate_runtime_hook_bindings_smali(bindings: list[dict[str, Any]]) -> str:
    helper_lines: list[str] = [
        ".class public final Lapkagi/menu/RuntimeHookBindings;",
        ".super Ljava/lang/Object;",
        '.source "RuntimeHookBindings.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
    ]

    adaptive_bindings = [
        binding
        for binding in bindings
        if str(binding.get("binding_mode") or "") in {"reflect_exact", "reflect_search"}
    ]
    if adaptive_bindings:
        helper_lines.extend(_generate_runtime_hook_reflection_helpers())

    for binding in bindings:
        binding_mode = str(binding.get("binding_mode") or "direct_static")
        if binding_mode == "direct_static":
            helper_lines.extend(_generate_direct_hook_binding_method(binding))
        else:
            helper_lines.extend(_generate_reflective_hook_binding_method(binding))

    return "\n".join(helper_lines) + "\n"


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
        if value is None:
            raise ValueError("shared_pref int actions require a value")
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
        if value is None:
            raise ValueError("shared_pref long actions require a value")
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
        if value is None:
            raise ValueError("static_field int writes require a value")
        int_value = int(value)
        if -8 <= int_value <= 7:
            lines.append(f"    const/4 v2, {hex(int_value)}")
        elif -32768 <= int_value <= 32767:
            lines.append(f"    const/16 v2, {hex(int_value)}")
        else:
            lines.append(f"    const v2, {hex(int_value)}")
        lines.append(f"    sput v2, {class_descriptor}->{field_name}:{field_type}")
    elif field_type == "J":
        if value is None:
            raise ValueError("static_field long writes require a value")
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


def _reset_control_state_lines(spec: dict[str, Any]) -> list[str]:
    reset_keys: list[str] = []
    for action in spec["buttons"]:
        if action.get("kind") == "internal_reset" or not action.get("persist_on_resume"):
            continue
        ui_kind = action.get("ui_kind", "button")
        if ui_kind == "button":
            reset_keys.append(str(action["id"]))
        elif ui_kind == "toggle":
            reset_keys.append(_toggle_state_key(action))
        else:
            reset_keys.append(_slider_state_key(action))

    if not reset_keys:
        return ["    return-void"]

    lines = [
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
    ]
    for key in reset_keys:
        lines.extend([
            f'    const-string v1, "{_escape_smali_string(key)}"',
            "    invoke-interface {v0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
            "    move-result-object v0",
        ])
    lines.extend([
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
    ])
    return lines


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
        return ["    invoke-static {p0}, Lapkagi/menu/MenuActions;->resetControls(Landroid/content/Context;)V"]
    if kind == "internal_reset_position":
        return ["    invoke-static {p0}, Lapkagi/menu/MenuActions;->resetMenuPosition(Landroid/content/Context;)V"]
    if kind == "internal_overlay_grant":
        return ["    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->requestOverlayAccessOrStart(Landroid/content/Context;)V"]
    if kind == "internal_overlay_settings":
        return ["    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->openOverlaySettings(Landroid/content/Context;)V"]
    if kind == "internal_restart_overlay":
        return ["    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->restartSystemOverlay(Landroid/content/Context;)V"]
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
    reset_lines = _reset_control_state_lines(spec)

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
            click_lines.extend(_button_action_lines(action))
            if action.get("persist_on_resume"):
                click_lines.extend([
                    "    const/4 v2, 0x1",
                    "    invoke-static {p0, v0, v2}, Lapkagi/menu/MenuActions;->setEnabled(Landroid/content/Context;Ljava/lang/String;Z)V",
                ])
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
            toggle_lines.extend(_toggle_action_lines(action, "p2"))
            if action.get("persist_on_resume"):
                toggle_lines.extend([
                    f'    const-string v0, "{_escape_smali_string(_toggle_state_key(action))}"',
                    "    invoke-static {p0, v0, p2}, Lapkagi/menu/MenuActions;->setToggleState(Landroid/content/Context;Ljava/lang/String;Z)V",
                ])
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
        slider_lines.extend(_slider_action_lines(action, "p2"))
        if action.get("persist_on_resume"):
            slider_lines.extend([
                f'    const-string v0, "{_escape_smali_string(_slider_state_key(action))}"',
                "    invoke-static {p0, v0, p2}, Lapkagi/menu/MenuActions;->setSliderState(Landroid/content/Context;Ljava/lang/String;I)V",
            ])
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
        ".method public static hasState(Landroid/content/Context;Ljava/lang/String;)Z",
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
        ".method public static setToggleState(Landroid/content/Context;Ljava/lang/String;Z)V",
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
        ".method public static getToggleState(Landroid/content/Context;Ljava/lang/String;Z)Z",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static setSliderState(Landroid/content/Context;Ljava/lang/String;I)V",
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
        ".method public static getSliderState(Landroid/content/Context;Ljava/lang/String;I)I",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0, p1, p2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static setMenuOpen(Landroid/content/Context;Z)V",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_open_key()}"',
        "    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
        ".end method",
        "",
        ".method public static isMenuOpen(Landroid/content/Context;Z)Z",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_open_key()}"',
        "    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static rememberMenuPosition(Landroid/content/Context;II)V",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_left_key()}"',
        "    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_top_key()}"',
        "    invoke-interface {v0, v1, p2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        "    return-void",
        ".end method",
        "",
        ".method public static getMenuLeft(Landroid/content/Context;I)I",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_left_key()}"',
        "    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static getMenuTop(Landroid/content/Context;I)I",
        "    .locals 3",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_top_key()}"',
        "    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I",
        "    move-result v0",
        "    return v0",
        ".end method",
        "",
        ".method public static resetMenuPosition(Landroid/content/Context;)V",
        "    .locals 3",
        "    if-eqz p0, :apkagi_reset_menu_position_done",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->prefs(Landroid/content/Context;)Landroid/content/SharedPreferences;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_left_key()}"',
        "    invoke-interface {v0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        f'    const-string v1, "{_menu_top_key()}"',
        "    invoke-interface {v0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        "    move-result-object v0",
        "    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V",
        ":apkagi_reset_menu_position_done",
        "    return-void",
        ".end method",
        "",
        ".method public static resetControls(Landroid/content/Context;)V",
        "    .locals 2",
        *reset_lines,
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
        "    if-eqz p0, :apkagi_toast_done",
        "    if-eqz p1, :apkagi_toast_done",
        "    :apkagi_toast_try_start",
        "    const/4 v0, 0x0",
        "    invoke-static {p0, p1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;",
        "    move-result-object v0",
        "    invoke-virtual {v0}, Landroid/widget/Toast;->show()V",
        "    :apkagi_toast_try_end",
        "    goto :apkagi_toast_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_toast_try_start .. :apkagi_toast_try_end} :apkagi_toast_catch",
        ":apkagi_toast_catch",
        "    move-exception v1",
        ":apkagi_toast_done",
        "    return-void",
        ".end method",
        "",
        ".method private static reapplyEnabledUnsafe(Landroid/content/Context;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_reapply_done",
        *reapply_lines,
        ":apkagi_reapply_done",
        "    return-void",
        ".end method",
        "",
        ".method public static reapplyEnabled(Landroid/content/Context;)V",
        "    .locals 1",
        "    :apkagi_reapply_try_start",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabledUnsafe(Landroid/content/Context;)V",
        "    :apkagi_reapply_try_end",
        "    goto :apkagi_reapply_wrapper_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_reapply_try_start .. :apkagi_reapply_try_end} :apkagi_reapply_catch",
        ":apkagi_reapply_catch",
        "    move-exception v0",
        "    invoke-static {p0}, Lapkagi/menu/MenuActions;->resetControls(Landroid/content/Context;)V",
        ":apkagi_reapply_wrapper_done",
        "    return-void",
        ".end method",
        "",
        ".method private static dispatchClickUnsafe(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 8",
        "    if-eqz p0, :apkagi_apply_done",
        "    if-eqz p1, :apkagi_apply_done",
        *click_lines,
        ":apkagi_apply_done",
        "    return-void",
        ".end method",
        "",
        ".method public static dispatchClick(Landroid/content/Context;Ljava/lang/String;)V",
        "    .locals 2",
        "    :apkagi_dispatch_click_try_start",
        "    invoke-static {p0, p1}, Lapkagi/menu/MenuActions;->dispatchClickUnsafe(Landroid/content/Context;Ljava/lang/String;)V",
        "    :apkagi_dispatch_click_try_end",
        "    goto :apkagi_dispatch_click_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_dispatch_click_try_start .. :apkagi_dispatch_click_try_end} :apkagi_dispatch_click_catch",
        ":apkagi_dispatch_click_catch",
        "    move-exception v0",
        "    const-string v1, \"Menu action failed\"",
        "    invoke-static {p0, v1}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
        ":apkagi_dispatch_click_done",
        "    return-void",
        ".end method",
        "",
        ".method private static dispatchToggleUnsafe(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    .locals 6",
        "    if-eqz p0, :apkagi_toggle_done",
        "    if-eqz p1, :apkagi_toggle_done",
        *toggle_lines,
        ":apkagi_toggle_done",
        "    return-void",
        ".end method",
        "",
        ".method public static dispatchToggle(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    .locals 2",
        "    :apkagi_dispatch_toggle_try_start",
        "    invoke-static {p0, p1, p2}, Lapkagi/menu/MenuActions;->dispatchToggleUnsafe(Landroid/content/Context;Ljava/lang/String;Z)V",
        "    :apkagi_dispatch_toggle_try_end",
        "    goto :apkagi_dispatch_toggle_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_dispatch_toggle_try_start .. :apkagi_dispatch_toggle_try_end} :apkagi_dispatch_toggle_catch",
        ":apkagi_dispatch_toggle_catch",
        "    move-exception v0",
        "    const-string v1, \"Menu toggle failed\"",
        "    invoke-static {p0, v1}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
        ":apkagi_dispatch_toggle_done",
        "    return-void",
        ".end method",
        "",
        ".method private static dispatchSliderUnsafe(Landroid/content/Context;Ljava/lang/String;I)V",
        "    .locals 6",
        "    if-eqz p0, :apkagi_slider_done",
        "    if-eqz p1, :apkagi_slider_done",
        *slider_lines,
        ":apkagi_slider_done",
        "    return-void",
        ".end method",
        "",
        ".method public static dispatchSlider(Landroid/content/Context;Ljava/lang/String;I)V",
        "    .locals 2",
        "    :apkagi_dispatch_slider_try_start",
        "    invoke-static {p0, p1, p2}, Lapkagi/menu/MenuActions;->dispatchSliderUnsafe(Landroid/content/Context;Ljava/lang/String;I)V",
        "    :apkagi_dispatch_slider_try_end",
        "    goto :apkagi_dispatch_slider_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_dispatch_slider_try_start .. :apkagi_dispatch_slider_try_end} :apkagi_dispatch_slider_catch",
        ":apkagi_dispatch_slider_catch",
        "    move-exception v0",
        "    const-string v1, \"Menu slider failed\"",
        "    invoke-static {p0, v1}, Lapkagi/menu/MenuActions;->toast(Landroid/content/Context;Ljava/lang/String;)V",
        ":apkagi_dispatch_slider_done",
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
        "    iput-object p1, p0, Lapkagi/menu/MenuActionClickListener;->appContext:Landroid/content/Context;",
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


def _generate_visibility_listener_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuVisibilityClickListener;",
        ".super Ljava/lang/Object;",
        ".implements Landroid/view/View$OnClickListener;",
        '.source "MenuVisibilityClickListener.java"',
        "",
        ".field private final appContext:Landroid/content/Context;",
        ".field private final launcherView:Landroid/view/View;",
        ".field private final panelView:Landroid/view/View;",
        ".field private final panelVisibility:I",
        "",
        ".method public constructor <init>(Landroid/content/Context;Landroid/view/View;Landroid/view/View;I)V",
        "    .locals 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    iput-object p1, p0, Lapkagi/menu/MenuVisibilityClickListener;->appContext:Landroid/content/Context;",
        "    iput-object p2, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelView:Landroid/view/View;",
        "    iput-object p3, p0, Lapkagi/menu/MenuVisibilityClickListener;->launcherView:Landroid/view/View;",
        "    iput p4, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelVisibility:I",
        "    return-void",
        ".end method",
        "",
        ".method public onClick(Landroid/view/View;)V",
        "    .locals 4",
        "    iget-object v0, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelView:Landroid/view/View;",
        "    iget v1, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelVisibility:I",
        "    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V",
        "    iget-object v0, p0, Lapkagi/menu/MenuVisibilityClickListener;->launcherView:Landroid/view/View;",
        "    if-eqz v0, :apkagi_visibility_store",
        "    iget v1, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelVisibility:I",
        "    if-nez v1, :apkagi_visibility_show_launcher",
        "    const/16 v1, 0x8",
        "    goto :apkagi_visibility_apply_launcher",
        ":apkagi_visibility_show_launcher",
        "    const/4 v1, 0x0",
        ":apkagi_visibility_apply_launcher",
        "    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V",
        ":apkagi_visibility_store",
        "    iget-object v0, p0, Lapkagi/menu/MenuVisibilityClickListener;->appContext:Landroid/content/Context;",
        "    iget v1, p0, Lapkagi/menu/MenuVisibilityClickListener;->panelVisibility:I",
        "    if-nez v1, :apkagi_visibility_closed",
        "    const/4 v1, 0x1",
        "    invoke-static {v0, v1}, Lapkagi/menu/MenuActions;->setMenuOpen(Landroid/content/Context;Z)V",
        "    return-void",
        ":apkagi_visibility_closed",
        "    const/4 v1, 0x0",
        "    invoke-static {v0, v1}, Lapkagi/menu/MenuActions;->setMenuOpen(Landroid/content/Context;Z)V",
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
        "    iput-object p1, p0, Lapkagi/menu/MenuToggleCheckedChangeListener;->appContext:Landroid/content/Context;",
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
        "    iput-object p1, p0, Lapkagi/menu/MenuSliderChangeListener;->appContext:Landroid/content/Context;",
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
        ".field private final appContext:Landroid/content/Context;",
        ".field private final targetView:Landroid/view/View;",
        ".field private startLeft:I",
        ".field private startRawX:F",
        ".field private startRawY:F",
        ".field private startTop:I",
        "",
        ".method public constructor <init>(Landroid/content/Context;Landroid/view/View;)V",
        "    .locals 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    iput-object p1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->appContext:Landroid/content/Context;",
        "    iput-object p2, p0, Lapkagi/menu/MenuPanelDragTouchListener;->targetView:Landroid/view/View;",
        "    return-void",
        ".end method",
        "",
        ".method public onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z",
        "    .locals 12",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getAction()I",
        "    move-result v0",
        "    if-nez v0, :apkagi_drag_check_move",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawX()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawX:F",
        "    invoke-virtual {p2}, Landroid/view/MotionEvent;->getRawY()F",
        "    move-result v1",
        "    iput v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->startRawY:F",
        "    iget-object v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->targetView:Landroid/view/View;",
        "    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;",
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
        "    iget-object v4, p0, Lapkagi/menu/MenuPanelDragTouchListener;->targetView:Landroid/view/View;",
        "    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;",
        "    move-result-object v4",
        "    instance-of v5, v4, Landroid/widget/FrameLayout$LayoutParams;",
        "    if-eqz v5, :apkagi_drag_return_true",
        "    check-cast v4, Landroid/widget/FrameLayout$LayoutParams;",
        "    iput v2, v4, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    iput v3, v4, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    iget-object v5, p0, Lapkagi/menu/MenuPanelDragTouchListener;->targetView:Landroid/view/View;",
        "    invoke-virtual {v5, v4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V",
        "    iget-object v5, p0, Lapkagi/menu/MenuPanelDragTouchListener;->appContext:Landroid/content/Context;",
        "    invoke-static {v5, v2, v3}, Lapkagi/menu/MenuActions;->rememberMenuPosition(Landroid/content/Context;II)V",
        ":apkagi_drag_return_true",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_drag_unhandled",
        "    const/4 v1, 0x1",
        "    if-ne v0, v1, :apkagi_drag_fallthrough",
        "    iget-object v1, p0, Lapkagi/menu/MenuPanelDragTouchListener;->targetView:Landroid/view/View;",
        "    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;",
        "    move-result-object v2",
        "    instance-of v3, v2, Landroid/widget/FrameLayout$LayoutParams;",
        "    if-eqz v3, :apkagi_drag_snap_done",
        "    check-cast v2, Landroid/widget/FrameLayout$LayoutParams;",
        "    iget-object v3, p0, Lapkagi/menu/MenuPanelDragTouchListener;->appContext:Landroid/content/Context;",
        "    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;",
        "    move-result-object v4",
        "    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;",
        "    move-result-object v4",
        "    iget v5, v4, Landroid/util/DisplayMetrics;->widthPixels:I",
        "    iget v6, v2, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    div-int/lit8 v7, v5, 0x2",
        "    const/16 v8, 0x10",
        "    if-le v6, v7, :apkagi_drag_snap_left",
        "    invoke-virtual {v1}, Landroid/view/View;->getWidth()I",
        "    move-result v9",
        "    sub-int/2addr v5, v9",
        "    sub-int/2addr v5, v8",
        "    iput v5, v2, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    goto :apkagi_drag_snap_apply",
        ":apkagi_drag_snap_left",
        "    iput v8, v2, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        ":apkagi_drag_snap_apply",
        "    invoke-virtual {v1, v2}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V",
        "    iget v5, v2, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    iget v6, v2, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    invoke-static {v3, v5, v6}, Lapkagi/menu/MenuActions;->rememberMenuPosition(Landroid/content/Context;II)V",
        ":apkagi_drag_snap_done",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_drag_fallthrough",
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
        "    const/4 v1, 0x1",
        "    if-ne v0, v1, :apkagi_overlay_drag_fallthrough",
        "    iget-object v1, p0, Lapkagi/menu/OverlayMenuDragTouchListener;->service:Lapkagi/menu/OverlayMenuService;",
        "    invoke-virtual {v1}, Lapkagi/menu/OverlayMenuService;->snapOverlayToEdge()V",
        "    const/4 v0, 0x1",
        "    return v0",
        ":apkagi_overlay_drag_fallthrough",
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


def _generate_attach_runnable_smali() -> str:
    return "\n".join([
        ".class public final Lapkagi/menu/MenuAttachRunnable;",
        ".super Ljava/lang/Object;",
        ".implements Ljava/lang/Runnable;",
        '.source "MenuAttachRunnable.java"',
        "",
        ".field private final activity:Landroid/app/Activity;",
        ".field private final attempt:I",
        "",
        ".method public constructor <init>(Landroid/app/Activity;I)V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    iput-object p1, p0, Lapkagi/menu/MenuAttachRunnable;->activity:Landroid/app/Activity;",
        "    iput p2, p0, Lapkagi/menu/MenuAttachRunnable;->attempt:I",
        "    return-void",
        ".end method",
        "",
        ".method public run()V",
        "    .locals 2",
        "    iget-object v0, p0, Lapkagi/menu/MenuAttachRunnable;->activity:Landroid/app/Activity;",
        "    iget v1, p0, Lapkagi/menu/MenuAttachRunnable;->attempt:I",
        "    invoke-static {v0, v1}, Lapkagi/menu/InAppMenuBridge;->attachAttempt(Landroid/app/Activity;I)V",
        "    return-void",
        ".end method",
        "",
    ]) + "\n"


def _generate_menu_compat_smali(spec: dict[str, Any]) -> str:
    strategy = str(spec.get("attach_root_strategy") or "auto")
    prefer_decor_first = strategy == "decor_first"

    if prefer_decor_first:
        resolve_lines = [
            "    if-eqz p0, :apkagi_compat_root_null",
            "    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;",
            "    move-result-object v0",
            "    if-eqz v0, :apkagi_compat_check_content_root",
            "    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;",
            "    move-result-object v1",
            "    if-eqz v1, :apkagi_compat_check_content_root",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_check_decor_content",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
            ":apkagi_compat_check_decor_content",
            "    const v2, 0x1020002",
            "    invoke-virtual {v1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;",
            "    move-result-object v1",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_check_content_root",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
            ":apkagi_compat_check_content_root",
            "    const v0, 0x1020002",
            "    invoke-virtual {p0, v0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;",
            "    move-result-object v1",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_root_view",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
            ":apkagi_compat_root_view",
            "    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;",
            "    move-result-object v0",
            "    if-eqz v0, :apkagi_compat_root_null",
            "    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;",
            "    move-result-object v1",
            "    if-eqz v1, :apkagi_compat_root_null",
            "    invoke-virtual {v1}, Landroid/view/View;->getRootView()Landroid/view/View;",
            "    move-result-object v1",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_root_null",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
        ]
    else:
        resolve_lines = [
            "    if-eqz p0, :apkagi_compat_root_null",
            "    const v0, 0x1020002",
            "    invoke-virtual {p0, v0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;",
            "    move-result-object v1",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_check_window_root",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
            ":apkagi_compat_check_window_root",
            "    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;",
            "    move-result-object v1",
            "    if-eqz v1, :apkagi_compat_root_view",
            "    invoke-virtual {v1}, Landroid/view/Window;->getDecorView()Landroid/view/View;",
            "    move-result-object v1",
            "    if-eqz v1, :apkagi_compat_root_view",
            "    invoke-virtual {v1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;",
            "    move-result-object v2",
            "    instance-of v0, v2, Landroid/view/ViewGroup;",
            "    if-eqz v0, :apkagi_compat_check_decor_group",
            "    check-cast v2, Landroid/view/ViewGroup;",
            "    return-object v2",
            ":apkagi_compat_check_decor_group",
            "    instance-of v0, v1, Landroid/view/ViewGroup;",
            "    if-eqz v0, :apkagi_compat_root_view",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
            ":apkagi_compat_root_view",
            "    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;",
            "    move-result-object v0",
            "    if-eqz v0, :apkagi_compat_root_null",
            "    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;",
            "    move-result-object v1",
            "    if-eqz v1, :apkagi_compat_root_null",
            "    invoke-virtual {v1}, Landroid/view/View;->getRootView()Landroid/view/View;",
            "    move-result-object v1",
            "    instance-of v2, v1, Landroid/view/ViewGroup;",
            "    if-eqz v2, :apkagi_compat_root_null",
            "    check-cast v1, Landroid/view/ViewGroup;",
            "    return-object v1",
        ]

    return "\n".join([
        ".class public final Lapkagi/menu/MenuCompat;",
        ".super Ljava/lang/Object;",
        '.source "MenuCompat.java"',
        "",
        ".method public constructor <init>()V",
        "    .locals 0",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        ".method public static resolveAttachRoot(Landroid/app/Activity;)Landroid/view/ViewGroup;",
        "    .locals 3",
        *resolve_lines,
        ":apkagi_compat_root_null",
        "    const/4 v0, 0x0",
        "    return-object v0",
        ".end method",
        "",
    ]) + "\n"


def _generate_widget_lines(spec: dict[str, Any], *, context_register: str, container_register: str) -> list[str]:
    widget_lines: list[str] = []
    current_section = ""
    for action in spec["buttons"]:
        section = str(action.get("section") or "").strip()
        if section and section != current_section:
            current_section = section
            widget_lines.extend([
                "    new-instance v3, Landroid/widget/TextView;",
                f"    invoke-direct {{v3, {context_register}}}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
                f'    const-string v4, "{_escape_smali_string(section)}"',
                "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
                "    const v4, 0x55ffffff",
                "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
                f"    invoke-virtual {{{container_register}, v3}}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
            ])

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
    auto_reapply_actions = bool(spec.get("auto_reapply_actions", False))
    restore_open_state = bool(spec.get("restore_open_state", False))
    delayed_attach_ms = max(0, min(int(spec.get("delayed_attach_ms", _DEFAULT_ATTACH_DELAY_MS) or 0), 5000))
    attach_retry_count = max(0, min(int(spec.get("attach_retry_count", _DEFAULT_ATTACH_RETRY_COUNT) or 0), 5))
    attach_retry_delay_ms = max(0, min(int(spec.get("attach_retry_delay_ms", _DEFAULT_ATTACH_RETRY_DELAY_MS) or 0), 3000))
    auto_start_overlay = bool(spec.get("auto_start_overlay", False))
    overlay_fallback_on_attach_failure = bool(spec.get("overlay_fallback_on_attach_failure", include_system_overlay and overlay_mode == "hybrid"))
    request_overlay_permission_on_fallback = bool(spec.get("request_overlay_permission_on_fallback", include_system_overlay))
    widget_lines = _generate_widget_lines(spec, context_register="p0", container_register="v12")
    default_open = "0x0" if bool(spec.get("start_collapsed")) else "0x1"

    install_lines: list[str] = [
        "    if-eqz p0, :apkagi_install_done",
    ]
    if auto_reapply_actions and not include_in_app:
        install_lines.append("    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabled(Landroid/content/Context;)V")
    if include_system_overlay and auto_start_overlay:
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
        "    .locals 1",
        "    :apkagi_install_try_start",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->installUnsafe(Landroid/content/Context;)V",
        "    :apkagi_install_try_end",
        "    goto :apkagi_install_wrapper_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_install_try_start .. :apkagi_install_try_end} :apkagi_install_catch",
        ":apkagi_install_catch",
        "    move-exception v0",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->rollbackInstall(Landroid/content/Context;)V",
        ":apkagi_install_wrapper_done",
        "    return-void",
        ".end method",
        "",
        ".method private static installUnsafe(Landroid/content/Context;)V",
        "    .locals 3",
        *install_lines,
        ":apkagi_install_done",
        "    return-void",
        ".end method",
        "",
        ".method private static rollbackInstall(Landroid/content/Context;)V",
        "    .locals 1",
        "    instance-of v0, p0, Landroid/app/Activity;",
        "    if-eqz v0, :apkagi_install_rollback_done",
        "    move-object v0, p0",
        "    check-cast v0, Landroid/app/Activity;",
        "    invoke-static {v0}, Lapkagi/menu/InAppMenuBridge;->rollbackAttach(Landroid/app/Activity;)V",
        ":apkagi_install_rollback_done",
        "    return-void",
        ".end method",
        "",
        ".method public static attach(Landroid/app/Activity;)V",
        "    .locals 1",
        "    :apkagi_attach_try_start",
        "    const/4 v0, 0x0",
        "    invoke-static {p0, v0}, Lapkagi/menu/InAppMenuBridge;->scheduleAttachUnsafe(Landroid/app/Activity;I)V",
        "    :apkagi_attach_try_end",
        "    goto :apkagi_attach_wrapper_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_attach_try_start .. :apkagi_attach_try_end} :apkagi_attach_catch",
        ":apkagi_attach_catch",
        "    move-exception v0",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->rollbackAttach(Landroid/app/Activity;)V",
        ":apkagi_attach_wrapper_done",
        "    return-void",
        ".end method",
        "",
        ".method private static scheduleAttachUnsafe(Landroid/app/Activity;I)V",
        "    .locals 4",
        "    if-eqz p0, :apkagi_schedule_attach_done",
        "    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;",
        "    move-result-object v0",
        "    if-eqz v0, :apkagi_schedule_attach_missing_root",
        "    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;",
        "    move-result-object v0",
        "    if-eqz v0, :apkagi_schedule_attach_missing_root",
        "    new-instance v1, Lapkagi/menu/MenuAttachRunnable;",
        "    invoke-direct {v1, p0, p1}, Lapkagi/menu/MenuAttachRunnable;-><init>(Landroid/app/Activity;I)V",
        "    if-eqz p1, :apkagi_schedule_attach_first_delay",
        f"    const-wide/16 v2, {hex(attach_retry_delay_ms)}",
        "    goto :apkagi_schedule_attach_delay_ready",
        ":apkagi_schedule_attach_first_delay",
        f"    const-wide/16 v2, {hex(delayed_attach_ms)}",
        ":apkagi_schedule_attach_delay_ready",
        "    invoke-virtual {v0, v1, v2, v3}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z",
        "    goto :apkagi_schedule_attach_done",
        ":apkagi_schedule_attach_missing_root",
        "    invoke-static {p0, p1}, Lapkagi/menu/InAppMenuBridge;->handleAttachMiss(Landroid/app/Activity;I)V",
        ":apkagi_schedule_attach_done",
        "    return-void",
        ".end method",
        "",
        ".method public static attachAttempt(Landroid/app/Activity;I)V",
        "    .locals 1",
        "    :apkagi_attach_attempt_try_start",
        "    invoke-static {p0, p1}, Lapkagi/menu/InAppMenuBridge;->attachAttemptUnsafe(Landroid/app/Activity;I)V",
        "    :apkagi_attach_attempt_try_end",
        "    goto :apkagi_attach_attempt_done",
        "    .catch Ljava/lang/Throwable; {:apkagi_attach_attempt_try_start .. :apkagi_attach_attempt_try_end} :apkagi_attach_attempt_catch",
        ":apkagi_attach_attempt_catch",
        "    move-exception v0",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->rollbackAttach(Landroid/app/Activity;)V",
        ":apkagi_attach_attempt_done",
        "    return-void",
        ".end method",
        "",
        ".method private static attachAttemptUnsafe(Landroid/app/Activity;I)V",
        "    .locals 1",
        "    if-eqz p0, :apkagi_attach_attempt_return",
        f"    invoke-static {{p0}}, {_COMPAT_DESCRIPTOR}->resolveAttachRoot(Landroid/app/Activity;)Landroid/view/ViewGroup;",
        "    move-result-object v0",
        "    if-nez v0, :apkagi_attach_attempt_now",
        "    invoke-static {p0, p1}, Lapkagi/menu/InAppMenuBridge;->handleAttachMiss(Landroid/app/Activity;I)V",
        "    return-void",
        ":apkagi_attach_attempt_now",
        "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->attachUnsafe(Landroid/app/Activity;)V",
        ":apkagi_attach_attempt_return",
        "    return-void",
        ".end method",
        "",
        ".method private static handleAttachMiss(Landroid/app/Activity;I)V",
        "    .locals 2",
        "    if-eqz p0, :apkagi_attach_miss_done",
        f"    const/16 v0, {hex(attach_retry_count)}",
        "    if-ge p1, v0, :apkagi_attach_miss_fallback",
        "    add-int/lit8 v0, p1, 0x1",
        "    invoke-static {p0, v0}, Lapkagi/menu/InAppMenuBridge;->scheduleAttachUnsafe(Landroid/app/Activity;I)V",
        "    return-void",
        ":apkagi_attach_miss_fallback",
        *([
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->ensureSystemOverlay(Landroid/content/Context;)V",
        ] if include_system_overlay and overlay_fallback_on_attach_failure and request_overlay_permission_on_fallback else [
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->hasOverlayPermission(Landroid/content/Context;)Z",
            "    move-result v0",
            "    if-eqz v0, :apkagi_attach_miss_done",
            "    invoke-static {p0}, Lapkagi/menu/InAppMenuBridge;->startOverlayService(Landroid/content/Context;)V",
        ] if include_system_overlay and overlay_fallback_on_attach_failure else []),
        ":apkagi_attach_miss_done",
        "    return-void",
        ".end method",
        "",
        ".method private static rollbackAttach(Landroid/app/Activity;)V",
        "    .locals 3",
        "    if-eqz p0, :apkagi_attach_rollback_done",
        f"    invoke-static {{p0}}, {_COMPAT_DESCRIPTOR}->resolveAttachRoot(Landroid/app/Activity;)Landroid/view/ViewGroup;",
        "    move-result-object v0",
        "    if-eqz v0, :apkagi_attach_rollback_done",
        '    const-string v1, "APKAGI_FLOATING_ROOT"',
        "    invoke-virtual {v0, v1}, Landroid/view/View;->findViewWithTag(Ljava/lang/Object;)Landroid/view/View;",
        "    move-result-object v2",
        "    if-eqz v2, :apkagi_attach_rollback_done",
        "    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V",
        ":apkagi_attach_rollback_done",
        "    return-void",
        ".end method",
        "",
        ".method private static attachUnsafe(Landroid/app/Activity;)V",
        "    .locals 15",
        "    if-eqz p0, :apkagi_attach_done",
        *([
            "    invoke-static {p0}, Lapkagi/menu/MenuActions;->reapplyEnabled(Landroid/content/Context;)V",
        ] if auto_reapply_actions else []),
        f"    invoke-static {{p0}}, {_COMPAT_DESCRIPTOR}->resolveAttachRoot(Landroid/app/Activity;)Landroid/view/ViewGroup;",
        "    move-result-object v0",
        "    if-eqz v0, :apkagi_attach_done",
        '    const-string v1, "APKAGI_FLOATING_ROOT"',
        "    invoke-virtual {v0, v1}, Landroid/view/View;->findViewWithTag(Ljava/lang/Object;)Landroid/view/View;",
        "    move-result-object v2",
        "    if-nez v2, :apkagi_attach_done",
        "    new-instance v2, Landroid/widget/FrameLayout;",
        "    invoke-direct {v2, p0}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V",
        "    invoke-virtual {v2, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    new-instance v3, Landroid/widget/TextView;",
        "    invoke-direct {v3, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        '    const-string v4, "APKAGI_FLOATING_ICON"',
        "    invoke-virtual {v3, v4}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        f'    const-string v4, "{_escape_smali_string(spec["launcher_label"])}"',
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    const/16 v4, 0x10",
        "    invoke-virtual {v3, v4, v4, v4, v4}, Landroid/view/View;->setPadding(IIII)V",
        "    const v5, 0xaa2255aa",
        "    invoke-virtual {v3, v5}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v12, Landroid/widget/LinearLayout;",
        "    invoke-direct {v12, p0}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        '    const-string v5, "APKAGI_MOD_MENU_PANEL"',
        "    invoke-virtual {v12, v5}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    const/4 v5, 0x1",
        "    invoke-virtual {v12, v5}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    invoke-virtual {v12, v4, v4, v4, v4}, Landroid/view/View;->setPadding(IIII)V",
        "    const v5, 0x66000000",
        "    invoke-virtual {v12, v5}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v7, Landroid/widget/LinearLayout;",
        "    invoke-direct {v7, p0}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        "    const/4 v5, 0x0",
        "    invoke-virtual {v7, v5}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    new-instance v8, Landroid/widget/TextView;",
        "    invoke-direct {v8, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        f'    const-string v4, "{_escape_smali_string(spec["title"])}"',
        "    invoke-virtual {v8, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v8, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    new-instance v9, Landroid/widget/TextView;",
        "    invoke-direct {v9, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        '    const-string v4, "x"',
        "    invoke-virtual {v9, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v9, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    const/16 v4, 0x8",
        "    invoke-virtual {v9, v4, v4, v4, v4}, Landroid/view/View;->setPadding(IIII)V",
        "    new-instance v10, Lapkagi/menu/MenuVisibilityClickListener;",
        "    const/16 v11, 0x8",
        "    invoke-direct {v10, p0, v12, v3, v11}, Lapkagi/menu/MenuVisibilityClickListener;-><init>(Landroid/content/Context;Landroid/view/View;Landroid/view/View;I)V",
        "    invoke-virtual {v9, v10}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
        "    new-instance v10, Lapkagi/menu/MenuVisibilityClickListener;",
        "    const/4 v11, 0x0",
        "    invoke-direct {v10, p0, v12, v3, v11}, Lapkagi/menu/MenuVisibilityClickListener;-><init>(Landroid/content/Context;Landroid/view/View;Landroid/view/View;I)V",
        "    invoke-virtual {v3, v10}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
        "    new-instance v10, Lapkagi/menu/MenuPanelDragTouchListener;",
        "    invoke-direct {v10, p0, v2}, Lapkagi/menu/MenuPanelDragTouchListener;-><init>(Landroid/content/Context;Landroid/view/View;)V",
        "    invoke-virtual {v3, v10}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v7, v10}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v7, v8}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v7, v9}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v12, v7}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        *widget_lines,
        *([
            f"    const/4 v10, {default_open}",
            "    invoke-static {p0, v10}, Lapkagi/menu/MenuActions;->isMenuOpen(Landroid/content/Context;Z)Z",
            "    move-result v10",
        ] if restore_open_state else [
            f"    const/4 v10, {default_open}",
        ]),
        "    if-eqz v10, :apkagi_attach_collapsed",
        "    const/16 v11, 0x8",
        "    invoke-virtual {v3, v11}, Landroid/view/View;->setVisibility(I)V",
        "    const/4 v11, 0x0",
        "    invoke-virtual {v12, v11}, Landroid/view/View;->setVisibility(I)V",
        "    goto :apkagi_attach_visibility_done",
        ":apkagi_attach_collapsed",
        "    const/4 v11, 0x0",
        "    invoke-virtual {v3, v11}, Landroid/view/View;->setVisibility(I)V",
        "    const/16 v11, 0x8",
        "    invoke-virtual {v12, v11}, Landroid/view/View;->setVisibility(I)V",
        ":apkagi_attach_visibility_done",
        "    invoke-virtual {v2, v3}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v2, v12}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;)V",
        "    new-instance v4, Landroid/widget/FrameLayout$LayoutParams;",
        "    const/4 v5, -0x2",
        "    invoke-direct {v4, v5, v5}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V",
        "    const v5, 0x800033",
        "    iput v5, v4, Landroid/widget/FrameLayout$LayoutParams;->gravity:I",
        "    const/16 v5, 0x18",
        "    invoke-static {p0, v5}, Lapkagi/menu/MenuActions;->getMenuLeft(Landroid/content/Context;I)I",
        "    move-result v6",
        "    iput v6, v4, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I",
        "    invoke-static {p0, v5}, Lapkagi/menu/MenuActions;->getMenuTop(Landroid/content/Context;I)I",
        "    move-result v6",
        "    iput v6, v4, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I",
        "    invoke-virtual {v0, v2, v4}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V",
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
    widget_lines = _generate_widget_lines(spec, context_register="p1", container_register="v10")
    default_open = "0x0" if bool(spec.get("start_collapsed")) else "0x1"
    restore_open_state = bool(spec.get("restore_open_state", False))

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
        "    invoke-static {p0, p1, p2}, Lapkagi/menu/MenuActions;->rememberMenuPosition(Landroid/content/Context;II)V",
        ":apkagi_overlay_update_done",
        "    return-void",
        ".end method",
        "",
        ".method public snapOverlayToEdge()V",
        "    .locals 8",
        "    iget-object v0, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    iget-object v1, p0, Lapkagi/menu/OverlayMenuService;->overlayRoot:Landroid/view/View;",
        "    if-eqz v0, :apkagi_overlay_snap_done",
        "    if-eqz v1, :apkagi_overlay_snap_done",
        "    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;",
        "    move-result-object v2",
        "    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;",
        "    move-result-object v2",
        "    iget v3, v2, Landroid/util/DisplayMetrics;->widthPixels:I",
        "    iget v4, v0, Landroid/view/WindowManager$LayoutParams;->x:I",
        "    div-int/lit8 v5, v3, 0x2",
        "    const/16 v6, 0x10",
        "    if-le v4, v5, :apkagi_overlay_snap_left",
        "    invoke-virtual {v1}, Landroid/view/View;->getWidth()I",
        "    move-result v7",
        "    sub-int/2addr v3, v7",
        "    sub-int/2addr v3, v6",
        "    goto :apkagi_overlay_snap_apply",
        ":apkagi_overlay_snap_left",
        "    move v3, v6",
        ":apkagi_overlay_snap_apply",
        "    iget v4, v0, Landroid/view/WindowManager$LayoutParams;->y:I",
        "    invoke-virtual {p0, v3, v4}, Lapkagi/menu/OverlayMenuService;->updateOverlayPosition(II)V",
        ":apkagi_overlay_snap_done",
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
        "    invoke-static {p0, v2}, Lapkagi/menu/MenuActions;->getMenuLeft(Landroid/content/Context;I)I",
        "    move-result v3",
        "    iput v3, v7, Landroid/view/WindowManager$LayoutParams;->x:I",
        "    invoke-static {p0, v2}, Lapkagi/menu/MenuActions;->getMenuTop(Landroid/content/Context;I)I",
        "    move-result v3",
        "    iput v3, v7, Landroid/view/WindowManager$LayoutParams;->y:I",
        "    iput-object v7, p0, Lapkagi/menu/OverlayMenuService;->overlayParams:Landroid/view/WindowManager$LayoutParams;",
        "    invoke-interface {v0, v1, v7}, Landroid/view/WindowManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V",
        ":apkagi_overlay_done",
        "    return-void",
        ".end method",
        "",
        ".method private buildOverlayView(Landroid/content/Context;)Landroid/view/View;",
        "    .locals 14",
        "    new-instance v2, Landroid/widget/FrameLayout;",
        "    invoke-direct {v2, p1}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V",
        '    const-string v0, "APKAGI_SYSTEM_OVERLAY_ROOT"',
        "    invoke-virtual {v2, v0}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    new-instance v3, Landroid/widget/TextView;",
        "    invoke-direct {v3, p1}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        '    const-string v0, "APKAGI_SYSTEM_OVERLAY_ICON"',
        "    invoke-virtual {v3, v0}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        f'    const-string v4, "{_escape_smali_string(spec["launcher_label"])}"',
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    const/16 v0, 0x10",
        "    invoke-virtual {v3, v0, v0, v0, v0}, Landroid/view/View;->setPadding(IIII)V",
        "    const v4, 0xaa2255aa",
        "    invoke-virtual {v3, v4}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v10, Landroid/widget/LinearLayout;",
        "    invoke-direct {v10, p1}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        '    const-string v4, "APKAGI_SYSTEM_OVERLAY_PANEL"',
        "    invoke-virtual {v10, v4}, Landroid/view/View;->setTag(Ljava/lang/Object;)V",
        "    const/4 v4, 0x1",
        "    invoke-virtual {v10, v4}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    invoke-virtual {v10, v0, v0, v0, v0}, Landroid/view/View;->setPadding(IIII)V",
        "    const v4, 0x66000000",
        "    invoke-virtual {v10, v4}, Landroid/view/View;->setBackgroundColor(I)V",
        "    new-instance v11, Landroid/widget/LinearLayout;",
        "    invoke-direct {v11, p1}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V",
        "    const/4 v4, 0x0",
        "    invoke-virtual {v11, v4}, Landroid/widget/LinearLayout;->setOrientation(I)V",
        "    new-instance v8, Landroid/widget/TextView;",
        "    invoke-direct {v8, p1}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        f'    const-string v4, "{_escape_smali_string(spec["title"])}"',
        "    invoke-virtual {v8, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v8, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    new-instance v9, Landroid/widget/TextView;",
        "    invoke-direct {v9, p1}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V",
        '    const-string v4, "x"',
        "    invoke-virtual {v9, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V",
        "    const/4 v4, -0x1",
        "    invoke-virtual {v9, v4}, Landroid/widget/TextView;->setTextColor(I)V",
        "    const/16 v4, 0x8",
        "    invoke-virtual {v9, v4, v4, v4, v4}, Landroid/view/View;->setPadding(IIII)V",
        "    new-instance v12, Lapkagi/menu/MenuVisibilityClickListener;",
        "    const/16 v13, 0x8",
        "    invoke-direct {v12, p1, v10, v3, v13}, Lapkagi/menu/MenuVisibilityClickListener;-><init>(Landroid/content/Context;Landroid/view/View;Landroid/view/View;I)V",
        "    invoke-virtual {v9, v12}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
        "    new-instance v12, Lapkagi/menu/MenuVisibilityClickListener;",
        "    const/4 v13, 0x0",
        "    invoke-direct {v12, p1, v10, v3, v13}, Lapkagi/menu/MenuVisibilityClickListener;-><init>(Landroid/content/Context;Landroid/view/View;Landroid/view/View;I)V",
        "    invoke-virtual {v3, v12}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V",
        "    new-instance v12, Lapkagi/menu/OverlayMenuDragTouchListener;",
        "    invoke-direct {v12, p0}, Lapkagi/menu/OverlayMenuDragTouchListener;-><init>(Lapkagi/menu/OverlayMenuService;)V",
        "    invoke-virtual {v3, v12}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v11, v12}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V",
        "    invoke-virtual {v11, v8}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v11, v9}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v10, v11}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V",
        *widget_lines,
        *([
            f"    const/4 v12, {default_open}",
            "    invoke-static {p1, v12}, Lapkagi/menu/MenuActions;->isMenuOpen(Landroid/content/Context;Z)Z",
            "    move-result v12",
        ] if restore_open_state else [
            f"    const/4 v12, {default_open}",
        ]),
        "    if-eqz v12, :apkagi_overlay_view_collapsed",
        "    const/16 v13, 0x8",
        "    invoke-virtual {v3, v13}, Landroid/view/View;->setVisibility(I)V",
        "    const/4 v13, 0x0",
        "    invoke-virtual {v10, v13}, Landroid/view/View;->setVisibility(I)V",
        "    goto :apkagi_overlay_view_visibility_done",
        ":apkagi_overlay_view_collapsed",
        "    const/4 v13, 0x0",
        "    invoke-virtual {v3, v13}, Landroid/view/View;->setVisibility(I)V",
        "    const/16 v13, 0x8",
        "    invoke-virtual {v10, v13}, Landroid/view/View;->setVisibility(I)V",
        ":apkagi_overlay_view_visibility_done",
        "    invoke-virtual {v2, v3}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;)V",
        "    invoke-virtual {v2, v10}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;)V",
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
    auto_configure_manifest: bool = True,
    require_foreground_service: bool = False,
    target_smali_root: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generate and inject a first-pass runtime mod-menu scaffold into an APK tree."""
    apktool_dir = Path(apktool_dir)
    backup_root = Path(backup_dir) if backup_dir else None
    normalized_spec = _normalize_menu_spec(spec, overlay_mode)
    requested_mode = normalized_spec["overlay_mode"]
    effective_mode = _effective_overlay_mode(requested_mode)
    effective_foreground_service = bool(require_foreground_service)
    requirements = _runtime_menu_requirements(
        requested_mode,
        require_foreground_service=effective_foreground_service,
    )
    has_toggle = "toggle" in normalized_spec["control_types"]
    has_slider = "slider" in normalized_spec["control_types"]
    hook_bindings = [binding for binding in normalized_spec.get("hook_bindings", []) if isinstance(binding, dict)]
    include_default_helpers = bool(normalized_spec.get("include_default_helpers", True))
    custom_helper_files = dict(normalized_spec.get("custom_helper_files") or {})
    requested_target_smali_root = normalize_smali_root_name(
        target_smali_root or normalized_spec.get("target_smali_root") or "auto"
    )

    helper_files: dict[str, str] = {}
    if include_default_helpers:
        helper_files = {
            "InAppMenuBridge.smali": _generate_bridge_smali(normalized_spec),
            "MenuCompat.smali": _generate_menu_compat_smali(normalized_spec),
            "MenuAttachRunnable.smali": _generate_attach_runnable_smali(),
            "MenuLifecycleCallbacks.smali": _generate_lifecycle_callbacks_smali(),
            "MenuActionClickListener.smali": _generate_click_listener_smali(),
            "MenuVisibilityClickListener.smali": _generate_visibility_listener_smali(),
            "MenuActions.smali": _generate_actions_smali(normalized_spec),
        }
        if hook_bindings:
            helper_files["RuntimeHookBindings.smali"] = _generate_runtime_hook_bindings_smali(hook_bindings)
        if requested_mode in {"in_app", "hybrid"}:
            helper_files["MenuPanelDragTouchListener.smali"] = _generate_panel_drag_listener_smali()
        if has_toggle:
            helper_files["MenuToggleCheckedChangeListener.smali"] = _generate_toggle_listener_smali()
        if has_slider:
            helper_files["MenuSliderChangeListener.smali"] = _generate_slider_listener_smali()
        if requested_mode in {"system_overlay", "hybrid"}:
            helper_files["OverlayMenuService.smali"] = _generate_overlay_service_smali(normalized_spec)
            helper_files["OverlayMenuDragTouchListener.smali"] = _generate_overlay_drag_listener_smali()
    helper_files.update(custom_helper_files)

    manifest_path = apktool_dir / "AndroidManifest.xml"
    entry = find_startup_entry(str(manifest_path), str(apktool_dir))
    startup_entry_root = ""
    if entry.get("success") and entry.get("smali_file"):
        startup_entry_root = _owning_smali_root_name(apktool_dir, Path(str(entry["smali_file"])))

    resolved_target_smali_root = requested_target_smali_root
    injection_plan: dict[str, Any] = {}
    if requested_target_smali_root == "auto":
        injection_plan = plan_dex_injection(
            apktool_dir,
            helper_files={f"apkagi/menu/{name}": content for name, content in helper_files.items()},
            purpose="runtime_scaffold",
        )
        resolved_target_smali_root = str(injection_plan.get("recommended_root") or "smali")
        if startup_entry_root:
            resolved_target_smali_root = startup_entry_root

    manifest_auto_configured = False
    manifest_followup_required = requested_mode in {"system_overlay", "hybrid"} and not auto_configure_manifest
    manifest_result: dict[str, Any] = {
        "success": True,
        "requested_overlay_mode": requested_mode,
        "effective_overlay_mode": effective_mode,
        "permissions_added": [],
        "components_added": [],
        "notes": [],
    }

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "requested_overlay_mode": requested_mode,
            "effective_overlay_mode": effective_mode,
            "requested_target_smali_root": requested_target_smali_root,
            "target_smali_root": resolved_target_smali_root,
            "menu_title": normalized_spec["title"],
            "launcher_label": normalized_spec["launcher_label"],
            "start_collapsed": normalized_spec["start_collapsed"],
            "auto_reapply_actions": normalized_spec["auto_reapply_actions"],
            "restore_open_state": normalized_spec["restore_open_state"],
            "menu_settings": normalized_spec["menu_settings"],
            "actions_generated": [button["id"] for button in normalized_spec["buttons"]],
            "control_types": normalized_spec["control_types"],
            "section_count": normalized_spec["section_count"],
            "hook_binding_count": len(hook_bindings),
            "helper_files": sorted(helper_files),
            "injection_plan": injection_plan,
            "tier_b_requirements": requirements,
            "manifest_auto_configure_default": requested_mode in {"system_overlay", "hybrid"},
            "manifest_followup_required": manifest_followup_required,
            "recommended_next_tool": "configure_runtime_menu_manifest" if manifest_followup_required else "generate_runtime_validation_plan",
            "recommended_next_args": {
                "overlay_mode": requested_mode,
                "add_overlay_permission": requested_mode in {"system_overlay", "hybrid"},
                "require_foreground_service": effective_foreground_service,
            } if manifest_followup_required else {"task": "runtime menu scaffold and controls"},
            "notes": [
                "Dry run only: no smali files or bootstrap hooks were written.",
                "The current implementation generates a floating launcher bubble, starts collapsed by default, and keeps runtime actions passive unless the spec explicitly enables auto-reapply or open-state restore.",
                "menu_settings provides one place to tune attach delay, attach retries, root-view resolution strategy, overlay fallback, and overlay-permission prompting.",
                "custom_helper_files can override generated helpers or replace the whole helper set when include_default_helpers=false.",
                "When target_smali_root is omitted, helper placement stays dex-aware but startup-bootstrapped helpers are co-located with the resolved startup entry root to avoid early launch class-loading crashes.",
                "Overlay-based modes expect manifest/service wiring as part of a successful deployment path.",
                "Foreground-service wiring stays optional; request it only when the deployment also adds a real notification/startForeground path.",
            ],
        }

    backed_up: dict[str, str] = {}
    touched_files: set[str] = set()
    validations: list[dict[str, Any]] = []
    errors: list[str] = []
    bootstrap_targets: list[dict[str, Any]] = []
    rolled_back_files: list[str] = []

    try:
        for relative_name, content in helper_files.items():
            helper_path = _helper_file_path(
                apktool_dir,
                relative_name,
                target_smali_root=resolved_target_smali_root,
            )
            helper_path.parent.mkdir(parents=True, exist_ok=True)
            _backup_file(helper_path, apktool_dir, backup_root, backed_up)
            helper_path.write_text(content, encoding="utf-8")
            touched_files.add(str(helper_path))

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

        if requested_mode in {"system_overlay", "hybrid"} and auto_configure_manifest and not errors:
            manifest_result = configure_runtime_menu_manifest(
                apktool_dir,
                overlay_mode=requested_mode,
                backup_dir=backup_root,
                add_overlay_permission=True,
                require_foreground_service=effective_foreground_service,
            )
            manifest_auto_configured = bool(manifest_result.get("success"))
            if manifest_result.get("success"):
                manifest_file = str(manifest_result.get("manifest_file") or "")
                if manifest_file:
                    touched_files.add(manifest_file)
            else:
                errors.append(f"Manifest configuration failed: {manifest_result.get('error', 'unknown error')}")
    except Exception as exc:
        errors.append(str(exc))

    if errors and touched_files:
        rolled_back_files = _rollback_runtime_menu_changes(touched_files, backed_up)

    return {
        "success": len(errors) == 0 and bool(touched_files),
        "requested_overlay_mode": requested_mode,
        "effective_overlay_mode": effective_mode,
        "requested_target_smali_root": requested_target_smali_root,
        "target_smali_root": resolved_target_smali_root,
        "menu_title": normalized_spec["title"],
        "launcher_label": normalized_spec["launcher_label"],
        "start_collapsed": normalized_spec["start_collapsed"],
        "auto_reapply_actions": normalized_spec["auto_reapply_actions"],
        "restore_open_state": normalized_spec["restore_open_state"],
        "menu_settings": normalized_spec["menu_settings"],
        "actions_generated": [button["id"] for button in normalized_spec["buttons"]],
        "user_buttons": normalized_spec["user_buttons"],
        "persistent_buttons": normalized_spec["persistent_buttons"],
        "control_types": normalized_spec["control_types"],
        "section_count": normalized_spec["section_count"],
        "hook_binding_count": len(hook_bindings),
        "tier_b_requirements": requirements,
        "manifest_auto_configured": manifest_auto_configured,
        "manifest_followup_required": manifest_followup_required,
        "manifest_config": manifest_result,
        "helper_classes": [
            _BRIDGE_DESCRIPTOR,
            _COMPAT_DESCRIPTOR,
            _ATTACH_RUNNABLE_DESCRIPTOR,
            _CLICK_DESCRIPTOR,
            _VISIBILITY_DESCRIPTOR,
            _ACTIONS_DESCRIPTOR,
            _LIFECYCLE_DESCRIPTOR,
            *([_HOOK_BINDINGS_DESCRIPTOR] if hook_bindings else []),
            *([_PANEL_DRAG_DESCRIPTOR] if requested_mode in {"in_app", "hybrid"} else []),
            *([_TOGGLE_DESCRIPTOR] if has_toggle else []),
            *([_SLIDER_DESCRIPTOR] if has_slider else []),
            *([_OVERLAY_SERVICE_DESCRIPTOR] if requested_mode in {"system_overlay", "hybrid"} else []),
            *([_OVERLAY_DRAG_DESCRIPTOR] if requested_mode in {"system_overlay", "hybrid"} else []),
        ],
        "bootstrap_targets": bootstrap_targets,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "rolled_back_files": rolled_back_files,
        "validation": validations,
        "recommended_next_tool": (
            "configure_runtime_menu_manifest"
            if manifest_followup_required
            else "generate_runtime_validation_plan"
        ),
        "recommended_next_args": (
            {
                "overlay_mode": requested_mode,
                "add_overlay_permission": requested_mode in {"system_overlay", "hybrid"},
                "require_foreground_service": effective_foreground_service,
            }
            if manifest_followup_required
            else {"task": "runtime menu scaffold and controls"}
        ),
        "notes": [
            "The runtime-menu scaffold now generates a real floating launcher bubble that opens/closes a draggable panel.",
            "Launcher visibility and floating position are remembered across later attaches/service restarts.",
            "Buttons can be grouped with section headers using the action-level section field.",
            "Persistent button/toggle/slider state is re-applied on later attaches/resumes until the generated reset button is pressed.",
            "menu_settings now unifies attach timing, retry behavior, root-view compatibility strategy, and overlay fallback/permission helpers.",
            "The generated helper package now includes MenuCompat and MenuAttachRunnable so the menu can retry delayed in-app attach before falling back to overlay permission/settings flows.",
            "kind=dispatcher binds controls directly to static runtime-hook methods without extra app-side glue.",
            "Helper classes can still be written into a secondary dex root when target_smali_root is set explicitly.",
            "When target_smali_root is omitted, startup-bootstrapped menu helpers are co-located with the startup entry dex root so launch-time bootstrap calls do not crash before multidex/class loading is ready.",
            "When system_overlay or hybrid is requested, the scaffold generates a real WindowManager overlay service and overlay-permission request flow.",
            "Overlay-based injections now auto-configure manifest permissions/services by default; disable that only when you intentionally want a separate manifest step.",
            "Foreground-service wiring remains optional and should only be requested when the deployment also adds a real notification/startForeground implementation.",
            "custom_helper_files may override generated menu helpers so the agent can inject fully authored smali menu implementations through this tool.",
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
        notes = ["No manifest permission changes were needed."]
        if any(permission.endswith("SYSTEM_ALERT_WINDOW") for permission in desired_permissions):
            notes.append("SYSTEM_ALERT_WINDOW still requires user approval at runtime on supported Android versions.")
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
            "notes": notes,
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