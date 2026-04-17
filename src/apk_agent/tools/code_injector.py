"""Code Injector — smali code injection and constructor override utilities.

Provides capabilities to:
1. Inject code at specific positions in smali methods
2. Override field values in ALL constructors of a class
3. Find and inject into app startup entry points (Application.onCreate)
"""

from __future__ import annotations

import re
from pathlib import Path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _method_name_matches(header_line: str, query: str) -> bool:
    """Check if *query* matches the method name in a .method line."""
    m = re.search(r'(\S+)\(', header_line)
    if not m:
        return False
    name_token = m.group(1)
    if '(' in query:
        sig_part = header_line[header_line.index(name_token):]
        return query in sig_part
    return name_token == query


def _count_param_slots(method_header: str) -> int:
    """Count parameter register slots from a method signature."""
    m = re.search(r'\((.*?)\)', method_header)
    if not m:
        return 0
    params = m.group(1)
    count = 0
    i = 0
    while i < len(params):
        c = params[i]
        if c in 'ZBCSIF':
            count += 1
            i += 1
        elif c in 'JD':
            count += 2
            i += 1
        elif c == 'L':
            count += 1
            i = params.index(';', i) + 1
        elif c == '[':
            i += 1
        else:
            i += 1
    if 'static' not in method_header.lower().split('(')[0]:
        count += 1
    return count


def _highest_v_register(code: str) -> int:
    """Return the highest vN register index referenced in code, or -1."""
    regs = re.findall(r'\bv(\d+)\b', code)
    return max((int(r) for r in regs), default=-1)


def _find_method(lines: list[str], method_name: str) -> tuple[int, int, str]:
    """Return (start, end, header) for the first matching method, or (-1,-1,'')."""
    start = -1
    header = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(".method") and _method_name_matches(s, method_name):
            start = i
            header = s
        if start >= 0 and s == ".end method":
            return start, i, header
    return -1, -1, ""


def _find_all_methods(lines: list[str], method_name: str) -> list[tuple[int, int, str]]:
    """Return all (start, end, header) tuples for matching methods."""
    results = []
    start = -1
    header = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(".method") and _method_name_matches(s, method_name):
            start = i
            header = s
        if start >= 0 and s == ".end method":
            results.append((start, i, header))
            start = -1
    return results


def _ensure_registers(lines: list[str], method_start: int, method_end: int,
                      method_header: str, needed_extra: int) -> tuple[int, str]:
    """Bump .locals (or .registers) by *needed_extra* and return (first_new_v, directive_used).

    Returns the v-register number of the first newly-added register.
    """
    for i in range(method_start, min(method_start + 20, method_end)):
        m_loc = re.match(r'(\s*)\.locals\s+(\d+)', lines[i])
        if m_loc:
            old = int(m_loc.group(2))
            lines[i] = f"{m_loc.group(1)}.locals {old + needed_extra}"
            return old, "locals"
        m_reg = re.match(r'(\s*)\.registers\s+(\d+)', lines[i])
        if m_reg:
            old = int(m_reg.group(2))
            param_slots = _count_param_slots(method_header)
            local_count = old - param_slots
            lines[i] = f"{m_reg.group(1)}.registers {old + needed_extra}"
            return local_count, "registers"
    return 0, "none"


# ---------------------------------------------------------------------------
# 1. inject_code_in_method
# ---------------------------------------------------------------------------

def inject_code_in_method(
    file_path: str | Path,
    method_name: str,
    smali_code: str,
    position: str = "start",
) -> dict:
    """Inject smali instructions into a method.

    *position*: ``"start"`` | ``"end"`` | ``"after_super"`` | ``"before_return"``
    """
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    start, end, header = _find_method(lines, method_name)
    if start < 0:
        return {"success": False,
                "error": f"Method '{method_name}' not found in {path.name}"}

    # --- determine register needs ----------------------------------------
    max_v = _highest_v_register(smali_code)
    if max_v >= 0:
        # Find current locals count
        cur_locals = 0
        for i in range(start, min(start + 20, end)):
            m = re.match(r'\s*\.locals\s+(\d+)', lines[i])
            if m:
                cur_locals = int(m.group(1))
                break
            m = re.match(r'\s*\.registers\s+(\d+)', lines[i])
            if m:
                param_slots = _count_param_slots(header)
                cur_locals = int(m.group(1)) - param_slots
                break
        needed = max_v + 1
        if needed > cur_locals:
            _ensure_registers(lines, start, end, header, needed - cur_locals)

    # --- build injection lines -------------------------------------------
    inject_lines = ["    # === APK-AGI INJECTED CODE ==="]
    for raw in smali_code.strip().splitlines():
        inject_lines.append(f"    {raw.strip()}" if raw.strip() else "")
    inject_lines.append("    # === END INJECTED CODE ===")

    # --- locate insertion point ------------------------------------------
    # Recalculate end after possible register bump
    for i in range(start, len(lines)):
        if lines[i].strip() == ".end method":
            end = i
            break

    insert_at = -1

    if position == "start":
        # After .locals/.prologue/.param directives
        for i in range(start + 1, end):
            s = lines[i].strip()
            if s.startswith(('.locals', '.registers', '.param', '.annotation',
                             '.end annotation', '.prologue', '.line')):
                continue
            if not s or s.startswith('#'):
                continue
            insert_at = i
            break
        if insert_at < 0:
            insert_at = end

    elif position == "after_super":
        # After the first invoke-direct {p0}, ...;-><init>
        for i in range(start + 1, end):
            s = lines[i].strip()
            if 'invoke-direct' in s and '-><init>' in s and 'p0' in s:
                # Skip to the next real instruction (might be .line directives)
                insert_at = i + 1
                break
        if insert_at < 0:
            # Fallback: before last return
            for i in range(end - 1, start, -1):
                if lines[i].strip().startswith('return'):
                    insert_at = i
                    break

    elif position in ("end", "before_return"):
        # Before the LAST return instruction
        for i in range(end - 1, start, -1):
            if lines[i].strip().startswith(('return', 'return-void',
                                             'return-object', 'return-wide')):
                insert_at = i
                break

    if insert_at < 0:
        return {"success": False,
                "error": f"Could not find insertion point for position '{position}'"}

    # --- insert ----------------------------------------------------------
    for j, il in enumerate(inject_lines):
        lines.insert(insert_at + j, il)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "success": True,
        "file": str(path),
        "method": header,
        "position": position,
        "injected_at_line": insert_at + 1,
        "lines_injected": len(inject_lines),
    }


# ---------------------------------------------------------------------------
# 2. override_constructor_fields
# ---------------------------------------------------------------------------

def _smali_value_instructions(scratch: str, field_name: str,
                               class_desc: str, ftype: str, value) -> list[str]:
    """Generate smali lines to set one field to *value* using *scratch* register."""
    out: list[str] = []
    if ftype == "Ljava/lang/String;":
        out.append(f'const-string {scratch}, "{value}"')
        out.append(f'iput-object {scratch}, p0, {class_desc}->{field_name}:{ftype}')
    elif ftype == "Z":
        val = "0x1" if value else "0x0"
        out.append(f'const/4 {scratch}, {val}')
        out.append(f'iput-boolean {scratch}, p0, {class_desc}->{field_name}:{ftype}')
    elif ftype == "I":
        v = int(value)
        if -8 <= v <= 7:
            out.append(f'const/4 {scratch}, {hex(v)}')
        elif -32768 <= v <= 32767:
            out.append(f'const/16 {scratch}, {hex(v)}')
        else:
            out.append(f'const {scratch}, {hex(v)}')
        out.append(f'iput {scratch}, p0, {class_desc}->{field_name}:{ftype}')
    elif ftype == "J":
        v = int(value)
        out.append(f'const-wide {scratch}, {hex(v)}')
        out.append(f'iput-wide {scratch}, p0, {class_desc}->{field_name}:{ftype}')
    elif ftype.startswith("L") or ftype.startswith("["):
        out.append(f'const/4 {scratch}, 0x0')
        out.append(f'iput-object {scratch}, p0, {class_desc}->{field_name}:{ftype}')
    return out


def override_constructor_fields(
    file_path: str | Path,
    class_descriptor: str,
    field_overrides: dict,
) -> dict:
    """Patch ALL constructors to force-set field values before ``return-void``.

    *field_overrides*: ``{"field": {"type": "Ljava/lang/String;", "value": "SVIP"}, ...}``
    """
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # collect all <init> methods
    constructors = _find_all_methods(lines, "<init>")
    if not constructors:
        return {"success": False, "error": "No constructors found in file"}

    has_wide = any(fi.get("type") in ("J", "D") for fi in field_overrides.values())
    extra_regs = 2 if has_wide else 1

    patched = 0
    details = []

    # process in reverse so line numbers stay valid
    for m_start, m_end, m_header in reversed(constructors):
        # find last return-void
        return_line = -1
        for i in range(m_end - 1, m_start, -1):
            if lines[i].strip() == "return-void":
                return_line = i
                break
        if return_line < 0:
            details.append({"constructor": m_header, "status": "skipped (no return-void)"})
            continue

        scratch_v, _ = _ensure_registers(lines, m_start, m_end, m_header, extra_regs)
        scratch = f"v{scratch_v}"

        # re-find return-void (may have shifted by 0 since we only changed .locals line)
        for i in range(m_end, m_start, -1):
            if i < len(lines) and lines[i].strip() == "return-void":
                return_line = i
                break

        override_lines = ["    # === APK-AGI: FIELD VALUE OVERRIDES ==="]
        for fname, finfo in field_overrides.items():
            for inst in _smali_value_instructions(scratch, fname,
                                                   class_descriptor,
                                                   finfo["type"], finfo["value"]):
                override_lines.append(f"    {inst}")
        override_lines.append("    # === END FIELD OVERRIDES ===")

        for j, ol in enumerate(override_lines):
            lines.insert(return_line + j, ol)

        patched += 1
        details.append({
            "constructor": m_header,
            "status": "patched",
            "scratch_register": scratch,
            "injected_before_line": return_line + 1,
        })

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "success": True,
        "file": str(path),
        "constructors_found": len(constructors),
        "constructors_patched": patched,
        "fields_overridden": list(field_overrides.keys()),
        "details": details,
    }


# ---------------------------------------------------------------------------
# 3. find_startup_entry  (returns info, does NOT inject)
# ---------------------------------------------------------------------------

def find_startup_entry(manifest_path: str | Path,
                       apktool_dir: str | Path) -> dict:
    """Find the Application class (or main Activity) and its onCreate method.

    Returns a dict with class name, smali file path, whether onCreate exists,
    and the line range.
    """
    import xml.etree.ElementTree as ET

    manifest = Path(manifest_path)
    apk_dir = Path(apktool_dir)
    if not manifest.is_file():
        return {"success": False, "error": "AndroidManifest.xml not found"}

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    tree = ET.parse(str(manifest))  # noqa: S314
    root = tree.getroot()

    # 1. Check for Application class
    app_elem = root.find("application")
    app_class = ""
    if app_elem is not None:
        app_class = app_elem.get(f"{{{ns['android']}}}name", "")

    if app_class:
        smali_rel = app_class.replace(".", "/") + ".smali"
        smali_path = _find_smali_file(apk_dir, smali_rel)
        if smali_path:
            on_create = _check_method_exists(smali_path, "onCreate")
            return {
                "success": True,
                "entry_type": "Application",
                "class_name": app_class,
                "smali_file": str(smali_path),
                "has_onCreate": on_create,
            }

    # 2. Fallback: find launcher Activity
    for activity in root.iter("activity"):
        for intent in activity.iter("intent-filter"):
            action = intent.find("action")
            category = intent.find("category")
            if action is not None and category is not None:
                a_name = action.get(f"{{{ns['android']}}}name", "")
                c_name = category.get(f"{{{ns['android']}}}name", "")
                if ("MAIN" in a_name and "LAUNCHER" in c_name):
                    act_class = activity.get(f"{{{ns['android']}}}name", "")
                    if act_class:
                        smali_rel = act_class.replace(".", "/") + ".smali"
                        smali_path = _find_smali_file(apk_dir, smali_rel)
                        if smali_path:
                            on_create = _check_method_exists(smali_path, "onCreate")
                            return {
                                "success": True,
                                "entry_type": "LauncherActivity",
                                "class_name": act_class,
                                "smali_file": str(smali_path),
                                "has_onCreate": on_create,
                            }

    return {"success": False, "error": "No Application or launcher Activity found"}


def _find_smali_file(apk_dir: Path, rel_path: str) -> Path | None:
    """Search all smali directories for a class file."""
    for child in sorted(apk_dir.iterdir()):
        if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_classes")):
            candidate = child / rel_path
            if candidate.is_file():
                return candidate
    return None


def _check_method_exists(smali_path: Path, method_name: str) -> bool:
    """Check if a method exists in a smali file."""
    text = smali_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(".method") and _method_name_matches(s, method_name):
            return True
    return False
