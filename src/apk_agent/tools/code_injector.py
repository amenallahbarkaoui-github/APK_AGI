"""Code Injector — smali code injection and constructor override utilities.

Provides capabilities to:
1. Inject code at specific positions in smali methods
2. Override field values in ALL constructors of a class
3. Find and inject into app startup entry points (Application.onCreate)
"""

from __future__ import annotations

import re
from pathlib import Path

from apk_agent.tools.smali_ir import SmaliMethod, parse_smali_file


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


def _method_query_matches_ir(method: SmaliMethod, query: str) -> bool:
    """Return True when a SmaliMethod matches a name-or-signature query."""
    query = str(query or "").strip()
    if not query:
        return False
    if "(" in query:
        return method.signature == query or method.full_signature.endswith(f"->{query}")
    return method.name == query


def _load_method_ir(file_path: Path, method_name: str) -> SmaliMethod | None:
    """Best-effort parse of the target file and method into Smali IR."""
    parsed = parse_smali_file(file_path, file_path.parent)
    if parsed is None:
        return None
    for method in parsed.methods:
        if _method_query_matches_ir(method, method_name):
            return method
    return None


def _default_method_insert_at(lines: list[str], method_start: int, method_end: int) -> int:
    """Return the default insertion line near the start of a method body."""
    for i in range(method_start + 1, method_end):
        s = lines[i].strip()
        if s.startswith((
            ".locals",
            ".registers",
            ".param",
            ".annotation",
            ".end annotation",
            ".prologue",
            ".line",
        )):
            continue
        if not s or s.startswith("#"):
            continue
        return i
    return method_end


def _advance_past_inline_metadata(lines: list[str], insert_at: int, method_end: int) -> int:
    """Skip metadata lines immediately after an anchor instruction.

    Labels are intentionally not skipped so they continue to bind the original
    following instruction rather than the injected code.
    """
    while insert_at < method_end:
        s = lines[insert_at].strip()
        if s.startswith((".line", ".local", ".restart local", ".end local", ".prologue")):
            insert_at += 1
            continue
        if not s or s.startswith("#"):
            insert_at += 1
            continue
        break
    return insert_at


def _after_super_insert_at(lines: list[str], method: SmaliMethod, method_start: int, method_end: int) -> int:
    """Return the insertion point immediately after the method's super/init call."""
    if method.name == "<init>":
        for instr in method.instructions:
            if not instr.is_invoke:
                continue
            if instr.target_method != "<init>" or "p0" not in instr.registers:
                continue
            if not instr.opcode.startswith(("invoke-direct", "invoke-super")):
                continue
            return _advance_past_inline_metadata(lines, instr.line, method_end)

    for instr in method.instructions:
        if not instr.is_invoke:
            continue
        if "p0" not in instr.registers:
            continue
        if not instr.opcode.startswith("invoke-super"):
            continue
        if instr.target_method == method.name:
            return _advance_past_inline_metadata(lines, instr.line, method_end)

    for instr in method.instructions:
        if instr.is_invoke and "p0" in instr.registers and instr.opcode.startswith("invoke-super"):
            return _advance_past_inline_metadata(lines, instr.line, method_end)

    return _default_method_insert_at(lines, method_start, method_end)


def _return_insert_points(method: SmaliMethod) -> list[int]:
    """Return zero-based source line indexes for each return in a method."""
    return [instr.line - 1 for instr in method.instructions if instr.is_return]


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
    method_ir = _load_method_ir(path, method_name)
    if start < 0:
        return {"success": False,
                "error": f"Method '{method_name}' not found in {path.name}"}

    # --- determine register needs ----------------------------------------
    max_v = _highest_v_register(smali_code)

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

    if max_v >= 0:
        needed = max_v + 1
        if needed > cur_locals:
            _ensure_registers(lines, start, end, header, needed - cur_locals)
            cur_locals = needed

    # --- 4-bit register safety check for p0 in iput/iget instructions ---
    # Dalvik iput/iget use 4-bit register encoding: both value and object
    # registers must be v0-v15.  p0 maps to v{cur_locals}, so if
    # cur_locals >= 16, any iput/iget using p0 will fail.
    p0_as_v = cur_locals
    p0_needs_alias = p0_as_v > 15

    # Check if injected code uses p0 in 4-bit instructions
    iput_iget_p0 = bool(re.search(
        r'\b(iput|iget|iput-object|iget-object|iput-boolean|iget-boolean|'
        r'iput-wide|iget-wide|iput-short|iget-short|iput-byte|iget-byte|'
        r'iput-char|iget-char)\b.*\bp0\b', smali_code
    ))

    if p0_needs_alias and iput_iget_p0:
        # Auto-fix: rewrite p0 in iput/iget to a low alias register
        # Pick a safe alias register (use v0 or next available)
        alias_v = max(max_v + 1 if max_v >= 0 else 0, 0)
        if alias_v > 14:
            alias_v = 0  # fall back to v0 — safe to reuse before return
        alias_reg = f"v{alias_v}"

        # Ensure we have enough locals for the alias
        if alias_v >= cur_locals:
            _ensure_registers(lines, start, end, header, alias_v + 1 - cur_locals)
            # Re-find end
            for i in range(start, len(lines)):
                if lines[i].strip() == ".end method":
                    end = i
                    break

        # Rewrite p0 in iput/iget instructions to alias_reg, and prepend
        # move-object/from16 alias_reg, p0
        new_lines = []
        for raw_line in smali_code.strip().splitlines():
            s = raw_line.strip()
            if re.match(r'(iput|iget)', s) and 'p0' in s:
                # Replace p0 with alias in this instruction
                # p0 is the second register in iput (iput vA, p0, field)
                # or the first register in iget (iget vA, p0, field)
                new_lines.append(re.sub(r'\bp0\b', alias_reg, s))
            else:
                new_lines.append(s)

        # Prepend the alias instruction
        smali_code = f"move-object/from16 {alias_reg}, p0\n" + "\n".join(new_lines)

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

    insert_points: list[int] = []

    if position == "start":
        insert_points = [_default_method_insert_at(lines, start, end)]

    elif position == "after_super":
        if method_ir is not None:
            insert_points = [_after_super_insert_at(lines, method_ir, start, end)]
        else:
            insert_points = [_default_method_insert_at(lines, start, end)]

    elif position == "before_return":
        if method_ir is not None:
            insert_points = _return_insert_points(method_ir)
        else:
            for i in range(end - 1, start, -1):
                if lines[i].strip().startswith(("return", "return-void", "return-object", "return-wide")):
                    insert_points.append(i)
            insert_points.reverse()

    elif position == "end":
        if method_ir is not None:
            returns = _return_insert_points(method_ir)
            insert_points = [returns[-1]] if returns else [end]
        else:
            for i in range(end - 1, start, -1):
                if lines[i].strip().startswith(("return", "return-void", "return-object", "return-wide")):
                    insert_points = [i]
                    break
            if not insert_points:
                insert_points = [end]

    if not insert_points:
        return {"success": False,
                "error": f"Could not find insertion point for position '{position}'"}

    # --- insert ----------------------------------------------------------
    applied_lines: list[int] = []
    for insert_at in sorted(set(insert_points), reverse=True):
        applied_lines.append(insert_at + 1)
        for j, il in enumerate(inject_lines):
            lines.insert(insert_at + j, il)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    applied_lines.reverse()

    return {
        "success": True,
        "file": str(path),
        "method": header,
        "position": position,
        "injected_at_line": applied_lines[0],
        "injected_at_lines": applied_lines,
        "lines_injected": len(inject_lines) * len(applied_lines),
    }


# ---------------------------------------------------------------------------
# 2. override_constructor_fields
# ---------------------------------------------------------------------------

def _smali_value_instructions(scratch: str, obj_reg: str, field_name: str,
                               class_desc: str, ftype: str, value) -> list[str]:
    """Generate smali lines to set one field to *value* using *scratch* register.

    *obj_reg* is the register holding ``this`` — usually ``p0`` but may be a
    low v-register alias when p0 > v15.
    """
    out: list[str] = []
    if ftype == "Ljava/lang/String;":
        out.append(f'const-string {scratch}, "{value}"')
        out.append(f'iput-object {scratch}, {obj_reg}, {class_desc}->{field_name}:{ftype}')
    elif ftype == "Z":
        val = "0x1" if value else "0x0"
        out.append(f'const/4 {scratch}, {val}')
        out.append(f'iput-boolean {scratch}, {obj_reg}, {class_desc}->{field_name}:{ftype}')
    elif ftype == "I":
        v = int(value)
        if -8 <= v <= 7:
            out.append(f'const/4 {scratch}, {hex(v)}')
        elif -32768 <= v <= 32767:
            out.append(f'const/16 {scratch}, {hex(v)}')
        else:
            out.append(f'const {scratch}, {hex(v)}')
        out.append(f'iput {scratch}, {obj_reg}, {class_desc}->{field_name}:{ftype}')
    elif ftype == "J":
        v = int(value)
        out.append(f'const-wide {scratch}, {hex(v)}')
        out.append(f'iput-wide {scratch}, {obj_reg}, {class_desc}->{field_name}:{ftype}')
    elif ftype.startswith("L") or ftype.startswith("["):
        out.append(f'const/4 {scratch}, 0x0')
        out.append(f'iput-object {scratch}, {obj_reg}, {class_desc}->{field_name}:{ftype}')
    return out


def _is_synthetic_delegating(lines: list[str], m_start: int, m_end: int,
                              class_desc: str) -> bool:
    """Return True if this constructor is a synthetic that delegates to another
    <init> of the same class via invoke-direct/range.  Such constructors should
    NOT get field overrides because the target constructor already has them.
    """
    is_synthetic = "synthetic" in lines[m_start]
    if not is_synthetic:
        return False
    # Look for invoke-direct/range {pX .. pY}, Lclass;-><init>(...)V
    escaped = re.escape(class_desc)
    for i in range(m_start + 1, m_end):
        s = lines[i].strip()
        if re.search(rf'invoke-direct/range\s+\{{.*\}},\s*{escaped}-><init>', s):
            return True
        if re.search(rf'invoke-direct\s+\{{.*\}},\s*{escaped}-><init>', s):
            return True
    return False


def override_constructor_fields(
    file_path: str | Path,
    class_descriptor: str,
    field_overrides: dict,
) -> dict:
    """Patch ALL constructors to force-set field values before ``return-void``.

    Handles the Dalvik 4-bit register constraint: iput/iget instructions require
    BOTH the value register AND the object register (``this``) to be v0-v15.
    When ``.locals`` is large (≥16), ``p0`` maps to ``v16+`` which would cause
    "Invalid register" build errors.  The fix:
    - Always use low scratch registers (v0-v1) that are safe to reuse at method end
    - When p0 > v15, emit ``move-object/from16 vN, p0`` to alias ``this`` into a
      low register before the iput instructions.
    - Skip synthetic constructors that delegate to the primary (they'd get the
      overrides via the primary constructor).

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
    patched = 0
    skipped_synthetic = 0
    details = []

    # process in reverse so line numbers stay valid
    for m_start, m_end, m_header in reversed(constructors):
        # --- Skip synthetic delegating constructors ---
        if _is_synthetic_delegating(lines, m_start, m_end, class_descriptor):
            skipped_synthetic += 1
            details.append({
                "constructor": m_header[:120],
                "status": "skipped (synthetic — primary constructor handles overrides)",
            })
            continue

        # find last return-void
        return_line = -1
        for i in range(m_end - 1, m_start, -1):
            if lines[i].strip() == "return-void":
                return_line = i
                break
        if return_line < 0:
            details.append({"constructor": m_header[:120], "status": "skipped (no return-void)"})
            continue

        # --- Determine current .locals count ---
        cur_locals = 0
        for i in range(m_start, min(m_start + 20, m_end)):
            m_loc = re.match(r'\s*\.locals\s+(\d+)', lines[i])
            if m_loc:
                cur_locals = int(m_loc.group(1))
                break
            m_reg = re.match(r'\s*\.registers\s+(\d+)', lines[i])
            if m_reg:
                param_slots = _count_param_slots(m_header)
                cur_locals = int(m_reg.group(1)) - param_slots
                break

        # p0 maps to v{cur_locals} (for instance methods)
        p0_as_v = cur_locals

        # --- Pick safe registers (must be v0-v15 for 4-bit instructions) ---
        # We reuse v0 and optionally v1 at the END of the method (before return-void)
        # which is safe — the original code is done executing at that point.
        # For wide values we need two consecutive registers: v0+v1.
        scratch = "v0"
        # If we need a separate obj_reg (when p0 > v15), use v1 for it
        # and v2/v3 for wide scratch. Keep everything ≤ v15.
        if p0_as_v > 15:
            obj_reg = "v1"
            scratch = "v2" if not has_wide else "v2"
            # Ensure we have enough locals (at least 4: v0, v1 for obj, v2+v3 for wide)
            needed_locals = 4 if has_wide else 3
        else:
            obj_reg = "p0"
            needed_locals = 2 if has_wide else 1

        # Bump .locals if needed (only up, never down)
        if cur_locals < needed_locals:
            _ensure_registers(lines, m_start, m_end, m_header, needed_locals - cur_locals)
            # Re-find return-void after potential line shift
            for i in range(m_end + 5, m_start, -1):
                if i < len(lines) and lines[i].strip() == "return-void":
                    return_line = i
                    break

        # --- Build override instructions ---
        override_lines = ["    # === APK-AGI: FIELD VALUE OVERRIDES ==="]

        # If p0 > v15, alias this into a low register
        if p0_as_v > 15:
            override_lines.append(f"    move-object/from16 {obj_reg}, p0")

        for fname, finfo in field_overrides.items():
            for inst in _smali_value_instructions(scratch, obj_reg, fname,
                                                   class_descriptor,
                                                   finfo["type"], finfo["value"]):
                override_lines.append(f"    {inst}")
        override_lines.append("    # === END FIELD OVERRIDES ===")

        for j, ol in enumerate(override_lines):
            lines.insert(return_line + j, ol)

        patched += 1
        details.append({
            "constructor": m_header[:120],
            "status": "patched",
            "scratch_register": scratch,
            "obj_register": obj_reg,
            "p0_maps_to": f"v{p0_as_v}",
            "injected_before_line": return_line + 1,
        })

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "success": True,
        "file": str(path),
        "constructors_found": len(constructors),
        "constructors_patched": patched,
        "constructors_skipped_synthetic": skipped_synthetic,
        "fields_overridden": list(field_overrides.keys()),
        "details": details,
    }

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

    launcher_entry = find_launcher_activity_entry(manifest_path, apktool_dir)
    if launcher_entry.get("success"):
        return launcher_entry

    return {"success": False, "error": "No Application or launcher Activity found"}


def find_launcher_activity_entry(manifest_path: str | Path,
                                 apktool_dir: str | Path) -> dict:
    """Find the launcher Activity and report whether it defines onCreate."""
    import xml.etree.ElementTree as ET

    manifest = Path(manifest_path)
    apk_dir = Path(apktool_dir)
    if not manifest.is_file():
        return {"success": False, "error": "AndroidManifest.xml not found"}

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    tree = ET.parse(str(manifest))  # noqa: S314
    root = tree.getroot()

    for activity in root.iter("activity"):
        for intent in activity.iter("intent-filter"):
            action = intent.find("action")
            category = intent.find("category")
            if action is None or category is None:
                continue
            a_name = action.get(f"{{{ns['android']}}}name", "")
            c_name = category.get(f"{{{ns['android']}}}name", "")
            if "MAIN" not in a_name or "LAUNCHER" not in c_name:
                continue
            act_class = activity.get(f"{{{ns['android']}}}name", "")
            if not act_class:
                continue
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

    return {"success": False, "error": "No launcher Activity found"}


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
