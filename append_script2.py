import sys
import re

path = r'c:\Users\Amenallah\Desktop\APK AGI\src\apk_agent\agent\tools_def.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

tools_code = """
@tool
def preview_dart_aot_patch(file_path: str, patch_plan_json: str) -> str:
    '''Preview a byte-level patch on a Dart AOT binary without writing to disk.

    Args:
        file_path: Target library path inside the project.
        patch_plan_json: JSON object with 'offset', 'replace_hex', and 'expected_original_hex'.

    Returns: JSON describing the planned patch sizes, hex differences, and safety notes.
    '''
    from apk_agent.tools.dart_aot import preview_dart_aot_patch as _preview
    import json
    
    def _run():
        try:
            plan = json.loads(patch_plan_json)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
        
        result = _preview(_resolve_project_path(file_path), plan)
        return json.dumps(result, indent=2)
    return _safe_call(_run, "preview_dart_aot_patch", _cache_hint=f"{file_path}:{patch_plan_json}")

@tool
def apply_dart_aot_patch(file_path: str, patch_plan_json: str) -> str:
    '''Apply a byte-level patch to a Dart AOT binary and record it to the patch journal.

    Args:
        file_path: Target library path inside the project.
        patch_plan_json: JSON object with 'offset', 'replace_hex', and optionally 'description'.

    Returns: JSON indicating success and backup details.
    '''
    from apk_agent.tools.dart_aot import apply_dart_aot_patch as _apply
    import json
    
    def _run():
        try:
            plan = json.loads(patch_plan_json)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
            
        real_path = _resolve_project_path(file_path)
        backup_dir = _project.patch_diffs_dir
        result = _apply(real_path, plan, backup_dir=backup_dir)
        
        if result.get("success"):
            # Try to log to the global journal
            try:
                _patch_journal.append({
                    "target_file": str(file_path),
                    "description": plan.get("description", "Dart AOT binary patch"),
                    "steps_applied": 1,
                    "steps_total": 1,
                    "diff_text": f"OFFSET: {result.get('offset_hex')} \\nORIGINAL: {result.get('original_hex')}\\nREPLACE:  {result.get('replace_hex')}",
                    "tool": "apply_dart_aot_patch",
                    "errors": []
                })
            except Exception:
                pass
                
        return json.dumps(result, indent=2)
    return _safe_call(_run, "apply_dart_aot_patch")

@tool
def validate_dart_aot_patch(file_path: str, offset: int, expected_hex: str) -> str:
    '''Check if exact bytes are present at an offset in a file. Use this post-patch.

    Args:
        file_path: Path to the modified library.
        offset: The integer offset in the binary.
        expected_hex: Hex string of bytes that should be there.

    Returns: JSON indicating validation success or mismatch.
    '''
    from apk_agent.tools.dart_aot import validate_dart_aot_patch as _valid
    import json
    
    def _run():
        result = _valid(_resolve_project_path(file_path), offset=offset, expected_hex=expected_hex)
        return json.dumps(result, indent=2)
    return _safe_call(_run, "validate_dart_aot_patch", _cache_hint=f"{file_path}:{offset}:{expected_hex}")
"""

content = content.replace('@tool\ndef patch_binary_strings', tools_code + '\n\n@tool\ndef patch_binary_strings')

# Inject into ALL_TOOLS
content = content.replace('locate_dart_aot_candidates,\n', 'locate_dart_aot_candidates,\n    preview_dart_aot_patch,\n    apply_dart_aot_patch,\n    validate_dart_aot_patch,\n')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
