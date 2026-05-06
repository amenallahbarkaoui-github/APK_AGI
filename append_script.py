import sys
import os

path = r'c:\Users\Amenallah\Desktop\APK AGI\src\apk_agent\tools\dart_aot.py'
with open(path, 'r') as f:
    content = f.read()

content = content.replace('import struct\n', 'import struct\nimport shutil\n')
content += '''
def apply_dart_aot_patch(
    file_path: str | Path,
    patch_plan: dict[str, Any],
    backup_dir: str | Path | None = None
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    preview = preview_dart_aot_patch(file_path, patch_plan)
    if not preview.get("success"):
        return preview

    try:
        backup_path = None
        if backup_dir:
            bd = Path(backup_dir)
            bd.mkdir(parents=True, exist_ok=True)
            backup_path = bd / f"{path.name}.bak"
            shutil.copy2(path, backup_path)
        
        data = bytearray(path.read_bytes())
        
        offset = preview["offset"]
        replace_bytes = bytes.fromhex(preview["replace_hex"])
        data[offset : offset + len(replace_bytes)] = replace_bytes
        
        path.write_bytes(data)
        
        return {
            "success": True,
            "path": str(path),
            "backup_path": str(backup_path) if backup_path else None,
            "offset": preview["offset"],
            "offset_hex": preview["offset_hex"],
            "original_hex": preview["original_hex"],
            "replace_hex": preview["replace_hex"],
            "bytes_written": len(replace_bytes)
        }
    except Exception as e:
        return {"success": False, "error": f"Patch application failed: {e}"}
'''

with open(path, 'w') as f:
    f.write(content)
