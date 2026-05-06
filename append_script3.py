import sys

path = r'c:\Users\Amenallah\Desktop\APK AGI\test_agent_regressions.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

test_code = """
def test_apply_dart_aot_patch_tools(monkeypatch, tmp_path) -> None:
    from apk_agent.agent.tools_def import preview_dart_aot_patch, apply_dart_aot_patch, validate_dart_aot_patch
    from apk_agent.workspace import WorkspaceSession
    import json
    
    ws = WorkspaceSession(tmp_path / "ws")
    
    so_path = ws.apktool_dir / "libapp.so"
    so_path.parent.mkdir(parents=True, exist_ok=True)
    # create dummy ELF
    data = bytearray(b"\\x7fELF\\x02\\x01\\x01\\x00" + b"\\x00" * 8)
    data += b"\\x03\\x00\\xb7\\x00" + b"\\x00" * (40 - len(data))
    # Target at offset 100
    data += b"\\x00" * (100 - len(data))
    data[100:104] = b"\\xaa\\xbb\\xcc\\xdd"
    data += b"\\x00" * 50
    so_path.write_bytes(data)
    
    monkeypatch.setattr("apk_agent.agent.tools_def._project", ws)
    monkeypatch.setattr("apk_agent.agent.tools_def._resolve_project_path", lambda p: so_path)
    monkeypatch.setattr("apk_agent.agent.tools_def._patch_journal", [])
    
    plan = {
        "offset": 100,
        "replace_hex": "11223344",
        "expected_original_hex": "aabbccdd",
        "description": "test hook"
    }
    
    preview_res = json.loads(preview_dart_aot_patch.invoke({"file_path": "libapp.so", "patch_plan_json": json.dumps(plan)}))
    assert preview_res["success"] is True
    assert preview_res["replace_hex"] == "11223344"
    assert preview_res["original_hex"] == "aabbccdd"
    
    apply_res = json.loads(apply_dart_aot_patch.invoke({"file_path": "libapp.so", "patch_plan_json": json.dumps(plan)}))
    assert apply_res["success"] is True
    assert apply_res["bytes_written"] == 4
    
    # check that value was replaced
    assert so_path.read_bytes()[100:104] == b"\\x11\\x22\\x33\\x44"
    
    # check validate tool
    valid_res = json.loads(validate_dart_aot_patch.invoke({"file_path": "libapp.so", "offset": 100, "expected_hex": "11223344"}))
    assert valid_res["success"] is True
"""

with open(path, 'a', encoding='utf-8') as f:
    f.write("\n" + test_code)

content2 = open(path, 'r', encoding='utf-8').read()
content2 = content2.replace('    assert "locate_dart_aot_candidates" in tool_names', '    assert "locate_dart_aot_candidates" in tool_names\n    assert "apply_dart_aot_patch" in tool_names\n    assert "validate_dart_aot_patch" in tool_names\n    assert "preview_dart_aot_patch" in tool_names\n')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content2)

