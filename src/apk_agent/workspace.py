"""Workspace & project manager — UUID-based project directories."""

from __future__ import annotations

import json
import shutil
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class Project:
    """Represents a single APK analysis project."""

    id: str
    apk_name: str
    created_at: str
    status: str = "created"  # created | decompiled | analysed | patched | complete
    workspace_path: str = ""
    source_type: str = "apk"
    xapk_base_apk_entry: str = ""
    xapk_split_apk_entries: list[str] = field(default_factory=list)
    xapk_obb_entries: list[str] = field(default_factory=list)
    xapk_manifest: dict = field(default_factory=dict)

    # --- derived paths ---
    @property
    def root(self) -> Path:
        return Path(self.workspace_path)

    @property
    def input_dir(self) -> Path:
        return self.root / "input"

    @property
    def apk_path(self) -> Path:
        return self.input_dir / "original.apk"

    @property
    def original_xapk_path(self) -> Path:
        return self.input_dir / "original.xapk"

    @property
    def xapk_contents_dir(self) -> Path:
        return self.input_dir / "xapk_contents"

    @property
    def apktool_dir(self) -> Path:
        return self.root / "decompiled" / "apktool"

    @property
    def jadx_dir(self) -> Path:
        return self.root / "decompiled" / "jadx_src"

    @property
    def patches_dir(self) -> Path:
        return self.root / "patches"

    @property
    def patch_plans_dir(self) -> Path:
        return self.patches_dir / "plans"

    @property
    def patch_backup_dir(self) -> Path:
        return self.patches_dir / "applied" / "backup"

    @property
    def patch_diffs_dir(self) -> Path:
        return self.patches_dir / "applied" / "diffs"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def outputs_dir(self) -> Path:
        return self.root / "outputs"

    @property
    def signed_apk_path(self) -> Path:
        return self.outputs_dir / "patched-signed.apk"

    @property
    def final_artifact_path(self) -> Path:
        suffix = ".xapk" if self.source_type.lower() == "xapk" else ".apk"
        return self.outputs_dir / f"patched-signed{suffix}"

    def meta_path(self) -> Path:
        return self.root / "project.json"


# ---------------------------------------------------------------------------
# Workspace directory scaffold
# ---------------------------------------------------------------------------

_SUBDIRS = [
    "input",
    "decompiled/apktool",
    "decompiled/jadx_src",
    "patches/plans",
    "patches/applied/backup",
    "patches/applied/diffs",
    "logs",
    "outputs",
]


def _scaffold(root: Path) -> None:
    """Create the standard workspace directory tree."""
    for sub in _SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_apk(apk_path: Path, max_size_mb: int = 200) -> list[str]:
    """Basic APK/XAPK validation — returns list of errors (empty == valid)."""
    errors: list[str] = []
    if not apk_path.is_file():
        errors.append(f"File not found: {apk_path}")
        return errors
    size_mb = apk_path.stat().st_size / (1024 * 1024)
    if size_mb > max_size_mb:
        errors.append(f"APK size {size_mb:.1f} MB exceeds limit of {max_size_mb} MB.")

    suffix = apk_path.suffix.lower()
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            if suffix == ".xapk":
                # XAPK is a ZIP containing one or more APKs + manifest.json
                has_apk = any(n.endswith(".apk") for n in names)
                has_manifest = any(Path(n).name == "manifest.json" for n in names)
                if not has_apk:
                    errors.append("XAPK missing inner APK files")
                if not has_manifest:
                    errors.append("XAPK missing manifest.json (may still work)")
            else:
                if not any(n == "AndroidManifest.xml" for n in names):
                    errors.append("APK missing AndroidManifest.xml")
                if not any(n.startswith("classes") and n.endswith(".dex") for n in names):
                    errors.append("APK missing classes.dex")
    except zipfile.BadZipFile:
        errors.append("File is not a valid ZIP/APK archive.")
    return errors


def _normalize_zip_name(name: str) -> str:
    return name.replace("\\", "/").strip("/")


def _safe_archive_member_path(output_dir: Path, member_name: str) -> Path:
    normalized = _normalize_zip_name(member_name)
    if not normalized or normalized in {".", ".."}:
        raise ValueError(f"Unsafe archive entry path: {member_name}")

    output_root = output_dir.resolve()
    candidate = (output_root / normalized).resolve()
    try:
        candidate.relative_to(output_root)
    except ValueError as exc:
        raise ValueError(f"Unsafe archive entry path: {member_name}") from exc
    return candidate


def _safe_extract_zip(zf: zipfile.ZipFile, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for info in zf.infolist():
        normalized = _normalize_zip_name(info.filename)
        if not normalized:
            continue
        target = _safe_archive_member_path(output_dir, info.filename)
        if info.is_dir() or info.filename.endswith(("/", "\\")):
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _read_xapk_manifest(zf: zipfile.ZipFile) -> dict:
    manifest_entry = next((name for name in zf.namelist() if Path(name).name == "manifest.json"), None)
    if not manifest_entry:
        return {}
    try:
        return json.loads(zf.read(manifest_entry).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _collect_manifest_apk_refs(node, refs: list[str]) -> None:
    if isinstance(node, dict):
        for value in node.values():
            _collect_manifest_apk_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_manifest_apk_refs(item, refs)
    elif isinstance(node, str) and node.lower().endswith(".apk"):
        refs.append(_normalize_zip_name(node))


def _collect_preferred_manifest_apk_refs(node, refs: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lower_key = str(key).lower()
            if isinstance(value, str) and value.lower().endswith(".apk") and lower_key in {"base_apk", "main_apk"}:
                refs.append(_normalize_zip_name(value))

        file_value = None
        for key in ("file", "apk", "apk_file", "name", "path"):
            candidate = node.get(key)
            if isinstance(candidate, str) and candidate.lower().endswith(".apk"):
                file_value = _normalize_zip_name(candidate)
                break

        identity_values = " ".join(
            str(node.get(key, "")).lower() for key in ("id", "split_id", "type", "name")
        )
        if file_value and any(tag in identity_values for tag in ("base", "main")):
            refs.append(file_value)

        for value in node.values():
            _collect_preferred_manifest_apk_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_preferred_manifest_apk_refs(item, refs)


def _select_base_xapk_entry(zf: zipfile.ZipFile, apk_entries: list[str], manifest_data: dict) -> str:
    normalized_entries = [_normalize_zip_name(name) for name in apk_entries]
    entry_by_normalized = {normalized: actual for normalized, actual in zip(normalized_entries, apk_entries)}

    manifest_refs: list[str] = []
    _collect_manifest_apk_refs(manifest_data, manifest_refs)
    preferred_refs: list[str] = []
    _collect_preferred_manifest_apk_refs(manifest_data, preferred_refs)

    def _resolve_manifest_ref(ref: str) -> str | None:
        ref = _normalize_zip_name(ref)
        if ref in entry_by_normalized:
            return entry_by_normalized[ref]
        base_name = Path(ref).name.lower()
        for normalized, actual in entry_by_normalized.items():
            if Path(normalized).name.lower() == base_name:
                return actual
        return None

    preferred_actual = [_resolve_manifest_ref(ref) for ref in preferred_refs]
    preferred_actual = [ref for ref in preferred_actual if ref]
    if preferred_actual:
        return preferred_actual[0]

    manifest_actual = {_resolve_manifest_ref(ref) for ref in manifest_refs}
    manifest_actual.discard(None)

    def _score(entry: str) -> tuple[int, int]:
        basename = Path(entry).name.lower()
        score = 0
        if basename == "base.apk":
            score += 1000
        elif basename in {"main.apk", "install.apk"}:
            score += 800
        elif basename.startswith("base") or basename.startswith("main"):
            score += 250
        if entry in manifest_actual:
            score += 120
        if "config." in basename or basename.startswith("config.") or "split_config" in basename:
            score -= 250
        if basename.startswith("split_"):
            score -= 120
        return score, zf.getinfo(entry).file_size

    return max(apk_entries, key=_score)


def extract_xapk_bundle(xapk_path: Path, output_dir: Path) -> dict:
    """Extract an XAPK bundle and return metadata about its contents."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(xapk_path) as zf:
        _safe_extract_zip(zf, output_dir)
        apk_entries = [
            _normalize_zip_name(name)
            for name in zf.namelist()
            if not name.endswith("/") and name.lower().endswith(".apk")
        ]
        if not apk_entries:
            raise ValueError("No APK files found in XAPK bundle")

        manifest_data = _read_xapk_manifest(zf)
        base_entry = _select_base_xapk_entry(zf, apk_entries, manifest_data)
        split_entries = [entry for entry in apk_entries if _normalize_zip_name(entry) != _normalize_zip_name(base_entry)]
        obb_entries = [
            _normalize_zip_name(name)
            for name in zf.namelist()
            if not name.endswith("/") and name.lower().endswith(".obb")
        ]

    base_apk_path = output_dir / Path(base_entry)
    if not base_apk_path.is_file():
        raise FileNotFoundError(f"Base APK entry was not extracted correctly: {base_entry}")

    return {
        "base_apk_path": base_apk_path,
        "base_apk_entry": base_entry,
        "split_apk_entries": split_entries,
        "obb_entries": obb_entries,
        "manifest": manifest_data,
    }


def extract_xapk(xapk_path: Path, output_dir: Path) -> Path:
    """Extract the base APK from an XAPK bundle.

    Returns the path to the extracted base APK.
    """
    bundle = extract_xapk_bundle(xapk_path, output_dir)
    return Path(bundle["base_apk_path"])


def _reset_input_dir(input_dir: Path) -> None:
    input_dir.mkdir(parents=True, exist_ok=True)
    for child in list(input_dir.iterdir()):
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _import_package_into_project_root(apk_path: Path, project_root: Path) -> dict:
    input_dir = project_root / "input"
    _reset_input_dir(input_dir)

    dest_apk = input_dir / "original.apk"
    metadata = {
        "source_type": "apk",
        "xapk_base_apk_entry": "",
        "xapk_split_apk_entries": [],
        "xapk_obb_entries": [],
        "xapk_manifest": {},
    }

    if apk_path.suffix.lower() == ".xapk":
        xapk_dir = input_dir / "xapk_contents"
        bundle = extract_xapk_bundle(apk_path, xapk_dir)
        shutil.copy2(str(bundle["base_apk_path"]), str(dest_apk))
        shutil.copy2(str(apk_path), str(input_dir / "original.xapk"))
        metadata.update({
            "source_type": "xapk",
            "xapk_base_apk_entry": str(bundle["base_apk_entry"]),
            "xapk_split_apk_entries": list(bundle["split_apk_entries"]),
            "xapk_obb_entries": list(bundle["obb_entries"]),
            "xapk_manifest": dict(bundle["manifest"]),
        })
    else:
        shutil.copy2(str(apk_path), str(dest_apk))

    return metadata


def get_final_artifact_path(project) -> Path:
    workspace_root = Path(getattr(project, "workspace_path", "")).resolve()
    outputs_dir = Path(getattr(project, "outputs_dir", workspace_root / "outputs"))
    outputs_dir.mkdir(parents=True, exist_ok=True)
    source_type = str(getattr(project, "source_type", "apk") or "apk").lower()
    suffix = ".xapk" if source_type == "xapk" else ".apk"
    return outputs_dir / f"patched-signed{suffix}"


def package_signed_output(project, signed_apk_path: str | Path) -> Path:
    """Package the final signed artifact for APK or XAPK projects."""
    signed_apk_path = Path(signed_apk_path).resolve()
    source_type = str(getattr(project, "source_type", "apk") or "apk").lower()
    if source_type != "xapk":
        return signed_apk_path

    workspace_root = Path(getattr(project, "workspace_path", "")).resolve()
    original_xapk = Path(getattr(project, "original_xapk_path", workspace_root / "input" / "original.xapk"))
    if not original_xapk.is_file():
        raise FileNotFoundError(f"Original XAPK not found: {original_xapk}")

    output_xapk = get_final_artifact_path(project)
    output_xapk.parent.mkdir(parents=True, exist_ok=True)
    base_entry = str(getattr(project, "xapk_base_apk_entry", "") or "").strip()

    with zipfile.ZipFile(original_xapk) as src:
        apk_entries = [
            _normalize_zip_name(name)
            for name in src.namelist()
            if not name.endswith("/") and name.lower().endswith(".apk")
        ]
        manifest_data = _read_xapk_manifest(src)
        if not base_entry:
            if not apk_entries:
                raise ValueError("Original XAPK has no APK entries to replace")
            base_entry = _select_base_xapk_entry(src, apk_entries, manifest_data)

        normalized_base = _normalize_zip_name(base_entry)
        replaced = False
        signed_bytes = signed_apk_path.read_bytes()

        with zipfile.ZipFile(output_xapk, "w") as dst:
            for info in src.infolist():
                if info.is_dir():
                    dst.writestr(info, b"")
                    continue

                if _normalize_zip_name(info.filename) == normalized_base:
                    new_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
                    new_info.compress_type = info.compress_type
                    new_info.comment = info.comment
                    new_info.extra = info.extra
                    new_info.create_system = info.create_system
                    new_info.create_version = info.create_version
                    new_info.extract_version = info.extract_version
                    new_info.flag_bits = info.flag_bits
                    new_info.external_attr = info.external_attr
                    dst.writestr(new_info, signed_bytes)
                    replaced = True
                else:
                    dst.writestr(info, src.read(info.filename))

    if not replaced:
        raise ValueError(f"Could not replace base APK entry inside XAPK: {base_entry}")

    extracted_base = workspace_root / "input" / "xapk_contents" / Path(base_entry)
    extracted_base.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(signed_apk_path), str(extracted_base))
    return output_xapk.resolve()


# ---------------------------------------------------------------------------
# ProjectManager
# ---------------------------------------------------------------------------


class ProjectManager:
    """Manages APK analysis projects inside a workspace root."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def create_project(self, apk_path: str | Path, max_size_mb: int = 200) -> Project:
        """Create a new project from an APK or XAPK file."""
        apk_path = Path(apk_path).resolve()

        project_id = uuid.uuid4().hex[:12]
        project_root = self.workspace_root / project_id
        _scaffold(project_root)

        project = Project(
            id=project_id,
            apk_name=apk_path.name,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="created",
            workspace_path=str(project_root.resolve()),
        )
        return self.import_package(project, apk_path, max_size_mb)

    def import_package(self, project: Project, apk_path: str | Path, max_size_mb: int = 200) -> Project:
        """Import or replace the APK/XAPK payload for an existing project."""
        apk_path = Path(apk_path).resolve()

        errors = validate_apk(apk_path, max_size_mb)
        if errors:
            raise ValueError("APK validation failed:\n" + "\n".join(errors))

        project_root = Path(project.workspace_path)
        _scaffold(project_root)
        metadata = _import_package_into_project_root(apk_path, project_root)

        project.apk_name = apk_path.name
        project.status = "created"
        project.source_type = str(metadata["source_type"])
        project.xapk_base_apk_entry = str(metadata["xapk_base_apk_entry"])
        project.xapk_split_apk_entries = list(metadata["xapk_split_apk_entries"])
        project.xapk_obb_entries = list(metadata["xapk_obb_entries"])
        project.xapk_manifest = dict(metadata["xapk_manifest"])
        self._save_meta(project)
        return project

    def open_project(self, project_id: str) -> Project:
        """Open an existing project by ID."""
        project_root = self.workspace_root / project_id
        meta_file = project_root / "project.json"
        if not meta_file.is_file():
            raise FileNotFoundError(f"Project {project_id} not found.")
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        return Project(**data)

    def list_projects(self) -> list[Project]:
        """List all projects in workspace."""
        projects: list[Project] = []
        for d in sorted(self.workspace_root.iterdir()):
            meta = d / "project.json"
            if meta.is_file():
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    projects.append(Project(**data))
                except Exception:
                    continue
        return projects

    def update_status(self, project: Project, status: str) -> None:
        """Update and persist project status."""
        project.status = status
        self._save_meta(project)

    def _save_meta(self, project: Project) -> None:
        meta_path = Path(project.workspace_path) / "project.json"
        meta_path.write_text(
            json.dumps(asdict(project), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
