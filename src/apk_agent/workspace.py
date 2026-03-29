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
                has_manifest = "manifest.json" in names
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


def extract_xapk(xapk_path: Path, output_dir: Path) -> Path:
    """Extract the base APK from an XAPK bundle.

    Returns the path to the extracted base APK.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(xapk_path) as zf:
        # Find the base APK (usually the largest .apk or named base.apk)
        apk_entries = [n for n in zf.namelist() if n.endswith(".apk")]
        if not apk_entries:
            raise ValueError("No APK files found in XAPK bundle")

        # Prefer base.apk, otherwise take the largest
        base_name = "base.apk" if "base.apk" in apk_entries else None
        if not base_name:
            # Find the largest APK
            sizes = {n: zf.getinfo(n).file_size for n in apk_entries}
            base_name = max(sizes, key=sizes.get)

        zf.extract(base_name, output_dir)
        extracted = output_dir / base_name

        # Also extract all split APKs for reference
        for name in apk_entries:
            if name != base_name:
                zf.extract(name, output_dir)

        return extracted


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

        # validate
        errors = validate_apk(apk_path, max_size_mb)
        if errors:
            raise ValueError("APK validation failed:\n" + "\n".join(errors))

        project_id = uuid.uuid4().hex[:12]
        project_root = self.workspace_root / project_id
        _scaffold(project_root)

        # Handle XAPK: extract base APK
        if apk_path.suffix.lower() == ".xapk":
            xapk_dir = project_root / "input" / "xapk_contents"
            base_apk = extract_xapk(apk_path, xapk_dir)
            dest_apk = project_root / "input" / "original.apk"
            shutil.copy2(str(base_apk), str(dest_apk))
            # Also keep original XAPK reference
            shutil.copy2(str(apk_path), str(project_root / "input" / "original.xapk"))
        else:
            dest_apk = project_root / "input" / "original.apk"
            shutil.copy2(str(apk_path), str(dest_apk))

        project = Project(
            id=project_id,
            apk_name=apk_path.name,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="created",
            workspace_path=str(project_root.resolve()),
        )

        # persist metadata
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
