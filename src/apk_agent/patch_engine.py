"""Smali Patch Engine — parse plans, apply ops, backup/diff."""

from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PatchOperation(str, Enum):
    REPLACE_LINE = "replace_line"
    REPLACE_BLOCK = "replace_block"
    INSERT_BEFORE = "insert_before"
    INSERT_AFTER = "insert_after"
    DELETE_BLOCK = "delete_block"
    DELETE_LINE = "delete_line"


@dataclass
class PatchStep:
    """A single patch operation."""

    operation: PatchOperation
    match_pattern: str  # exact string or regex to locate target
    replacement: str = ""  # used for replace ops
    content: str = ""  # used for insert ops
    is_regex: bool = False
    description: str = ""


@dataclass
class PatchPlan:
    """A plan to modify a smali file."""

    target_file: str  # relative path within apktool output
    description: str = ""
    steps: list[PatchStep] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "PatchPlan":
        """Create PatchPlan from a dict (LLM-generated JSON)."""
        steps = []
        for s in data.get("steps", []):
            steps.append(PatchStep(
                operation=PatchOperation(s["operation"]),
                match_pattern=s["match_pattern"],
                replacement=s.get("replacement", ""),
                content=s.get("content", ""),
                is_regex=s.get("is_regex", False),
                description=s.get("description", ""),
            ))
        return cls(
            target_file=data["target_file"],
            description=data.get("description", ""),
            steps=steps,
        )


@dataclass
class PatchResult:
    """Result of applying a patch plan."""

    success: bool
    target_file: str
    files_modified: list[str] = field(default_factory=list)
    backup_path: str = ""
    diff_text: str = ""
    errors: list[str] = field(default_factory=list)
    steps_applied: int = 0
    steps_total: int = 0


class PatchEngine:
    """Applies PatchPlans to smali files with backup and diff."""

    def __init__(self, apktool_dir: Path, backup_dir: Path, diffs_dir: Path):
        self.apktool_dir = apktool_dir
        self.backup_dir = backup_dir
        self.diffs_dir = diffs_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.diffs_dir.mkdir(parents=True, exist_ok=True)

    def preview_plan(self, plan: PatchPlan) -> str:
        """Show what a plan would change without actually modifying files."""
        target = self.apktool_dir / plan.target_file
        if not target.is_file():
            return f"❌ Target file not found: {plan.target_file}"

        original = target.read_text(encoding="utf-8", errors="replace")
        modified = self._apply_steps(original, plan.steps)
        if modified is None:
            return "❌ Could not apply one or more steps (pattern not found)."

        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile=f"a/{plan.target_file}",
            tofile=f"b/{plan.target_file}",
            lineterm="",
        )
        return "".join(diff) or "(no changes)"

    def apply_plan(self, plan: PatchPlan) -> PatchResult:
        """Apply a patch plan to the target file. Backs up before modifying."""
        target = self.apktool_dir / plan.target_file
        result = PatchResult(
            success=False,
            target_file=plan.target_file,
            steps_total=len(plan.steps),
        )

        if not target.is_file():
            result.errors.append(f"Target file not found: {plan.target_file}")
            return result

        # Backup
        backup_path = self.backup_dir / plan.target_file
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(target), str(backup_path))
        result.backup_path = str(backup_path)

        # Read original
        original = target.read_text(encoding="utf-8", errors="replace")
        current = original

        # Apply steps one by one
        for i, step in enumerate(plan.steps):
            new_content = self._apply_single_step(current, step)
            if new_content is None:
                result.errors.append(
                    f"Step {i+1}/{len(plan.steps)} failed "
                    f"({step.operation.value}): pattern not found — "
                    f"'{step.match_pattern[:80]}...'"
                )
                # Continue trying other steps (don't abort entire plan)
                continue
            current = new_content
            result.steps_applied += 1

        if result.steps_applied == 0:
            result.errors.append("No steps were applied — all patterns failed to match.")
            return result

        # Write modified file
        target.write_text(current, encoding="utf-8")
        result.files_modified.append(str(target))

        # Generate diff
        diff_lines = difflib.unified_diff(
            original.splitlines(keepends=True),
            current.splitlines(keepends=True),
            fromfile=f"a/{plan.target_file}",
            tofile=f"b/{plan.target_file}",
        )
        result.diff_text = "".join(diff_lines)

        # Save diff
        diff_file = self.diffs_dir / (plan.target_file.replace("/", "_").replace("\\", "_") + ".diff")
        diff_file.parent.mkdir(parents=True, exist_ok=True)
        diff_file.write_text(result.diff_text, encoding="utf-8")

        result.success = result.steps_applied == result.steps_total
        return result

    def _apply_steps(self, text: str, steps: list[PatchStep]) -> Optional[str]:
        """Apply all steps; return None if any step fails."""
        current = text
        for step in steps:
            result = self._apply_single_step(current, step)
            if result is None:
                return None
            current = result
        return current

    def _apply_single_step(self, text: str, step: PatchStep) -> Optional[str]:
        """Apply a single step. Returns modified text or None if match fails."""
        match step.operation:
            case PatchOperation.REPLACE_LINE:
                return self._op_replace_line(text, step)
            case PatchOperation.REPLACE_BLOCK:
                return self._op_replace_block(text, step)
            case PatchOperation.INSERT_BEFORE:
                return self._op_insert(text, step, before=True)
            case PatchOperation.INSERT_AFTER:
                return self._op_insert(text, step, before=False)
            case PatchOperation.DELETE_BLOCK:
                return self._op_delete_block(text, step)
            case PatchOperation.DELETE_LINE:
                return self._op_delete_line(text, step)
            case _:
                return None

    # ---- Operation implementations ----

    def _find_pattern(self, text: str, pattern: str, is_regex: bool) -> Optional[re.Match]:
        """Find pattern in text."""
        if is_regex:
            return re.search(pattern, text, re.MULTILINE | re.DOTALL)
        else:
            idx = text.find(pattern)
            if idx == -1:
                return None
            # Create a fake match-like result
            return _FakeMatch(idx, idx + len(pattern), pattern)

    def _op_replace_line(self, text: str, step: PatchStep) -> Optional[str]:
        """Replace lines containing the match pattern."""
        lines = text.splitlines(keepends=True)
        found = False
        result_lines = []
        for line in lines:
            if step.is_regex:
                if re.search(step.match_pattern, line):
                    result_lines.append(step.replacement + "\n")
                    found = True
                else:
                    result_lines.append(line)
            else:
                if step.match_pattern in line:
                    result_lines.append(step.replacement + "\n")
                    found = True
                else:
                    result_lines.append(line)
        return "".join(result_lines) if found else None

    def _op_replace_block(self, text: str, step: PatchStep) -> Optional[str]:
        """Replace an entire block of text."""
        m = self._find_pattern(text, step.match_pattern, step.is_regex)
        if m is None:
            return None
        return text[:m.start()] + step.replacement + text[m.end():]

    def _op_insert(self, text: str, step: PatchStep, before: bool) -> Optional[str]:
        """Insert content before or after the match pattern."""
        m = self._find_pattern(text, step.match_pattern, step.is_regex)
        if m is None:
            return None
        if before:
            return text[:m.start()] + step.content + "\n" + text[m.start():]
        else:
            return text[:m.end()] + "\n" + step.content + text[m.end():]

    def _op_delete_block(self, text: str, step: PatchStep) -> Optional[str]:
        """Delete a block of text matching the pattern."""
        m = self._find_pattern(text, step.match_pattern, step.is_regex)
        if m is None:
            return None
        return text[:m.start()] + text[m.end():]

    def _op_delete_line(self, text: str, step: PatchStep) -> Optional[str]:
        """Delete all lines containing the match pattern."""
        lines = text.splitlines(keepends=True)
        found = False
        result_lines = []
        for line in lines:
            if step.is_regex:
                if re.search(step.match_pattern, line):
                    found = True
                    continue
            else:
                if step.match_pattern in line:
                    found = True
                    continue
            result_lines.append(line)
        return "".join(result_lines) if found else None


class _FakeMatch:
    """Minimal match-like object for literal string finds."""

    def __init__(self, start: int, end: int, group0: str):
        self._start = start
        self._end = end
        self._group0 = group0

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self, n: int = 0) -> str:
        return self._group0
