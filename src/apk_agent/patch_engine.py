"""Smali Patch Engine — parse plans, apply ops, backup/diff."""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


def _ensure_writable(path: Path) -> None:
    """Clear the read-only flag on Windows so we can write to the file."""
    if path.exists():
        path.chmod(path.stat().st_mode | stat.S_IWRITE)


def _unescape_smali(pattern: str) -> str:
    """Strip regex-escape backslashes from a pattern that should be literal.

    LLMs often pre-escape smali metacharacters (parentheses in method
    signatures, $ in inner-class names, dots in directives) even when the
    pattern is supposed to be a plain-text literal.
    """
    return (
        pattern
        .replace("\\(", "(")
        .replace("\\)", ")")
        .replace("\\$", "$")
        .replace("\\.", ".")
        .replace("\\;", ";")
        .replace("\\[", "[")
    )


def _write_with_retry(path: Path, content: str, retries: int = 3, delay: float = 0.3) -> None:
    """Write text to a file with retry on Windows file lock errors (WinError 32)."""
    import time
    for attempt in range(retries):
        try:
            _ensure_writable(path)
            path.write_text(content, encoding="utf-8")
            return
        except OSError as e:
            if attempt < retries - 1 and getattr(e, 'winerror', 0) == 32:
                time.sleep(delay * (attempt + 1))
            else:
                raise


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
        # Normalise target_file: the LLM sometimes sends absolute paths or
        # prefixed relative paths. We need a clean relative path within apktool/.
        raw_tf = data.get("target_file") or data.get("file") or data.get("smali_file") or ""
        if not raw_tf:
            raise ValueError(
                "Missing 'target_file' in patch plan JSON. "
                "The JSON must contain a 'target_file' key with the smali file path."
            )
        tf = raw_tf.replace("\\", "/")

        # Handle absolute paths: extract everything after "decompiled/apktool/"
        if "decompiled/apktool/" in tf:
            tf = tf.split("decompiled/apktool/", 1)[1]
        elif "decompiled/" in tf:
            tf = tf.split("decompiled/", 1)[1]
        else:
            # Handle relative prefixes
            for prefix in ("decompiled/apktool/", "decompiled/"):
                if tf.startswith(prefix):
                    tf = tf[len(prefix):]
                    break

        # Strip leading slashes and collapse double slashes
        tf = tf.lstrip("/")
        while "//" in tf:
            tf = tf.replace("//", "/")

        return cls(
            target_file=tf,
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

    def _find_target(self, target_file: str) -> Path | None:
        """Resolve target_file to an actual file path, searching all smali dirs.

        Returns the Path if found, None otherwise.
        """
        tf = target_file.replace("\\", "/").lstrip("/")
        while "//" in tf:
            tf = tf.replace("//", "/")

        # Direct under apktool_dir (covers smali/..., smali_classes2/..., res/..., etc.)
        candidate = self.apktool_dir / tf
        if candidate.is_file():
            return candidate

        # If path starts with "smali/", search smali_classes2/, smali_classes3/, etc.
        if tf.startswith("smali/"):
            inner = tf.split("/", 1)[1]
            for child in sorted(self.apktool_dir.iterdir()):
                if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_classes")):
                    test = child / inner
                    if test.is_file():
                        return test

        # Bare path (e.g. "B2/g0.smali") — search all smali dirs
        if not tf.startswith("smali") and tf.endswith(".smali"):
            for child in sorted(self.apktool_dir.iterdir()):
                if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_classes")):
                    test = child / tf
                    if test.is_file():
                        return test

        return None

    def preview_plan(self, plan: PatchPlan) -> str:
        """Show what a plan would change without actually modifying files."""
        target = self._find_target(plan.target_file)
        if target is None:
            return f"\u274c Target file not found: {plan.target_file}"

        original = target.read_text(encoding="utf-8", errors="replace")
        modified, errors = self._apply_steps(original, plan.steps, collect_errors=True)
        if modified is None:
            error_detail = "\n".join(errors) if errors else "Unknown step failure"
            return f"❌ Could not apply one or more steps (pattern not found).\n\n{error_detail}"

        clean_path = plan.target_file.lstrip("/").replace("\\", "/")
        while "//" in clean_path:
            clean_path = clean_path.replace("//", "/")
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile=f"a/{clean_path}",
            tofile=f"b/{clean_path}",
            lineterm="",
        )
        return "".join(diff) or "(no changes)"

    def restore_backup(self, target_file: str) -> dict:
        """Restore a file from its backup (undo all patches)."""
        backup_path = self.backup_dir / target_file
        if not backup_path.is_file():
            return {"success": False, "error": f"No backup found for {target_file}"}

        target = self._find_target(target_file)
        if target is None:
            return {"success": False, "error": f"Target file not found: {target_file}"}

        shutil.copy2(str(backup_path), str(target))
        return {
            "success": True,
            "restored_file": str(target),
            "backup_source": str(backup_path),
        }

    def apply_plan(self, plan: PatchPlan) -> PatchResult:
        """Apply a patch plan to the target file. Backs up before modifying."""
        target = self._find_target(plan.target_file)
        result = PatchResult(
            success=False,
            target_file=plan.target_file,
            steps_total=len(plan.steps),
        )

        if target is None:
            result.errors.append(f"Target file not found: {plan.target_file}")
            return result

        # Backup — only create if no backup exists yet (preserve the ORIGINAL)
        backup_path = self.backup_dir / plan.target_file
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        if not backup_path.is_file():
            import time as _t
            for _attempt in range(3):
                try:
                    shutil.copy2(str(target), str(backup_path))
                    break
                except OSError as _oe:
                    if _attempt < 2 and getattr(_oe, 'winerror', 0) == 32:
                        _t.sleep(0.3 * (_attempt + 1))
                    else:
                        raise
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

        # Write modified file with retry for Windows file locks
        _write_with_retry(target, current)
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
        _write_with_retry(diff_file, result.diff_text)

        result.success = result.steps_applied == result.steps_total
        return result

    def _apply_steps(self, text: str, steps: list[PatchStep],
                      collect_errors: bool = False) -> Optional[str] | tuple[Optional[str], list[str]]:
        """Apply all steps; return None if any step fails.

        If *collect_errors* is True, returns (result, errors_list) — where
        result may be partial (steps applied up to the failure point) and
        errors_list contains descriptions of each failed step.
        """
        current = text
        errors: list[str] = []
        for i, step in enumerate(steps, 1):
            result = self._apply_single_step(current, step)
            if result is None:
                desc = step.description or f"step {i}"
                pat_preview = step.match_pattern[:120] if step.match_pattern else "(empty)"
                errors.append(
                    f"Step {i} ({step.operation.value}) FAILED — "
                    f"pattern not found: {pat_preview!r}  "
                    f"(description: {desc})"
                )
                if not collect_errors:
                    return (None, errors) if collect_errors else None
            else:
                current = result
        if collect_errors:
            return (current if not errors else None, errors)
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
        """Find pattern in text.

        For regex patterns, if the initial match fails, retries with smali
        metacharacters escaped — the LLM often emits `.method foo()V[\\s\\S]*?.end method`
        where `()` and `.method`/`.end` contain unescaped regex metacharacters.
        """
        if is_regex:
            try:
                m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
                if m:
                    return m
            except re.error:
                pass

            # Retry: auto-escape smali-specific metacharacters that the LLM
            # leaves unescaped.  Targets: parentheses in method signatures,
            # dots in `.method`/`.end method`/`.field`/`.local` etc., and `$`
            # in inner-class names.  Preserve intentional regex like [\s\S]*?
            # and .* / .+ by only escaping when adjacent to smali keywords.
            escaped = pattern
            # Escape literal parentheses in method signatures: Foo(Ljava/...) → Foo\(Ljava/...\)
            escaped = re.sub(r'(?<!\\)\((?!\?)', r'\\(', escaped)  # ( not preceded by \ and not followed by ? (regex group)
            escaped = re.sub(r'(?<!\\)\)(?![*+?])', r'\\)', escaped)  # ) not followed by quantifier
            # Escape leading dot in smali directives: .method .end .field .local etc.
            escaped = re.sub(r'(?<!\\)\.(?=method|end |field|local|super|source|class|implements|annotation|param|line|registers|locals|prologue|epilogue)', r'\\.', escaped)
            # Escape $ in class names like Foo$Bar
            escaped = re.sub(r'(?<!\\)\$(?=[A-Za-z_])', r'\\$', escaped)

            if escaped != pattern:
                try:
                    m = re.search(escaped, text, re.MULTILINE | re.DOTALL)
                    if m:
                        return m
                except re.error:
                    pass

            # Final fallback: try treating the whole pattern as literal with
            # only [\s\S]*? / .* / .+ as wildcards
            # Split on common regex wildcards, escape everything else, rejoin
            parts = re.split(r'(\[\\s\\S\]\*\?|\.\*\??|\.\+\??|\\s\+|\\S\+)', pattern)
            if len(parts) > 1:
                reassembled = ""
                for i, part in enumerate(parts):
                    if i % 2 == 0:  # literal fragment
                        reassembled += re.escape(part)
                    else:  # regex wildcard — keep as-is
                        reassembled += part
                try:
                    m = re.search(reassembled, text, re.MULTILINE | re.DOTALL)
                    if m:
                        return m
                except re.error:
                    pass

            return None
        else:
            idx = text.find(pattern)
            if idx != -1:
                return _FakeMatch(idx, idx + len(pattern), pattern)

            # Fallback: the LLM often pre-escapes smali metacharacters
            # (e.g. \( instead of (, \$ instead of $, \. instead of .)
            # even when is_regex=False.  Un-escape and retry.
            unescaped = _unescape_smali(pattern)
            if unescaped != pattern:
                idx = text.find(unescaped)
                if idx != -1:
                    return _FakeMatch(idx, idx + len(unescaped), unescaped)

            # Second fallback: normalise line endings (\r\n → \n) and try
            # both original and unescaped patterns.
            text_lf = text.replace("\r\n", "\n")
            for candidate in (pattern, unescaped) if unescaped != pattern else (pattern,):
                cand_lf = candidate.replace("\r\n", "\n")
                idx = text_lf.find(cand_lf)
                if idx != -1:
                    # Map position back to original text
                    # Count how many \r\n pairs precede 'idx' in the original
                    preceding = text_lf[:idx]
                    real_idx = idx + preceding.count("")  # approx; use direct search
                    # Direct search in original text for the matched region
                    real_match = text_lf[idx:idx + len(cand_lf)]
                    real_idx2 = text.find(real_match)
                    if real_idx2 != -1:
                        return _FakeMatch(real_idx2, real_idx2 + len(real_match), real_match)
                    # If exact repositioning failed, still return the LF-based match
                    return _FakeMatch(idx, idx + len(cand_lf), cand_lf)

            # Third fallback: collapse all whitespace and try matching.
            # This handles extra spaces, tabs, and other minor differences.
            norm_pattern = " ".join(pattern.split())
            norm_unesc = " ".join(unescaped.split()) if unescaped != pattern else norm_pattern
            norm_text = " ".join(text.split())
            for norm_p, orig_p in ((norm_pattern, pattern), (norm_unesc, unescaped)):
                idx = norm_text.find(norm_p)
                if idx != -1:
                    # Try to find a reasonable match region in the original text.
                    # Use the first few non-whitespace words as anchors.
                    words = orig_p.split()
                    if words:
                        # Find the first word in original text
                        anchor = words[0]
                        search_start = 0
                        for _ in range(text.count(anchor)):
                            pos = text.find(anchor, search_start)
                            if pos == -1:
                                break
                            # Check if enough of the pattern follows from here
                            end_guess = pos + len(orig_p) + 100  # generous
                            chunk = " ".join(text[pos:end_guess].split())
                            if norm_p in chunk:
                                # Find exact end by scanning forward
                                end = pos + len(orig_p)
                                while end < len(text) and " ".join(text[pos:end].split()) != norm_p:
                                    end += 1
                                    if end - pos > len(orig_p) * 3:
                                        break
                                return _FakeMatch(pos, min(end, len(text)), text[pos:min(end, len(text))])
                            search_start = pos + 1
                    break

            return None

    def _line_matches(self, line: str, pat: str, pat_unesc: str, is_regex: bool) -> bool:
        """Check if a line matches the pattern, with robust fallbacks.

        Handles whitespace normalisation, CRLF, and partial matches for
        long constructor/method signatures that the LLM may truncate.
        """
        stripped = line.rstrip("\r\n")
        if is_regex:
            try:
                return bool(re.search(pat, stripped))
            except re.error:
                return False

        # 1. Exact substring
        if pat in stripped or (pat_unesc != pat and pat_unesc in stripped):
            return True

        # 2. Whitespace-normalised substring
        norm_line = " ".join(stripped.split())
        norm_pat = " ".join(pat.split())
        norm_unesc = " ".join(pat_unesc.split()) if pat_unesc != pat else norm_pat
        if norm_pat in norm_line or (norm_unesc != norm_pat and norm_unesc in norm_line):
            return True

        # 3. For long method signatures: match if the pattern is a prefix of
        #    the line (LLM often truncates at 80 chars). Require at least 40
        #    chars to avoid false positives on short patterns.
        if len(norm_pat) >= 40:
            if norm_line.startswith(norm_pat) or (norm_unesc != norm_pat and norm_line.startswith(norm_unesc)):
                return True
            # Also handle case where pattern starts with leading whitespace already stripped
            if norm_pat.startswith(".method") and norm_line.startswith(".method"):
                # Compare just the method signature part
                if norm_line.startswith(norm_pat[:len(norm_pat)-3]):
                    return True

        return False

    def _op_replace_line(self, text: str, step: PatchStep) -> Optional[str]:
        """Replace lines containing the match pattern."""
        lines = text.splitlines(keepends=True)
        found = False
        result_lines = []
        pat = step.match_pattern
        pat_unesc = _unescape_smali(pat)
        for line in lines:
            if self._line_matches(line, pat, pat_unesc, step.is_regex):
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
        pat = step.match_pattern
        pat_unesc = _unescape_smali(pat)
        for line in lines:
            if self._line_matches(line, pat, pat_unesc, step.is_regex):
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
