"""Auto-compact — summarize conversation context when it grows too large.

When the message history exceeds a token threshold (default 160 000 tokens,
tuned for the GLM-5.1 204k context window), the compactor:

1. Extracts the full conversation history
2. Sends it to the LLM with a compact/summary prompt
3. Replaces the old messages with:
   - The original system prompt
   - A compact summary message
   - The last N recent messages (to preserve immediate context)

This lets the agent keep working on long tasks without hitting context limits
or degrading quality.
"""

from __future__ import annotations

import logging
from typing import Any

import tiktoken
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

logger = logging.getLogger("apk_agent.compactor")

# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------

# Use cl100k_base as a reasonable approximation for most models
_ENCODING: tiktoken.Encoding | None = None


def _get_encoding() -> tiktoken.Encoding:
    global _ENCODING
    if _ENCODING is None:
        try:
            _ENCODING = tiktoken.encoding_for_model("gpt-4o")
        except Exception:
            _ENCODING = tiktoken.get_encoding("cl100k_base")
    return _ENCODING


def count_tokens(text: str) -> int:
    """Count tokens in a string using tiktoken."""
    return len(_get_encoding().encode(text))


def count_message_tokens(messages: list[BaseMessage]) -> int:
    """Estimate total tokens across all messages."""
    total = 0
    for msg in messages:
        content = msg.content or ""
        if isinstance(content, list):
            # Multi-part messages (e.g., images + text)
            for part in content:
                if isinstance(part, dict) and "text" in part:
                    total += count_tokens(part["text"])
                elif isinstance(part, str):
                    total += count_tokens(part)
        else:
            total += count_tokens(str(content))

        # Count tool call args too
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                total += count_tokens(str(tc.get("args", {})))

        # Overhead per message (role, separators, etc.)
        total += 4
    return total


# ---------------------------------------------------------------------------
# Compact prompt
# ---------------------------------------------------------------------------

COMPACT_SYSTEM_PROMPT = """You are a conversation compactor for an APK reverse-engineering AI agent.

Your job: Take a long conversation history and produce a **dense, structured summary** that preserves ALL important context so the agent can seamlessly continue its work.

The summary MUST include these sections — DO NOT SKIP ANY:

## 1. Project Info
APK name, package name, target SDK, any metadata discovered.

## 2. Original Task
The user's EXACT original request — quote it verbatim.

## 3. Current Progress
- What phase the agent is in (Recon / Deep Analysis / Patching / Build / Report)
- What has been completed vs still pending
- Percentage estimate of task completion

## 4. Analysis Results (PRESERVE ALL)
For EVERY tool that was run, record:
- Tool name + what it found (key data only, not raw output)
- Specific file paths where findings were located
- Line numbers of critical code sections

## 5. Vulnerability Findings (FULL LIST)
For EACH vulnerability found:
- ID, Name, Severity, Category
- Exact file path and line number
- Brief description of the issue
- CWE if available

## 6. Protection Mechanisms Found
List ALL detected protections with:
- Type (SSL pinning, root detection, anti-tamper, etc.)
- Class/method implementing it
- Recommended bypass approach

## 7. Patches Applied
For each patch:
- Target file and method
- What was changed (before → after)
- Success/failure status

## 8. Patches Still Needed
List remaining protections that need bypassing.

## 9. Key File Paths
Every important file path referenced — smali files, Java sources, configs.
The agent needs these to continue without re-searching.

## 10. Critical Code Snippets
Include actual code for any method body that is a bypass target.
The agent needs these to write patches without re-reading files.

## 11. Next Steps
Explicit list of what the agent should do next to complete the task.

Be EXTREMELY thorough. The agent will use this summary as its ONLY memory of past work.
Loss of any finding, path, or code snippet means wasted tool calls to re-discover it."""


def build_compact_prompt(messages: list[BaseMessage]) -> str:
    """Build the prompt for the compaction LLM call."""
    from apk_agent.session import export_messages_text

    conversation_text = export_messages_text(messages)

    return f"""Summarize this APK analysis conversation into a dense, structured summary.
Preserve ALL findings, file paths, tool results, and the current task state.

--- CONVERSATION START ---
{conversation_text}
--- CONVERSATION END ---

Produce a structured summary following the format described in your instructions."""


# ---------------------------------------------------------------------------
# Compactor
# ---------------------------------------------------------------------------

# Configurable thresholds (GLM-5.1 context window: 204,800 tokens, max output: 131,072)
DEFAULT_TOKEN_THRESHOLD = 100_000  # Start compacting — leaves ~105k headroom for response + tools
KEEP_RECENT_MESSAGES = 20  # Keep the last N messages for immediate context
MIN_MESSAGES_TO_COMPACT = 30  # Don't compact if fewer messages than this


class Compactor:
    """Monitors conversation size and auto-compacts when needed."""

    def __init__(
        self,
        token_threshold: int = DEFAULT_TOKEN_THRESHOLD,
        keep_recent: int = KEEP_RECENT_MESSAGES,
    ):
        self.token_threshold = token_threshold
        self.keep_recent = keep_recent
        self.compact_count = 0
        self.last_token_count = 0
        self._last_compact_msg_count = 0  # message count at last compaction

    def should_compact(self, messages: list[BaseMessage]) -> bool:
        """Check if the conversation needs compaction.

        Includes a cooldown: won't re-compact until at least 10 new messages
        have been added since the last compaction.  This prevents the expensive
        compaction LLM call from firing on every turn when the context stays
        near the threshold.
        """
        if len(messages) < MIN_MESSAGES_TO_COMPACT:
            return False

        # Cooldown — require 10+ new messages since last compaction
        if self._last_compact_msg_count and len(messages) - self._last_compact_msg_count < 10:
            return False

        self.last_token_count = count_message_tokens(messages)
        return self.last_token_count >= self.token_threshold

    def estimate_tokens(self, messages: list[BaseMessage]) -> int:
        """Estimate token count without storing it."""
        return count_message_tokens(messages)

    def compact(self, messages: list[BaseMessage], llm, *, agent_state: dict | None = None) -> list[BaseMessage]:
        """Compact the conversation by summarizing old messages.

        Args:
            messages: Full message list from the agent state
            llm: The LLM instance to use for summarization
            agent_state: Optional agent state dict with findings/patches for fallback

        Returns:
            New message list: [SystemPrompt, CompactSummary, ...recent_messages]
        """
        logger.info(
            "Auto-compacting conversation: %d messages, ~%d tokens",
            len(messages),
            self.last_token_count or count_message_tokens(messages),
        )

        # Record message count for cooldown tracking
        self._last_compact_msg_count = len(messages)

        # Separate system prompt from conversation
        system_msg = None
        conversation = []
        for msg in messages:
            if isinstance(msg, SystemMessage) and system_msg is None:
                system_msg = msg
            else:
                conversation.append(msg)

        if len(conversation) <= self.keep_recent:
            logger.info("Not enough messages to compact after excluding recent.")
            return messages

        # Split: old messages to summarize, recent to keep
        old_messages = conversation[: -self.keep_recent]
        recent_messages = conversation[-self.keep_recent :]

        # If the old messages are huge, skip the LLM summarization entirely
        # (the LLM call itself would hang trying to process 100K+ tokens).
        # Use the fast fallback trim instead, which extracts structured state
        # from agent_state without any LLM call.
        old_tokens = count_message_tokens(old_messages)
        if old_tokens > 80_000:
            logger.info(
                "Old messages too large for LLM summary (%d tokens). "
                "Using fast fallback trim.",
                old_tokens,
            )
            self.compact_count += 1
            return _sanitize_compacted(
                _fallback_trim(messages, system_msg, recent_messages, old_messages,
                               agent_state=agent_state)
            )

        # Build summary prompt
        compact_prompt = build_compact_prompt(old_messages)

        try:
            # Use LLM to summarize — retry once on empty response
            summary_text = ""
            for _attempt in range(2):
                summary_response = llm.invoke([
                    SystemMessage(content=COMPACT_SYSTEM_PROMPT),
                    HumanMessage(content=compact_prompt),
                ])

                # Handle content that might be a string or list of parts
                raw_content = summary_response.content
                if isinstance(raw_content, list):
                    summary_text = " ".join(
                        p.get("text", "") if isinstance(p, dict) else str(p)
                        for p in raw_content
                    ).strip()
                else:
                    summary_text = str(raw_content or "").strip()

                if summary_text:
                    break
                logger.warning("Compactor LLM returned empty (attempt %d/2)", _attempt + 1)

            if not summary_text:
                logger.warning("Compactor returned empty summary after retries. Using fallback trim.")
                return _sanitize_compacted(
                    _fallback_trim(messages, system_msg, recent_messages, old_messages,
                                   agent_state=agent_state)
                )

            self.compact_count += 1

            # Build the compact summary message
            compact_msg = HumanMessage(
                content=(
                    f"📋 **[Auto-Compact Summary #{self.compact_count}]**\n\n"
                    f"The conversation history has been automatically summarized to save context. "
                    f"Previous messages ({len(old_messages)} messages, ~{count_message_tokens(old_messages)} tokens) "
                    f"were condensed into this summary.\n\n"
                    f"---\n\n{summary_text}\n\n---\n\n"
                    f"⚡ **AUTO-CONTINUE**: The task is NOT finished. Pick up EXACTLY where the summary "
                    f"says you left off. Check the 'Next Steps' section above and execute immediately. "
                    f"Do NOT re-run tools whose results are already in the summary. "
                    f"Do NOT ask the user what to do next — the original task is stated above."
                )
            )

            # Reassemble: SystemPrompt + CompactSummary + RecentMessages
            new_messages: list[BaseMessage] = []
            if system_msg:
                new_messages.append(system_msg)
            new_messages.append(compact_msg)
            new_messages.extend(recent_messages)

            new_token_count = count_message_tokens(new_messages)
            logger.info(
                "Compacted: %d → %d messages, ~%d → ~%d tokens (saved ~%d tokens)",
                len(messages),
                len(new_messages),
                self.last_token_count,
                new_token_count,
                self.last_token_count - new_token_count,
            )

            return _sanitize_compacted(new_messages)

        except Exception as e:
            logger.error("Auto-compact failed: %s", e)
            # Fallback: just trim old messages without LLM summary
            return _sanitize_compacted(
                _fallback_trim(messages, system_msg, recent_messages, old_messages,
                               agent_state=agent_state)
            )

    def get_stats(self) -> dict[str, Any]:
        """Return compactor statistics."""
        return {
            "compact_count": self.compact_count,
            "last_token_count": self.last_token_count,
            "token_threshold": self.token_threshold,
            "keep_recent": self.keep_recent,
        }


def _sanitize_compacted(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Sanitize messages after compaction to prevent API errors.

    Fixes:
    - ToolMessages with missing/empty name field (Gemini requirement)
    - Orphaned ToolMessages whose parent AIMessage was compacted away
    - AIMessage.tool_calls with empty names
    """
    # Build tool_id→name mapping from AIMessage tool_calls
    id_to_name: dict[str, str] = {}
    ai_tool_ids: set[str] = set()
    for msg in messages:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                name = tc.get("name") or ""
                tid = tc.get("id") or ""
                if name and tid:
                    id_to_name[tid] = name
                if tid:
                    ai_tool_ids.add(tid)
                # Fix empty tool_call names
                if not tc.get("name"):
                    tc["name"] = id_to_name.get(tid, "unknown_tool")

    # Fix ToolMessage names and remove orphans
    cleaned: list[BaseMessage] = []
    for msg in messages:
        if isinstance(msg, ToolMessage):
            if not getattr(msg, "name", None):
                msg.name = id_to_name.get(msg.tool_call_id, "unknown_tool")
            # Drop orphaned ToolMessages (no matching AIMessage.tool_call)
            if msg.tool_call_id and msg.tool_call_id not in ai_tool_ids:
                logger.debug("Dropping orphaned ToolMessage: %s", msg.tool_call_id)
                continue
        cleaned.append(msg)

    return cleaned


def _fallback_trim(
    original: list[BaseMessage],
    system_msg: SystemMessage | None,
    recent: list[BaseMessage],
    old: list[BaseMessage],
    *,
    agent_state: dict | None = None,
) -> list[BaseMessage]:
    """Fallback when LLM compaction fails — build a structured summary from agent state."""
    logger.warning("Using fallback trim (no LLM summary).")

    # Count findings mentioned in old messages
    tool_names: set[str] = set()
    for msg in old:
        if isinstance(msg, ToolMessage):
            tool_names.add(msg.name or "unknown")

    parts: list[str] = [
        "📋 **[Context Trimmed — Fallback]**\n",
        f"The conversation was trimmed to stay within context limits.",
        f"- {len(old)} older messages were removed",
        f"- Tools used: {', '.join(sorted(tool_names)) or 'none'}",
    ]

    # Preserve actual findings from agent state
    if agent_state:
        findings = agent_state.get("findings") or []
        patches = agent_state.get("patch_results") or []
        task = agent_state.get("task") or ""
        target_pkgs = agent_state.get("target_packages") or []
        scratchpad = agent_state.get("scratchpad") or {}
        task_plan = agent_state.get("task_plan") or []

        if task:
            parts.append(f"\n## Original Task\n{task}")

        if target_pkgs:
            parts.append(f"\n## Target Packages\n{', '.join(target_pkgs)}")

        if findings:
            parts.append(f"\n## Vulnerability Findings ({len(findings)} total)")
            by_sev: dict[str, list[dict]] = {}
            for f in findings:
                sev = f.get("severity", "info").upper()
                by_sev.setdefault(sev, []).append(f)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                items = by_sev.get(sev, [])
                if items:
                    parts.append(f"\n### {sev} ({len(items)})")
                    for item in items[:20]:
                        name = item.get("name", "unknown")
                        fpath = item.get("file", "")
                        cat = item.get("category", "")
                        parts.append(f"- **{name}** ({cat}) — `{fpath}`")

        if patches:
            ok = sum(1 for p in patches if p.get("success"))
            parts.append(f"\n## Patches Applied ({ok}/{len(patches)} successful)")
            for p in patches:
                status = "✅" if p.get("success") else "❌"
                target = p.get("target_file", "unknown")
                errors = p.get("errors", [])
                parts.append(f"- {status} `{target}` — {p.get('steps_applied', 0)} steps")
                if errors:
                    for err in errors[:3]:
                        parts.append(f"  - Error: {err}")

        if scratchpad:
            parts.append("\n## Working Memory (Scratchpad)")
            for k, v in list(scratchpad.items())[:20]:
                parts.append(f"- **{k}**: {str(v)[:300]}")

        if task_plan:
            parts.append("\n## Task Plan")
            for t in task_plan:
                status = t.get("status", "pending")
                icon = "✅" if status == "done" else "🔄" if status == "in_progress" else "⬜"
                parts.append(f"- {icon} [{t.get('id', '?')}] {t.get('desc', '')}")
    else:
        # No state available — fall back to counting message mentions
        finding_count = 0
        for msg in old:
            content = str(msg.content).lower()
            if "vulnerability" in content or "finding" in content or "critical" in content:
                finding_count += 1
        parts.append(f"- Approximate findings mentioned: {finding_count}")

    parts.append(
        "\n⚡ **AUTO-CONTINUE**: Review the findings and patches above, "
        "then continue working on the original task. Do NOT re-run tools "
        "whose results are already listed."
    )

    fallback_summary = HumanMessage(content="\n".join(parts))

    result: list[BaseMessage] = []
    if system_msg:
        result.append(system_msg)
    result.append(fallback_summary)
    result.extend(recent)
    return result
