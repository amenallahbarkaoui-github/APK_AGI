"""Auto-compact — summarize conversation context when it grows too large.

When the message history exceeds a token threshold (default 200 000 tokens),
the compactor:

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

# Configurable thresholds
DEFAULT_TOKEN_THRESHOLD = 90_000  # Start compacting when conversation exceeds this many tokens
KEEP_RECENT_MESSAGES = 30  # Keep the last N messages for immediate context
MIN_MESSAGES_TO_COMPACT = 40  # Don't compact if fewer messages than this


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

    def should_compact(self, messages: list[BaseMessage]) -> bool:
        """Check if the conversation needs compaction."""
        if len(messages) < MIN_MESSAGES_TO_COMPACT:
            return False

        self.last_token_count = count_message_tokens(messages)
        return self.last_token_count >= self.token_threshold

    def estimate_tokens(self, messages: list[BaseMessage]) -> int:
        """Estimate token count without storing it."""
        return count_message_tokens(messages)

    def compact(self, messages: list[BaseMessage], llm) -> list[BaseMessage]:
        """Compact the conversation by summarizing old messages.

        Args:
            messages: Full message list from the agent state
            llm: The LLM instance to use for summarization

        Returns:
            New message list: [SystemPrompt, CompactSummary, ...recent_messages]
        """
        logger.info(
            "Auto-compacting conversation: %d messages, ~%d tokens",
            len(messages),
            self.last_token_count or count_message_tokens(messages),
        )

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

        # Build summary prompt
        compact_prompt = build_compact_prompt(old_messages)

        try:
            # Use LLM to summarize
            summary_response = llm.invoke([
                SystemMessage(content=COMPACT_SYSTEM_PROMPT),
                HumanMessage(content=compact_prompt),
            ])

            summary_text = summary_response.content
            if not summary_text or not summary_text.strip():
                logger.warning("Compactor returned empty summary. Skipping.")
                return messages

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
                _fallback_trim(messages, system_msg, recent_messages, old_messages)
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
) -> list[BaseMessage]:
    """Fallback when LLM compaction fails — trim with a basic text summary."""
    logger.warning("Using fallback trim (no LLM summary).")

    # Count findings mentioned in old messages
    finding_count = 0
    tool_names: set[str] = set()
    for msg in old:
        if isinstance(msg, ToolMessage):
            tool_names.add(msg.name or "unknown")
        content = str(msg.content).lower()
        if "vulnerability" in content or "finding" in content or "critical" in content:
            finding_count += 1

    fallback_summary = HumanMessage(
        content=(
            f"📋 **[Context Trimmed — Fallback]**\n\n"
            f"The conversation was trimmed to stay within context limits.\n"
            f"- {len(old)} older messages were removed\n"
            f"- Tools used: {', '.join(sorted(tool_names)) or 'none'}\n"
            f"- Approximate findings mentioned: {finding_count}\n\n"
            f"Recent context preserved below. Review the project files and "
            f"tool outputs if you need to recall earlier analysis results."
        )
    )

    result: list[BaseMessage] = []
    if system_msg:
        result.append(system_msg)
    result.append(fallback_summary)
    result.extend(recent)
    return result
