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

Your job: Take a long conversation history and produce a **dense, structured summary** that preserves ALL important context.

The summary MUST include:
1. **Project Info**: APK name, package name, target SDK, key metadata
2. **Task**: The user's original request / goal
3. **Analysis Done**: What tools were run, what was analyzed
4. **Key Findings**: ALL security vulnerabilities found (severity, file, description)
5. **Patches Applied**: Any smali patches that were created or applied
6. **Current State**: What the agent was in the middle of doing
7. **Pending Work**: What still needs to be done
8. **Important File Paths**: Key files referenced in the analysis
9. **Tool Results Summary**: Brief summary of each significant tool result

Format the summary as structured Markdown with clear sections.
Be thorough — the agent will use this summary to continue working without the original messages.
Do NOT lose any vulnerability findings, file paths, or analysis results."""


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
                    f"were condensed into this summary. Use it to continue your analysis.\n\n"
                    f"---\n\n{summary_text}\n\n---\n\n"
                    f"Continue from where the analysis left off. The recent messages below show your last actions."
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

            return new_messages

        except Exception as e:
            logger.error("Auto-compact failed: %s", e)
            # Fallback: just trim old messages without LLM summary
            return _fallback_trim(messages, system_msg, recent_messages, old_messages)

    def get_stats(self) -> dict[str, Any]:
        """Return compactor statistics."""
        return {
            "compact_count": self.compact_count,
            "last_token_count": self.last_token_count,
            "token_threshold": self.token_threshold,
            "keep_recent": self.keep_recent,
        }


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
