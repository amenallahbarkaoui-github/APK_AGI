"""LLM provider — configurable OpenAI-compatible API."""

from __future__ import annotations

import contextlib
import json as _json
from collections import deque
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from apk_agent.config import AppConfig

import httpx
from langchain_openai import ChatOpenAI

from apk_agent.config import normalize_api_base_url

# ---------------------------------------------------------------------------
# Reasoning / thinking content capture
# ---------------------------------------------------------------------------
# Many providers (Nine Router, DeepSeek, GLM) return model reasoning in
# non-standard fields (``reasoning_text``, ``reasoning_content``,
# ``thinking``).  The OpenAI SDK drops these since they're not in the
# Pydantic model.  We capture them at the HTTP layer and expose via
# ``pop_last_reasoning()`` so the CLI can render them in a blue box.
# ---------------------------------------------------------------------------
_reasoning_buffer_var: ContextVar[deque[str] | None] = ContextVar(
    "apk_agent_reasoning_buffer",
    default=None,
)
_reasoning_capture_enabled: ContextVar[bool] = ContextVar(
    "apk_agent_reasoning_capture_enabled",
    default=True,
)

_QUOTA_EXHAUSTED_MARKERS = (
    "usage limit reached",
    "insufficient_quota",
    "quota exhausted",
    "quota exceeded",
    "api key limit",
    "credit balance",
    "out of credits",
    "not enough credits",
    "billing hard limit",
    "spending limit",
    "plan limit reached",
)

_RETRYABLE_API_MARKERS = (
    "429",
    "rate_limit",
    "rate limit",
    "502",
    "bad gateway",
    "fetch failed",
    "503",
    "service unavailable",
    "overloaded",
    "500",
    "internal server error",
    "tool name is required",
    "must be in json format",
    "invalidparameter",
    "invalid_parameter_error",
    "tool_call_id",
    "is not found",
)


def _get_reasoning_buffer() -> deque[str]:
    """Return the current logical reasoning buffer for this execution flow."""
    buffer = _reasoning_buffer_var.get()
    if buffer is None:
        buffer = deque(maxlen=20)
        _reasoning_buffer_var.set(buffer)
    return buffer

# ---------------------------------------------------------------------------
# Fixes for aimlapi.com proxy compatibility
# ---------------------------------------------------------------------------
# Fix 1: Some providers reject null ``content`` on assistant tool-call
#         messages.  Patch _convert_message_to_dict to default to "".
# Fix 2: For thinking/reasoning models (Claude, Kimi K2, …) the proxy
#         requires ``reasoning_content`` on every assistant message.
#         A custom httpx Client subclass injects it at send()-time so the
#         field survives all upstream serialisation.
# ---------------------------------------------------------------------------
import langchain_openai.chat_models.base as _oai_base

# -- Fix 1 --------------------------------------------------------------------
_original_convert = _oai_base._convert_message_to_dict


def _patched_convert_message_to_dict(
    message,
    api: Literal["chat/completions", "responses"] = "chat/completions",
):
    result = _original_convert(message, api=api)
    if result.get("content") is None:
        result["content"] = ""
    return result


_oai_base._convert_message_to_dict = _patched_convert_message_to_dict


# -- Fix 2 --------------------------------------------------------------------
def pop_last_reasoning() -> str | None:
    """Pop the most recent reasoning/thinking text captured from the API.

    Returns *None* if there is nothing to show.  Called by the CLI after
    each AIMessage to render the blue thinking panel.
    """
    buffer = _get_reasoning_buffer()
    return buffer.popleft() if buffer else None


def is_quota_exhausted_error(error: object) -> bool:
    """Return True for non-retryable provider quota or usage-limit errors."""
    err_str = str(error).lower()
    if any(marker in err_str for marker in _QUOTA_EXHAUSTED_MARKERS):
        return True

    quota_hints = ("quota", "credits", "credit", "balance", "billing")
    if any(hint in err_str for hint in quota_hints) and any(code in err_str for code in ("403", "429", "forbidden", "limit")):
        return True

    return False


def is_retryable_api_error(error: object) -> bool:
    """Return True only for transient API errors worth retrying."""
    err_str = str(error).lower()
    if is_quota_exhausted_error(err_str):
        return False
    return any(marker in err_str for marker in _RETRYABLE_API_MARKERS)


@contextlib.contextmanager
def suppress_reasoning_capture():
    """Temporarily disable reasoning capture for internal/background LLM calls."""
    token = _reasoning_capture_enabled.set(False)
    try:
        yield
    finally:
        _reasoning_capture_enabled.reset(token)


class _PatchedHttpClient(httpx.Client):
    """Patches outgoing requests for Z.AI / AIML API compatibility:
    1. Injects ``reasoning_content`` on assistant messages (required by proxy)
    2. Injects ``thinking`` parameter for deep thinking models
    3. Captures ``reasoning_text`` / ``reasoning_content`` from responses
    """

    _enable_thinking: bool = False
    _capture_reasoning: bool = True

    def send(self, request, **kwargs):
        if (
            request.method == "POST"
            and "/chat/completions" in str(request.url)
            and request.content
        ):
            try:
                body = _json.loads(request.content)
                if isinstance(body, dict) and "messages" in body:
                    modified = False
                    for msg in body["messages"]:
                        if (
                            isinstance(msg, dict)
                            and msg.get("role") == "assistant"
                            and not msg.get("reasoning_content")
                        ):
                            msg["reasoning_content"] = "."
                            modified = True
                    # Inject thinking parameter into the request body
                    if self._enable_thinking and "thinking" not in body:
                        body["thinking"] = {"type": "enabled"}
                        modified = True
                    if modified:
                        new_bytes = _json.dumps(
                            body, ensure_ascii=False
                        ).encode("utf-8")
                        request._content = new_bytes
                        request.stream = httpx.ByteStream(new_bytes)
                        request.headers["content-length"] = str(
                            len(new_bytes)
                        )
            except Exception:
                pass

        response = super().send(request, **kwargs)

        # ── Capture reasoning from the response ──────────────────────
        if (
            self._capture_reasoning
            and _reasoning_capture_enabled.get()
            and request.method == "POST"
            and "/chat/completions" in str(request.url)
        ):
            try:
                data = response.json()
                for choice in (data.get("choices") or []):
                    msg = choice.get("message") or choice.get("delta") or {}
                    # Providers use different field names
                    reasoning = (
                        msg.get("reasoning_text")
                        or msg.get("reasoning_content")
                        or msg.get("thinking")
                    )
                    if reasoning and isinstance(reasoning, str) and reasoning.strip():
                        _get_reasoning_buffer().append(reasoning.strip())
            except Exception:
                pass

        return response


# ---------------------------------------------------------------------------
# Default context window when user doesn't set one
# ---------------------------------------------------------------------------
_FALLBACK_CONTEXT_WINDOW = 128_000


def _model_supports_thinking(model_name: str) -> bool:
    """Return True when the provider/model pair is known to accept `thinking`."""
    model_lower = (model_name or "").lower()
    return any(tag in model_lower for tag in ("glm-5", "glm-4.7", "glm-4.6", "glm-4.5"))


def _recommended_max_output_tokens(model_name: str, context_window: int) -> int:
    """Pick a safe output budget using model-family hints and the active context window."""
    model_lower = (model_name or "").lower()

    if any(tag in model_lower for tag in (
        "claude", "anthropic", "glm-5", "glm-4", "gemini-2.5",
        "deepseek-r1", "deepseek-reasoner",
    )):
        base_limit = 65_536
    else:
        base_limit = 32_768

    effective_context = context_window if context_window and context_window > 0 else _FALLBACK_CONTEXT_WINDOW
    context_cap = max(4_096, min(65_536, effective_context // 2))
    return min(base_limit, context_cap)


def get_llm(
    config: "AppConfig",
    temperature: float = 1.0,
    *,
    capture_reasoning: bool = True,
    enable_thinking: bool | None = None,
) -> ChatOpenAI:
    """Return a ChatOpenAI model pointed at the configured API.

    Works with any OpenAI-compatible API (AIML API, OpenRouter,
    local Ollama, etc.) — just set API_BASE_URL in .env.
    """
    if not config.api_key:
        raise ValueError(
            "API_KEY not set in .env. "
            "Set your AIML API key or other provider key."
        )
    if not config.api_base_url:
        raise ValueError(
            "API_BASE_URL not set in .env. "
            "Set the provider base URL explicitly."
        )
    if not config.model_name:
        raise ValueError(
            "MODEL_NAME not set in .env. "
            "Set the model explicitly."
        )

    api_base_url, _ = normalize_api_base_url(config.api_base_url)
    if not api_base_url:
        raise ValueError(
            "API_BASE_URL not set in .env. "
            "Set the provider base URL explicitly."
        )

    model_supports_thinking = _model_supports_thinking(config.model_name)
    thinking_enabled = model_supports_thinking if enable_thinking is None else bool(enable_thinking and model_supports_thinking)

    http_client = _PatchedHttpClient(timeout=httpx.Timeout(10.0, read=300.0))
    http_client._enable_thinking = thinking_enabled
    http_client._capture_reasoning = capture_reasoning

    max_tokens = _recommended_max_output_tokens(config.model_name, config.context_window)

    llm_kwargs: dict[str, Any] = {
        "model": config.model_name,
        "api_key": config.api_key,
        "base_url": api_base_url,
        "temperature": 1.0 if model_supports_thinking else temperature,
        "max_tokens": max_tokens,
        "http_client": http_client,
    }
    return ChatOpenAI(**llm_kwargs)
