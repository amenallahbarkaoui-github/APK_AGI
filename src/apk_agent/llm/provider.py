"""LLM provider — configurable OpenAI-compatible API."""

from __future__ import annotations

import json as _json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.config import AppConfig

import httpx
from langchain_openai import ChatOpenAI

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


def _patched_convert_message_to_dict(message, api="chat/completions"):
    result = _original_convert(message, api=api)
    if result.get("content") is None:
        result["content"] = ""
    return result


_oai_base._convert_message_to_dict = _patched_convert_message_to_dict


# -- Fix 2 --------------------------------------------------------------------
class _PatchedHttpClient(httpx.Client):
    """Injects ``reasoning_content`` into assistant messages at send()-time."""

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
        return super().send(request, **kwargs)


def get_llm(config: "AppConfig", temperature: float = 1.0) -> ChatOpenAI:
    """Return a ChatOpenAI model pointed at the configured API.

    Works with any OpenAI-compatible API (AIML API, OpenRouter,
    local Ollama, etc.) — just set API_BASE_URL in .env.
    """
    if not config.api_key:
        raise ValueError(
            "API_KEY not set in .env. "
            "Set your AIML API key or other provider key."
        )

    return ChatOpenAI(
        model=config.model_name,
        api_key=config.api_key,
        base_url=config.api_base_url,
        temperature=temperature,
        max_tokens=4096,
        http_client=_PatchedHttpClient(),
    )
