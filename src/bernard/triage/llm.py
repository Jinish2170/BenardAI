"""OpenAI-compatible LLM client (defaults to NVIDIA NIM)."""
from __future__ import annotations
import asyncio
from openai import OpenAI

from ..config import CONFIG, require_llm

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    require_llm()
    if _client is None:
        _client = OpenAI(api_key=CONFIG.llm.api_key, base_url=CONFIG.llm.base_url)
    return _client


def get_model() -> str:
    return CONFIG.llm.model


async def chat(*, system: str, user: str, json_mode: bool = False,
               temperature: float | None = None, max_tokens: int | None = None) -> str:
    """Send a chat request. Runs sync OpenAI call in a thread to keep API non-blocking."""
    def _call() -> str:
        client = _get_client()
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        kwargs = {
            "model": CONFIG.llm.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else CONFIG.llm.temperature,
            "max_tokens": max_tokens if max_tokens is not None else CONFIG.llm.max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = client.chat.completions.create(**kwargs)
        return (resp.choices[0].message.content or "").strip()

    return await asyncio.to_thread(_call)
