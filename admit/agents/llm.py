"""LLM plumbing for the side agents: ADK ``LlmAgent`` + ``output_schema``, cached.

Every agent call goes through :func:`ask_json`:

* Live (default): an ADK ``LlmAgent`` with ``output_schema`` runs through an
  ``InMemoryRunner`` (3 tries with backoff on 429/503/network errors). Every
  response is written to ``.admit/cache/<sha256(model+instruction+prompt+schema)>.json``.
  If every try fails, a recorded answer for the same prompt is used instead.
* ``replay=True`` serves *only* from the cache (``.admit/cache/``, then the
  committed fixtures in ``tests/fixtures/llm-cache/``) and raises
  :class:`CacheMiss` on a miss: no network, so a rehearsed stage run is offline-safe.

Backend chosen by :func:`get_backend` (``ADMIT_LLM_BACKEND``, default ``gemini-api``):

* ``gemini-api`` -- the ``google-genai`` path. The key comes from ``GOOGLE_API_KEY`` /
  ``GEMINI_API_KEY`` or, if neither is set, the ``GEMINI_API_KEY`` line of the repo's
  ``.env`` (read by :func:`load_api_key`; the value is never printed or logged).
* ``agy`` -- :class:`AgyLlm`, an ADK ``BaseLlm`` that would shell out to the signed-in
  ``agy -p`` CLI (plan section 9). Stub: not required for the demo.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import warnings
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.base_llm import BaseLlm
from pydantic import BaseModel

if TYPE_CHECKING:
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse

DEFAULT_MODEL = "gemini-3.8-flash"
CACHE_DIR = Path(".admit/cache")
#: Committed responses from rehearsal runs: tests and a fresh clone replay these.
FIXTURE_CACHE_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "llm-cache"
RETRIES = 3

#: Per-process counters, shown in the CLI summary (cache hits vs live calls).
STATS: dict[str, float] = {
    "live_calls": 0,
    "live_seconds": 0.0,
    "cache_hits": 0,
    "fallbacks": 0,
    "errors": 0,
}


class CacheMiss(RuntimeError):
    """``--replay`` asked for a response that was never recorded."""


class LlmUnavailable(RuntimeError):
    """The live model failed after every retry and nothing was cached."""


def get_backend() -> str:
    """Return the LLM backend: ``ADMIT_LLM_BACKEND``, default ``gemini-api``."""
    return os.environ.get("ADMIT_LLM_BACKEND", "gemini-api")


def model_for(role: str) -> str:
    """Model id for an agent role (``redteam`` | ``author``) from ``ADMIT_MODEL_<ROLE>``."""
    return os.environ.get(f"ADMIT_MODEL_{role.upper()}", DEFAULT_MODEL)


def quiet_adk_warnings() -> None:
    """Hide ADK's deprecation/experimental chatter (LoopAgent -> Workflow) on stage."""
    warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"google\.adk.*")
    warnings.filterwarnings("ignore", message=r".*deprecated in favor of Workflow.*")
    warnings.filterwarnings("ignore", category=UserWarning, module=r"google\.adk.*")
    import logging

    for name in ("google_adk", "google.adk", "google_genai", "google.genai"):
        logging.getLogger(name).setLevel(logging.CRITICAL)


# -- API key ------------------------------------------------------------------


def load_api_key(env_file: Path = Path(".env")) -> bool:
    """Make a Gemini key available to google-genai without ever echoing it.

    Returns True when a key is set. Only the ``GEMINI_API_KEY`` line is parsed;
    other ``.env`` values are never read into the process.
    """
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "FALSE")
    if os.environ.get("GOOGLE_API_KEY"):
        return True
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        candidates = [env_file, Path(__file__).resolve().parents[2] / ".env"]
        for path in candidates:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                name, sep, value = line.strip().partition("=")
                if sep and name.strip().removeprefix("export ").strip() == "GEMINI_API_KEY":
                    key = value.strip().strip("'\"")
                    break
            if key:
                break
    if not key:
        return False
    os.environ["GOOGLE_API_KEY"] = key
    return True


# -- cache --------------------------------------------------------------------


def cache_key(model: str, instruction: str, prompt: str, schema: type[BaseModel]) -> str:
    material = "\n\x00".join([model, schema.__name__, instruction, prompt])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_dirs(cache_dir: Path) -> list[Path]:
    dirs = [cache_dir]
    if FIXTURE_CACHE_DIR.resolve() != cache_dir.resolve():
        dirs.append(FIXTURE_CACHE_DIR)
    return dirs


def cache_get(key: str, cache_dir: Path = CACHE_DIR) -> str | None:
    for directory in _cache_dirs(cache_dir):
        path = directory / f"{key}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return None


def cache_put(key: str, model: str, agent: str, response: str, cache_dir: Path = CACHE_DIR) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{key}.json"
    record = {"model": model, "agent": agent, "created": time.time(), "response": response}
    path.write_text(json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8")
    return path


# -- live call ----------------------------------------------------------------


def _generate_config() -> Any:
    from google.genai import types

    level = os.environ.get("ADMIT_THINKING", "low").upper()
    try:
        return types.GenerateContentConfig(
            temperature=1.0, thinking_config=types.ThinkingConfig(thinking_level=level)
        )
    except Exception:  # noqa: BLE001 - older SDK / unknown level: model default
        return types.GenerateContentConfig(temperature=1.0)


async def _run_agent(
    name: str, model: str, instruction: str, prompt: str, schema: type[BaseModel]
) -> str:
    from google.adk.agents import LlmAgent
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    agent = LlmAgent(
        name=name,
        model=create_llm(model),
        # A callable skips ADK's {state} templating: our prompts contain literal braces.
        instruction=lambda _ctx: instruction,
        output_schema=schema,
        generate_content_config=_generate_config(),
    )
    runner = InMemoryRunner(agent=agent, app_name="admit")
    session = await runner.session_service.create_session(app_name="admit", user_id="admit")
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    chunks: list[str] = []
    async for event in runner.run_async(
        user_id="admit", session_id=session.id, new_message=message
    ):
        if event.is_final_response() and event.content and event.content.parts:
            chunks.append("".join(p.text or "" for p in event.content.parts if not p.thought))
    text = "".join(chunks).strip()
    if not text:
        raise LlmUnavailable(f"{name}: empty response from {model}")
    return text


def _parse[T: BaseModel](schema: type[T], text: str) -> T:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    return schema.model_validate_json(text)


async def ask_json_async[T: BaseModel](
    agent: str,
    instruction: str,
    prompt: str,
    schema: type[T],
    *,
    model: str | None = None,
    replay: bool = False,
    cache_dir: Path = CACHE_DIR,
) -> T:
    """One structured agent call: live with cache fallback, or ``replay``-only."""
    model = model or DEFAULT_MODEL
    key = cache_key(model, instruction, prompt, schema)
    if replay:
        cached = cache_get(key, cache_dir)
        if cached is None:
            raise CacheMiss(
                f"--replay: no cached {agent} response for this prompt (key {key[:12]}). "
                "Run once without --replay to record it."
            )
        STATS["cache_hits"] += 1
        return _parse(schema, cached)
    last: Exception | None = None
    if get_backend() == "gemini-api" and not load_api_key():
        last = LlmUnavailable("no Gemini API key: set GEMINI_API_KEY (or .env), or use --replay")
    else:
        quiet_adk_warnings()
        for attempt in range(RETRIES):
            started = time.monotonic()
            try:
                text = await _run_agent(agent, model, instruction, prompt, schema)
                result = _parse(schema, text)
            except Exception as exc:  # noqa: BLE001 - 429/503/network/bad JSON: retry
                last = exc
                STATS["errors"] += 1
                if attempt + 1 < RETRIES:
                    await asyncio.sleep(2.0 * (2**attempt))
                continue
            STATS["live_calls"] += 1
            STATS["live_seconds"] += time.monotonic() - started
            cache_put(key, model, agent, text, cache_dir)
            return result
    cached = cache_get(key, cache_dir)  # live failed: a recorded answer beats no answer
    if cached is not None:
        STATS["fallbacks"] += 1
        return _parse(schema, cached)
    raise LlmUnavailable(f"{agent}: {model} unavailable and not cached: {_short(last)}")


def ask_json[T: BaseModel](
    agent: str, instruction: str, prompt: str, schema: type[T], **kwargs: Any
) -> T:
    """Synchronous wrapper around :func:`ask_json_async`."""
    return asyncio.run(ask_json_async(agent, instruction, prompt, schema, **kwargs))


def _short(exc: BaseException | None) -> str:
    text = f"{type(exc).__name__}: {exc}" if exc else "unknown error"
    return text.splitlines()[0][:300]


# -- backends -----------------------------------------------------------------


class AgyLlm(BaseLlm):
    """LLM that answers through ``agy -p`` in headless ``--mode plan`` (stub, optional)."""

    model: str

    def capabilities(self) -> LlmCapabilities:
        """Declare capabilities outright (avoids the deprecated name-based fallback)."""
        return LlmCapabilities(output_schema_and_tools=False)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        """Flatten the request into one prompt and run ``agy -p ...`` per plan section 9."""
        raise NotImplementedError("AgyLlm is not implemented; use ADMIT_LLM_BACKEND=gemini-api")
        yield  # pragma: no cover - makes this an async generator


def create_llm(model: str | None = None) -> BaseLlm | str:
    """Factory: the model for an ``LlmAgent``, per :func:`get_backend`.

    ``gemini-api`` returns the plain model id (ADK resolves it to its Gemini
    class); ``agy`` returns an :class:`AgyLlm`.
    """
    model = model or DEFAULT_MODEL
    if get_backend() == "agy":
        return AgyLlm(model=model)
    return model
