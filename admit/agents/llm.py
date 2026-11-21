"""AgyLlm: ADK BaseLlm that answers through the signed-in ``agy`` CLI.

Backend chosen by :func:`get_backend` (``ADMIT_LLM_BACKEND``, default ``agy``):

* ``agy``        -- shell out to ``agy -p "<prompt>" --model <slug> --output-format json
                     --json-schema <schema> --print-timeout 2m`` in an empty temp dir,
                     ``--mode plan`` so the model cannot touch files. Uses the developer's
                     signed-in Antigravity quota through Google's own CLI: no AI Studio key.
* ``gemini-api`` -- the original ``google-genai`` path with ``GOOGLE_API_KEY`` (fallback).

The side agents stay ADK ``LlmAgent``s; only the model behind them changes.
Subclassing BaseLlm directly is slightly awkward (it is a pydantic BaseModel
with an abstract async method); if it proves awkward in M0, keep a plain class
here and wire ADK ``LlmAgent``s to it manually -- note the fallback in get_backend().
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.base_llm import BaseLlm

if TYPE_CHECKING:
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse


def get_backend() -> str:
    """Return the LLM backend: ``ADMIT_LLM_BACKEND``, default ``agy``."""
    return os.environ.get("ADMIT_LLM_BACKEND", "agy")


class AgyLlm(BaseLlm):
    """LLM that answers through ``agy -p`` in headless ``--mode plan``."""

    model: str

    def capabilities(self) -> LlmCapabilities:
        """Declare capabilities outright (avoids the deprecated name-based fallback)."""
        return LlmCapabilities(output_schema_and_tools=False)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        """Flatten the request into one prompt and run ``agy -p ...`` per plan section 9."""
        raise NotImplementedError


def create_llm() -> BaseLlm:
    """Factory: AgyLlm or the gemini-api path, per :func:`get_backend`."""
    raise NotImplementedError
