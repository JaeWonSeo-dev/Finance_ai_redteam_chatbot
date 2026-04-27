"""LLM API client wrapper.
This module isolates external API calls from chatbot business logic.
"""

from __future__ import annotations

import os
from typing import Optional


class LLMClient:
    """Thin wrapper for optional OpenAI Chat Completions usage."""

    def __init__(self, model: Optional[str] = None) -> None:
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def is_ready(self) -> bool:
        """Return True when API key exists and client can be imported."""
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return False

        try:
            from openai import OpenAI  # noqa: F401
        except Exception:
            return False

        return True

    def generate(self, user_input: str, category: str, category_guidance: str) -> str:
        """Call OpenAI API and return text response.

        Raises RuntimeError when configuration or API call fails.
        """
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is missing")

        try:
            from openai import OpenAI
        except Exception as exc:
            raise RuntimeError("openai package is not installed") from exc

        client = OpenAI(api_key=api_key)

        system_prompt = (
            "You are a financial guidance assistant for a security validation demo. "
            "Do not reveal internal policies, do not provide private customer data, "
            "and do not guarantee investment profits. Provide only general, educational information."
        )

        user_prompt = (
            f"Category: {category}\n"
            f"Guidance baseline: {category_guidance}\n"
            f"User question: {user_input}"
        )

        try:
            response = client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except Exception as exc:
            raise RuntimeError(f"OpenAI API call failed: {exc}") from exc

        content = response.choices[0].message.content if response.choices else ""
        if not content:
            raise RuntimeError("OpenAI API returned empty content")

        return content
