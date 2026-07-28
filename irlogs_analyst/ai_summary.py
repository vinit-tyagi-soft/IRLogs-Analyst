from __future__ import annotations

import os
from typing import Any


def maybe_generate_ai_summary(enabled: bool, payload: dict[str, Any]) -> str | None:
    if not enabled:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return None

    client = OpenAI(api_key=api_key)
    prompt = (
        "You are an incident response analyst. Summarize the investigation findings. "
        "Answer what happened, how it likely happened, and why this assessment is reasonable. "
        "Keep it concise, evidence-based, and avoid speculation."
        f"\n\nData:\n{payload}"
    )
    try:
        response = client.responses.create(
            model=os.getenv("IRLOGS_OPENAI_MODEL", "gpt-4.1-mini"),
            input=prompt,
            temperature=0.2,
        )
        return getattr(response, "output_text", None)
    except Exception:
        return None
