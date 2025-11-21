from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any

from google import genai
from google.genai import types as genai_types

from env_utils import load_env_from_dotenv

logger = logging.getLogger("podrush.gemini")
load_env_from_dotenv()
MODEL_NAME = os.getenv("GEMINI_MODEL") or "gemini-2.5-flash"


def _api_key() -> str | None:
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")


@lru_cache(maxsize=1)
def _client() -> genai.Client | None:
    api_key = _api_key()
    if not api_key:
        logger.info("No Gemini API key found; AI shorthands disabled.")
        return None
    try:
        logger.info("Initializing Gemini client for shorthand generation.")
        return genai.Client(api_key=api_key)
    except Exception as exc:
        logger.warning("Failed to initialize Gemini client: %s", exc)
        return None


def _build_prompt(kind: str, title: str, detail: str | None) -> str:
    lines = [
        f"Create a terse filesystem-safe nickname for a {kind}.",
        "Goal: about 8-24 characters, human-style shorthand.",
        "Acceptable separators: dash or underscore; no spaces or punctuation otherwise.",
        "Do NOT repeat the title verbatim; compress or abbreviate it instead.",
        "Drop filler like podcast, episode, official, the.",
        "Prefer 2-4 tokens; blend words if it keeps things short.",
        "Return only the nickname through JSON, no explanations.",
        f"Title: {title}",
    ]
    if detail:
        lines.append(f"Context (podcast name etc.): {detail}")
    return "\n".join(lines)


def _parse_candidate(response: Any) -> str | None:
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, dict):
        candidate = parsed.get("shorthand") or parsed.get("short")
        if isinstance(candidate, str):
            return candidate.strip()
    if isinstance(parsed, str):
        return parsed.strip()

    raw_text = (getattr(response, "text", "") or "").strip()
    if not raw_text:
        return None
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text
    if isinstance(loaded, dict):
        candidate = loaded.get("shorthand") or loaded.get("short")
        if isinstance(candidate, str):
            return candidate.strip()
    if isinstance(loaded, str):
        return loaded.strip()
    return None


def ai_short_name(kind: str, title: str, detail: str | None = None) -> str | None:
    client = _client()
    if not client:
        return None

    prompt = _build_prompt(kind, title, detail)
    config = genai_types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=genai_types.Schema(
            type=genai_types.Type.OBJECT,
            properties={
                "shorthand": genai_types.Schema(
                    type=genai_types.Type.STRING,
                    description="Terse, filesystem-friendly nickname with dash/underscore allowed.",
                )
            },
            required=["shorthand"],
        ),
    )

    try:
        logger.info("Requesting Gemini shorthand for %s: %s", kind, title)
        response = client.models.generate_content(
            model=MODEL_NAME, contents=prompt, config=config
        )
    except Exception as exc:
        logger.warning("Gemini request failed: %s", exc)
        return None

    shorthand = _parse_candidate(response)
    logger.info("Gemini shorthand candidate: %s", shorthand)
    return shorthand


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    load_env_from_dotenv()
    sample = "Example Podcast: Tech & Culture"
    nickname = ai_short_name("podcast", sample)
    print(f"Input: {sample}")
    print(f"Shorthand: {nickname}")
