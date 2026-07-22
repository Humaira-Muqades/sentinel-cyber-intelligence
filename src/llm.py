"""Groq inference wrapper.

One place to configure the model, so agents stay focused on their prompts.
"""

import os
import json
import re
from typing import Any, Dict, List, Optional

from groq import Groq
from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "4096"))

_client: Optional[Groq] = None


def client() -> Groq:
    """Lazily create the Groq client so imports don't fail without a key."""
    global _client
    if _client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Copy .env.example to .env "
                "and add your key from https://console.groq.com"
            )
        _client = Groq(api_key=key)
    return _client


def complete(system: str, user: str, json_mode: bool = False) -> str:
    """Send a single-turn request and return the text response."""
    kwargs: Dict[str, Any] = {
        "model": MODEL,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    response = client().chat.completions.create(**kwargs)
    return response.choices[0].message.content or ""


def _strip_fences(text: str) -> str:
    """Remove ```json fences if the model adds them despite instructions."""
    return re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()


def complete_json(system: str, user: str, key: str) -> List[Dict[str, Any]]:
    """Request JSON and return the list stored under `key`.

    Returns an empty list rather than raising, so one bad response
    doesn't take down the whole pipeline.
    """
    raw = complete(system, user, json_mode=True)
    try:
        data = json.loads(_strip_fences(raw))
    except json.JSONDecodeError:
        return []

    value = data.get(key, [])
    return value if isinstance(value, list) else []
