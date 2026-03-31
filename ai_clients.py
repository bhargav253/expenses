from __future__ import annotations

import json
import re
from typing import Any, Optional

import requests


AI_MODELS = {
    "deepseek": {
        "name": "DeepSeek",
        "api_url": "https://api.deepseek.com/v1/chat/completions",
        "model_name": "deepseek-chat",
        "api_key_field": "deepseek_api_key",
    },
    "mistral": {
        "name": "Mistral",
        "api_url": "https://api.mistral.ai/v1/chat/completions",
        "model_name": "mistral-large-latest",
        "api_key_field": "mistral_api_key",
    },
    "openai": {
        "name": "OpenAI",
        "api_url": "https://api.openai.com/v1/chat/completions",
        "model_name": "gpt-4",
        "api_key_field": "openai_api_key",
    },
}


def _extract_json_object(text: str) -> Optional[dict[str, Any]]:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None


def resolve_model_config(user):
    model_key = getattr(user, "default_ai_provider", None) or "mistral"
    model_config = AI_MODELS.get(model_key)
    if not model_config:
        return None, None, None
    api_key = user.get_decrypted_api_key(model_config["api_key_field"])
    if not api_key:
        return model_key, model_config, None
    return model_key, model_config, api_key


def extract_usage_payload(response_json: dict[str, Any]) -> Optional[dict[str, int]]:
    usage = response_json.get("usage") or {}
    if not usage:
        return None
    prompt_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    total_tokens = usage.get("total_tokens") or (prompt_tokens + completion_tokens)
    return {
        "input_tokens": int(prompt_tokens or 0),
        "output_tokens": int(completion_tokens or 0),
        "total_tokens": int(total_tokens or 0),
    }


def call_chat_completion(user, system_prompt: str, user_payload: str, *, max_tokens: int = 800, temperature: float = 0.2, expect_json: bool = False, timeout: int = 25):
    model_key, model_config, api_key = resolve_model_config(user)
    if not model_config or not api_key:
        return None

    payload = {
        "model": model_config["model_name"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    response = requests.post(model_config["api_url"], headers=headers, data=json.dumps(payload), timeout=timeout)
    response.raise_for_status()
    response_json = response.json()
    content = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
    parsed_content: Any = _extract_json_object(content) if expect_json else content
    return {
        "content": parsed_content,
        "raw_content": content,
        "provider": model_key,
        "provider_label": model_config["name"],
        "model": model_config["model_name"],
        "usage": extract_usage_payload(response_json),
    }
