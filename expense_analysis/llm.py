from __future__ import annotations

import json
from typing import Any, Optional

from ai_clients import call_chat_completion
from models import EXPENSE_CATEGORIES


SUPPORTED_WORKFLOWS = [
    "category_trend",
    "category_vs_category",
    "category_breakdown",
    "what_changed",
    "who_spent_what",
    "recurring_charges",
    "merchant_trend",
    "outlier_expenses",
    "savings_opportunities",
    "monthly_review",
]


def _normalize_category(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = str(value).strip().lower()
    return cleaned if cleaned in EXPENSE_CATEGORIES else None


def llm_plan_request(user, prompt: str):
    system_prompt = f"""
You normalize expense-analysis requests for a finance app.
Return JSON only.

Allowed workflows: {", ".join(SUPPORTED_WORKFLOWS)}
Allowed categories: {", ".join(EXPENSE_CATEGORIES)}
Allowed artifact_preference: line_chart, bar_chart, pie_chart, table, stat_grid, null

Rules:
- Infer the user's intended workflow.
- Fix obvious category typos.
- Prefer category_vs_category when two categories are compared.
- Prefer category_trend for one category over time.
- Prefer category_breakdown for pie/share/top category requests.
- Do not invent numeric results.
"""
    user_payload = json.dumps({"prompt": prompt})
    response = call_chat_completion(user, system_prompt, user_payload, max_tokens=350, temperature=0.0, expect_json=True)
    if not response or not isinstance(response.get("content"), dict):
        return None
    content = response["content"]
    planned = {
        "workflow": content.get("workflow"),
        "category_a": _normalize_category(content.get("category_a")),
        "category_b": _normalize_category(content.get("category_b")),
        "merchant": content.get("merchant"),
        "artifact_preference": content.get("artifact_preference"),
    }
    if planned["workflow"] not in SUPPORTED_WORKFLOWS:
        return None
    response["content"] = planned
    return response


def llm_merge_request(user, prompt: str, previous_request: dict[str, Any]):
    system_prompt = f"""
You merge a follow-up expense-analysis request with the prior normalized request for a finance app.
Return JSON only.

Allowed workflows: {", ".join(SUPPORTED_WORKFLOWS)}
Allowed categories: {", ".join(EXPENSE_CATEGORIES)}
Allowed artifact_preference: line_chart, bar_chart, pie_chart, table, stat_grid, null

Rules:
- Treat the follow-up as an edit to the prior request unless it clearly replaces the whole request.
- Preserve the prior date range if the follow-up does not specify a new one.
- If the follow-up says add/include categories, append them to the prior categories.
- If the follow-up says remove/drop categories, remove them from the prior categories.
- If multiple categories remain, use category_vs_category.
- If exactly one category remains, use category_trend.
- Do not invent numeric results.
"""
    user_payload = json.dumps({"previous_request": previous_request, "follow_up_prompt": prompt}, default=str)
    response = call_chat_completion(user, system_prompt, user_payload, max_tokens=450, temperature=0.0, expect_json=True)
    if not response or not isinstance(response.get("content"), dict):
        return None
    content = response["content"]
    categories = []
    for value in content.get("categories") or []:
        normalized = _normalize_category(value)
        if normalized and normalized not in categories:
            categories.append(normalized)
    planned = {
        "workflow": content.get("workflow"),
        "categories": categories,
        "category_a": categories[0] if categories else _normalize_category(content.get("category_a")),
        "category_b": categories[1] if len(categories) > 1 else _normalize_category(content.get("category_b")),
        "merchant": content.get("merchant"),
        "artifact_preference": content.get("artifact_preference"),
    }
    if planned["workflow"] not in SUPPORTED_WORKFLOWS:
        return None
    response["content"] = planned
    return response


def llm_summarize_response(user, normalized_request: dict[str, Any], evidence_payload: dict[str, Any]):
    system_prompt = """
You summarize expense-analysis evidence for a finance app.
Return JSON only with keys:
- summary
- findings
- actions

Rules:
- Use only the supplied evidence.
- Do not invent numbers or unsupported claims.
- Keep findings concise.
- findings must be a list of objects with title and detail.
- actions must be a list of short strings.
"""
    user_payload = json.dumps(
        {
            "request": normalized_request,
            "evidence": {
                "workflow": evidence_payload.get("workflow"),
                "summary": evidence_payload.get("summary"),
                "findings": evidence_payload.get("findings"),
                "critic": evidence_payload.get("critic"),
                "trace": evidence_payload.get("trace"),
                "rows": evidence_payload.get("rows"),
                "labels": evidence_payload.get("labels"),
                "data": evidence_payload.get("data"),
            },
        },
        default=str,
    )
    response = call_chat_completion(user, system_prompt, user_payload, max_tokens=500, temperature=0.2, expect_json=True)
    if not response or not isinstance(response.get("content"), dict):
        return None
    content = response["content"]
    if not isinstance(content.get("summary"), str):
        return None
    response["content"] = {
        "summary": content.get("summary"),
        "findings": content.get("findings") if isinstance(content.get("findings"), list) else [],
        "actions": content.get("actions") if isinstance(content.get("actions"), list) else [],
    }
    return response
