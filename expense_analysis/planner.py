from __future__ import annotations

import calendar
import difflib
import re
from datetime import date
from typing import Optional, Tuple

from models import EXPENSE_CATEGORIES

from .contracts import DateRange, NormalizedExpenseRequest


_CATEGORY_ALIASES = {
    "restaurants": "restaurant",
    "dining": "restaurant",
    "resturant": "restaurant",
    "restraunt": "restaurant",
    "restuarant": "restaurant",
    "groceries": "grocery",
    "grovery": "grocery",
    "groccery": "grocery",
    "grocerry": "grocery",
    "travel": "vacation",
    "trip": "vacation",
    "shopping": "shopping",
    "utilities": "utility",
    "transportation": "transport",
}

_MONTH_LOOKUP = {name.lower(): index for index, name in enumerate(calendar.month_name) if name}
_MONTH_LOOKUP.update({abbr.lower(): index for index, abbr in enumerate(calendar.month_abbr) if abbr})


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _normalize_phrase(text: str) -> str:
    return re.sub(r"[^a-z0-9\s]", " ", _normalize_text(text))


def _extract_merchant(prompt: str) -> Optional[str]:
    text = _normalize_text(prompt)
    patterns = [
        r"\bat\s+([a-z0-9&*'. -]+?)(?:\s+in\s+20\d{2}|\s+this month|\s+last month|$)",
        r"\bmerchant\s+([a-z0-9&*'. -]+?)(?:\s+in\s+20\d{2}|\s+this month|\s+last month|$)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            candidate = match.group(1).strip(" .")
            if candidate and candidate not in {"restaurant", "grocery", "shopping"}:
                return candidate
    return None


def detect_categories(prompt: str) -> list[str]:
    text = _normalize_phrase(prompt)
    found: list[str] = []
    for category in EXPENSE_CATEGORIES:
        if re.search(rf"\b{re.escape(category.lower())}\b", text):
            found.append(category.lower())
    for alias, canonical in _CATEGORY_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", text) and canonical not in found:
            found.append(canonical)
    if found:
        return found

    tokens = [token for token in text.split() if len(token) >= 4]
    category_candidates = list(EXPENSE_CATEGORIES) + list(_CATEGORY_ALIASES.keys())
    for token in tokens:
        match = difflib.get_close_matches(token, category_candidates, n=1, cutoff=0.8)
        if not match:
            continue
        matched = match[0]
        canonical = _CATEGORY_ALIASES.get(matched, matched)
        if canonical not in found:
            found.append(canonical)
    return found


def normalize_categories(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not value:
            continue
        lowered = value.strip().lower()
        canonical = _CATEGORY_ALIASES.get(lowered, lowered)
        if canonical in EXPENSE_CATEGORIES and canonical not in normalized:
            normalized.append(canonical)
    return normalized


def _parse_date_range(prompt: str) -> Tuple[DateRange, str]:
    text = _normalize_text(prompt)
    years = sorted(set(int(year) for year in re.findall(r"20\d{2}", text)))
    month_matches = [(name, idx) for name, idx in _MONTH_LOOKUP.items() if re.search(rf"\b{name}\b", text)]
    month_index = month_matches[0][1] if month_matches else None

    if years and month_index:
        year = years[0]
        start = date(year, month_index, 1)
        if month_index == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, month_index + 1, 1)
        return DateRange(start, end, f"{calendar.month_name[month_index]} {year}"), "month"

    if len(years) == 1:
        year = years[0]
        return DateRange(date(year, 1, 1), date(year + 1, 1, 1), str(year)), "month"

    if len(years) >= 2:
        start_year = min(years)
        end_year = max(years) + 1
        return DateRange(date(start_year, 1, 1), date(end_year, 1, 1), f"{start_year}-{end_year - 1}"), "year"

    today = date.today()
    return DateRange(date(today.year, 1, 1), date(today.year + 1, 1, 1), str(today.year)), "month"


def _detect_artifact_preference(text: str) -> Optional[str]:
    if "line plot" in text or "line chart" in text:
        return "line_chart"
    if "bar chart" in text or "bar plot" in text:
        return "bar_chart"
    if "pie" in text:
        return "pie_chart"
    if "table" in text:
        return "table"
    return None


def is_follow_up_prompt(prompt: str) -> bool:
    text = _normalize_text(prompt)
    follow_up_tokens = [
        "also add",
        "add ",
        "include ",
        "same plot",
        "same chart",
        "same month",
        "same months",
        "same period",
        "same year",
        "same years",
        "to the plot",
        "to the chart",
        "remove ",
        "drop ",
        "switch to",
        "use a ",
        "make it a ",
        "compare it with",
        "compare this with",
        "compare that with",
        "compare with",
        "vs ",
        "versus ",
    ]
    if any(token in text for token in follow_up_tokens):
        return True
    return bool(re.search(r"\b(compare|add|include)\b.*\b(it|this|that|same)\b", text))


def merge_follow_up_request(
    previous_request: NormalizedExpenseRequest,
    prompt: str,
    categories: Optional[list[str]] = None,
    artifact_preference: Optional[str] = None,
) -> NormalizedExpenseRequest:
    text = _normalize_text(prompt)
    merged_categories = list(previous_request.categories or [])
    detected_categories = normalize_categories(categories or detect_categories(prompt))
    if any(token in text for token in ["remove ", "drop "]):
        merged_categories = [category for category in merged_categories if category not in detected_categories]
    elif detected_categories:
        for category in detected_categories:
            if category not in merged_categories:
                merged_categories.append(category)

    preference = artifact_preference or _detect_artifact_preference(text) or previous_request.artifact_preference
    date_range = previous_request.date_range
    granularity = previous_request.granularity
    if re.search(r"20\d{2}", text) or any(re.search(rf"\b{name}\b", text) for name in _MONTH_LOOKUP):
        date_range, granularity = _parse_date_range(prompt)

    workflow = previous_request.workflow
    if merged_categories:
        workflow = "category_vs_category" if len(merged_categories) >= 2 else "category_trend"

    warnings = list(previous_request.warnings)
    warnings.append("Follow-up request merged with the prior analytics context.")
    return NormalizedExpenseRequest(
        prompt=prompt,
        workflow=workflow,
        date_range=date_range,
        granularity=granularity,
        categories=merged_categories,
        category_a=merged_categories[0] if merged_categories else None,
        category_b=merged_categories[1] if len(merged_categories) > 1 else None,
        merchant=previous_request.merchant,
        user_id=previous_request.user_id,
        artifact_preference=preference,
        warnings=warnings,
    )


def finalize_request(request: NormalizedExpenseRequest) -> NormalizedExpenseRequest:
    categories = normalize_categories(list(request.categories or []))
    if request.category_a:
        categories = normalize_categories(categories + [request.category_a])
    if request.category_b:
        categories = normalize_categories(categories + [request.category_b])
    request.categories = categories
    request.category_a = categories[0] if categories else None
    request.category_b = categories[1] if len(categories) > 1 else None

    if request.workflow == "category_vs_category":
        if len(categories) >= 2:
            return request
        if len(categories) == 1:
            request.workflow = "category_trend"
            request.warnings.append("Only one category was recognized, so the comparison was narrowed to a single-category trend.")
        else:
            request.workflow = "category_breakdown"
            request.warnings.append("No valid categories were recognized, so the request was routed to an overall breakdown.")
    elif request.workflow == "category_trend" and not request.category_a:
        request.workflow = "category_breakdown"
        request.warnings.append("No valid category was recognized, so the request was routed to an overall breakdown.")
    return request


def serialize_request_context(request: NormalizedExpenseRequest) -> dict:
    return {
        "prompt": request.prompt,
        "workflow": request.workflow,
        "date_range": {
            "start_date": request.date_range.start_date.isoformat() if request.date_range.start_date else None,
            "end_date": request.date_range.end_date.isoformat() if request.date_range.end_date else None,
            "label": request.date_range.label,
        },
        "granularity": request.granularity,
        "categories": list(request.categories or []),
        "category_a": request.category_a,
        "category_b": request.category_b,
        "merchant": request.merchant,
        "user_id": request.user_id,
        "artifact_preference": request.artifact_preference,
        "warnings": list(request.warnings or []),
    }


def deserialize_request_context(payload: Optional[dict]) -> Optional[NormalizedExpenseRequest]:
    if not payload or not isinstance(payload, dict):
        return None
    date_payload = payload.get("date_range") or {}
    start_date = date.fromisoformat(date_payload["start_date"]) if date_payload.get("start_date") else None
    end_date = date.fromisoformat(date_payload["end_date"]) if date_payload.get("end_date") else None
    categories = normalize_categories(payload.get("categories") or [])
    return NormalizedExpenseRequest(
        prompt=payload.get("prompt") or "",
        workflow=payload.get("workflow") or "category_breakdown",
        date_range=DateRange(start_date=start_date, end_date=end_date, label=date_payload.get("label")),
        granularity=payload.get("granularity") or "month",
        categories=categories,
        category_a=payload.get("category_a") or (categories[0] if categories else None),
        category_b=payload.get("category_b") or (categories[1] if len(categories) > 1 else None),
        merchant=payload.get("merchant"),
        user_id=payload.get("user_id"),
        artifact_preference=payload.get("artifact_preference"),
        warnings=list(payload.get("warnings") or []),
    )


def plan_expense_request(prompt: str, user_id: int | None = None) -> NormalizedExpenseRequest:
    categories = detect_categories(prompt)
    date_range, granularity = _parse_date_range(prompt)
    text = _normalize_text(prompt)
    merchant = _extract_merchant(prompt)
    artifact_preference = _detect_artifact_preference(text)

    if any(token in text for token in ["what changed", "why was", "why is", "changed from", "changed compared", "why did"]):
        workflow = "what_changed"
    elif any(token in text for token in ["who spent", "vs my wife", "vs my husband", "by user", "split by user"]):
        workflow = "who_spent_what"
    elif any(token in text for token in ["recurring", "subscription", "subscriptions", "monthly charges"]):
        workflow = "recurring_charges"
    elif merchant and any(token in text for token in ["merchant", "at ", "amazon", "costco", "whole foods", "spent at", "spend at"]):
        workflow = "merchant_trend"
    elif any(token in text for token in ["outlier", "unusual", "large expense", "big purchase", "one-off"]):
        workflow = "outlier_expenses"
    elif any(token in text for token in ["save money", "cut back", "savings", "reduce spending", "where can we cut"]):
        workflow = "savings_opportunities"
    elif any(token in text for token in ["monthly review", "review this month", "summary for", "how did we do"]):
        workflow = "monthly_review"
    elif any(token in text for token in ["breakdown", "major expenses", "top categories", "share", "pie"]):
        workflow = "category_breakdown"
    elif len(categories) >= 2 and any(token in text for token in ["compare", "vs", "versus"]):
        workflow = "category_vs_category"
    elif categories:
        workflow = "category_trend"
    else:
        workflow = "category_breakdown"

    warnings: list[str] = []
    if workflow == "category_vs_category" and len(categories) < 2:
        warnings.append("Two recognizable categories were not found, so the request was downgraded.")
        workflow = "category_breakdown"
    if workflow == "category_trend" and not categories:
        warnings.append("No recognized category was found; showing a breakdown instead.")
        workflow = "category_breakdown"
    if any(alias in text for alias in ["resturant", "restraunt", "restuarant", "groccery", "grocerry"]):
        warnings.append("Category matching used typo-tolerant normalization.")

    return finalize_request(NormalizedExpenseRequest(
        prompt=prompt,
        workflow=workflow,
        date_range=date_range,
        granularity=granularity,
        categories=categories[:],
        category_a=categories[0] if categories else None,
        category_b=categories[1] if len(categories) > 1 else None,
        merchant=merchant,
        user_id=user_id,
        artifact_preference=artifact_preference,
        warnings=warnings,
    ))
