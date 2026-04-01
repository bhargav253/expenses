from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
import re
from typing import Optional
from urllib.parse import quote_plus

import requests

from models import Asset, TrendScanEvent, TrendScanRun


DEFAULT_TREND_SCAN_SOURCES = ["newsapi", "gdelt"]
SUPPORTED_TREND_SCAN_SOURCES = {"gdelt", "newsapi", "reddit", "stocktwits"}
AMBIGUOUS_SYMBOLS = {
    "A", "AI", "ALL", "AM", "ARE", "AT", "BE", "BY", "CAN", "DD", "FOR", "GO", "IT", "LIFE", "LOVE", "NOW", "ON", "OR", "SO", "TO", "UK", "US",
}
REDDIT_SUBREDDITS = ["wallstreetbets", "stocks", "investing", "options"]


def extract_prompt_symbols(prompt: str):
    candidates = []
    for token in re.findall(r"\b[A-Z]{2,5}\b", prompt or ""):
        if token in AMBIGUOUS_SYMBOLS or token in candidates:
            continue
        candidates.append(token)
    return candidates[:4]


def _source_priority(source_name: str):
    return {"newsapi": 0, "gdelt": 1, "reddit": 2, "stocktwits": 3}.get(source_name, 9)


def _lookup_asset_names(symbols: list[str]):
    if not symbols:
        return {}
    rows = Asset.query.filter(Asset.symbol.in_(symbols)).all()
    return {row.symbol: row.name for row in rows if row and row.name}


def normalize_trend_scan_request(scenario_prompt: str, source_modes=None, max_results=None):
    prompt = (scenario_prompt or "").strip()
    if not prompt:
        raise ValueError("Scenario prompt is required")

    normalized_sources = []
    for source in source_modes or DEFAULT_TREND_SCAN_SOURCES:
        source_name = str(source).strip().lower()
        if source_name in SUPPORTED_TREND_SCAN_SOURCES and source_name not in normalized_sources:
            normalized_sources.append(source_name)
    if not normalized_sources:
        normalized_sources = DEFAULT_TREND_SCAN_SOURCES[:]
    normalized_sources.sort(key=_source_priority)

    try:
        normalized_max_results = int(max_results or 5)
    except (TypeError, ValueError):
        normalized_max_results = 5
    normalized_max_results = max(1, min(normalized_max_results, 8))

    prompt_symbols = extract_prompt_symbols(prompt)
    query_terms = build_query_terms(prompt, prompt_symbols=prompt_symbols)
    return {
        "scenario_prompt": prompt,
        "source_modes": normalized_sources,
        "max_results": normalized_max_results,
        "query_terms": query_terms,
        "prompt_symbols": prompt_symbols,
    }


def build_query_terms(prompt: str, prompt_symbols=None):
    cleaned = re.sub(r"\s+", " ", prompt.strip())
    fragments = [cleaned]
    lowered = cleaned.lower()
    prompt_symbols = prompt_symbols or extract_prompt_symbols(cleaned)
    if prompt_symbols:
        asset_names = _lookup_asset_names(prompt_symbols)
        expanded = " ".join([asset_names.get(symbol, symbol) for symbol in prompt_symbols])
        if expanded and expanded.lower() != cleaned.lower():
            fragments.append(f"{cleaned} {expanded}")
        if len(prompt_symbols) >= 2 and any(token in lowered for token in ["investment", "invest", "partner", "partnership", "supplier", "stake"]):
            left = asset_names.get(prompt_symbols[0], prompt_symbols[0])
            right = asset_names.get(prompt_symbols[1], prompt_symbols[1])
            fragments.append(f"{left} {right} relationship investment partnership supplier")
    if "war" in lowered and "defense" not in lowered:
        fragments.append(f"{cleaned} defense contractors")
        fragments.append(f"{cleaned} oil stocks")
    if "nvidia" in lowered and "gtc" in lowered:
        fragments.append(f"{cleaned} suppliers")
        fragments.append(f"{cleaned} networking optics")
    deduped = []
    for fragment in fragments:
        normalized = fragment.strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped[:4]


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_dt(value: Optional[str]):
    if not value:
        return None
    cleaned = str(value).strip()
    for parser in (
        lambda item: datetime.fromisoformat(item.replace("Z", "+00:00")),
        lambda item: datetime.strptime(item[:14], "%Y%m%d%H%M%S"),
        lambda item: datetime.strptime(item[:19], "%Y-%m-%dT%H:%M:%S"),
    ):
        try:
            return parser(cleaned)
        except Exception:
            continue
    return None


def get_newsapi_remaining_budget(user) -> int:
    daily_limit = getattr(user, "newsapi_daily_limit", None)
    try:
        limit_value = int(daily_limit if daily_limit is not None else 0)
    except (TypeError, ValueError):
        limit_value = 0
    if limit_value <= 0:
        return 0

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    used_count = (
        TrendScanEvent.query.join(TrendScanRun, TrendScanRun.id == TrendScanEvent.trend_scan_run_id)
        .filter(
            TrendScanRun.created_by == user.id,
            TrendScanEvent.event_type == "newsapi_request",
            TrendScanEvent.created_at >= today_start,
        )
        .count()
    )
    return max(0, limit_value - used_count)


def fetch_gdelt_items(query_terms, *, limit=12, timeout=12):
    items = []
    for query in query_terms[:2]:
        url = (
            "https://api.gdeltproject.org/api/v2/doc/doc"
            f"?query={quote_plus(query)}&mode=ArtList&maxrecords={limit}&format=json&sort=HybridRel"
        )
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        for article in payload.get("articles") or []:
            items.append(
                {
                    "source_name": "gdelt",
                    "title": article.get("title") or "",
                    "body_snippet": article.get("seendate") or article.get("socialimage") or "",
                    "url": article.get("url"),
                    "published_at": (_parse_dt(article.get("seendate")) or datetime.utcnow()).isoformat(),
                    "author_or_source": article.get("domain") or "GDELT",
                    "engagement_hint": None,
                }
            )
        if items:
            break
    return _dedupe_source_items(items)[:limit]


def fetch_newsapi_items(query_terms, user, *, limit=10, timeout=12):
    api_key = user.get_decrypted_api_key("newsapi_api_key") if user else None
    if not api_key or get_newsapi_remaining_budget(user) <= 0:
        return []

    from_date = (datetime.utcnow() - timedelta(days=3)).date().isoformat()
    items = []
    for query in query_terms[:2]:
        response = requests.get(
            "https://newsapi.org/v2/everything",
            params={
                "q": query,
                "from": from_date,
                "language": "en",
                "sortBy": "publishedAt",
                "pageSize": limit,
                "apiKey": api_key,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        for article in payload.get("articles") or []:
            items.append(
                {
                    "source_name": "newsapi",
                    "title": article.get("title") or "",
                    "body_snippet": article.get("description") or article.get("content") or "",
                    "url": article.get("url"),
                    "published_at": (_parse_dt(article.get("publishedAt")) or datetime.utcnow()).isoformat(),
                    "author_or_source": (article.get("source") or {}).get("name") or "NewsAPI",
                    "engagement_hint": None,
                }
            )
        if items:
            break
    return _dedupe_source_items(items)[:limit]


def fetch_reddit_items(query_terms, *, limit=8, timeout=12):
    headers = {"User-Agent": "ExpensesTrendScanner/1.0"}
    items = []
    for query in query_terms[:1]:
        response = requests.get(
            "https://www.reddit.com/search.json",
            params={"q": query, "limit": limit, "sort": "new", "restrict_sr": False},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        for child in (((payload.get("data") or {}).get("children")) or []):
            data = child.get("data") or {}
            subreddit = data.get("subreddit")
            if subreddit and subreddit.lower() not in REDDIT_SUBREDDITS:
                continue
            items.append(
                {
                    "source_name": "reddit",
                    "title": data.get("title") or "",
                    "body_snippet": data.get("selftext") or "",
                    "url": f"https://www.reddit.com{data.get('permalink')}" if data.get("permalink") else data.get("url"),
                    "published_at": datetime.utcfromtimestamp(data.get("created_utc") or datetime.utcnow().timestamp()).isoformat(),
                    "author_or_source": subreddit or "reddit",
                    "engagement_hint": _safe_float(data.get("score")),
                }
            )
    return _dedupe_source_items(items)[:limit]


def fetch_stocktwits_items(query_terms, *, limit=8, timeout=12):
    items = []
    response = requests.get("https://api.stocktwits.com/api/2/trending/symbols.json", timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    for symbol_data in (payload.get("symbols") or [])[:limit]:
        symbol = symbol_data.get("symbol")
        if not symbol:
            continue
        items.append(
            {
                "source_name": "stocktwits",
                "title": f"Stocktwits trending symbol {symbol}",
                "body_snippet": "Trending on Stocktwits.",
                "url": f"https://stocktwits.com/symbol/{symbol}",
                "published_at": datetime.utcnow().isoformat(),
                "author_or_source": "Stocktwits",
                "engagement_hint": None,
            }
        )
    return items[:limit]


def fetch_trend_source_items(normalized_request, user):
    items = []
    warnings = []
    sources_used = []
    request_events = []
    source_statuses = []

    for source_name in normalized_request["source_modes"]:
        attempted = False
        try:
            if source_name == "gdelt":
                attempted = True
                source_items = fetch_gdelt_items(normalized_request["query_terms"])
            elif source_name == "newsapi":
                attempted = True
                source_items = fetch_newsapi_items(normalized_request["query_terms"], user)
                request_events.append({"event_type": "newsapi_request", "event_payload": {"query_terms": normalized_request["query_terms"]}})
            elif source_name == "reddit":
                attempted = True
                source_items = fetch_reddit_items(normalized_request["query_terms"])
            elif source_name == "stocktwits":
                attempted = True
                source_items = fetch_stocktwits_items(normalized_request["query_terms"])
            else:
                source_items = []
        except Exception as exc:
            warnings.append(f"{source_name} fetch failed: {exc}")
            source_items = []
            source_statuses.append({
                "source_name": source_name,
                "status": "failed",
                "item_count": 0,
                "detail": str(exc),
            })
            continue
        if attempted:
            source_statuses.append({
                "source_name": source_name,
                "status": "ok" if source_items else "empty",
                "item_count": len(source_items),
                "detail": None,
            })
        if source_items:
            items.extend(source_items)
            sources_used.append(source_name)

    return {
        "items": _dedupe_source_items(items),
        "warnings": warnings,
        "sources_used": sources_used,
        "request_events": request_events,
        "source_statuses": source_statuses,
    }


def _dedupe_source_items(items):
    seen = set()
    deduped = []
    for item in items:
        key = ((item.get("url") or "").strip(), (item.get("title") or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _extract_symbol_mentions(text: str):
    if not text:
        return set()
    candidates = set()
    for match in re.findall(r"\$([A-Z]{1,5})\b", text):
        candidates.add(match.upper())
    for match in re.findall(r"\b(?:NASDAQ|NYSE|AMEX)[: ]([A-Z]{1,5})\b", text):
        candidates.add(match.upper())
    for match in re.findall(r"\(([A-Z]{1,5})\)", text):
        candidates.add(match.upper())
    return {symbol for symbol in candidates if symbol not in AMBIGUOUS_SYMBOLS}


def _extract_asset_name_mentions(text: str):
    lowered = (text or "").lower()
    mentions = []
    for asset in Asset.query.filter(Asset.name.isnot(None)).all():
        company_name = (asset.name or "").strip()
        if len(company_name) < 4:
            continue
        if company_name.lower() in lowered:
            mentions.append(asset.symbol)
    return mentions


def extract_trend_candidates(source_items, prompt_symbols=None):
    candidate_map = {}
    for item in source_items:
        combined_text = " ".join([item.get("title") or "", item.get("body_snippet") or ""])
        symbols = set(_extract_symbol_mentions(combined_text))
        symbols.update(_extract_asset_name_mentions(combined_text))
        for symbol in symbols:
            evidence = candidate_map.setdefault(
                symbol,
                {
                    "symbol": symbol,
                    "mention_count": 0,
                    "source_items": [],
                    "source_types": set(),
                    "confidence": "moderate",
                },
            )
            evidence["mention_count"] += 1
            evidence["source_items"].append(item)
            evidence["source_types"].add(item.get("source_name") or "unknown")
    prompt_symbols = prompt_symbols or []
    if source_items and prompt_symbols:
        for symbol in prompt_symbols:
            evidence = candidate_map.setdefault(
                symbol,
                {
                    "symbol": symbol,
                    "mention_count": 0,
                    "source_items": [],
                    "source_types": set(),
                    "confidence": "moderate",
                },
            )
            if not evidence["source_items"]:
                evidence["source_items"] = list(source_items[:3])
                evidence["source_types"] = {item.get("source_name") or "unknown" for item in evidence["source_items"]}
                evidence["mention_count"] = len(evidence["source_items"])
                evidence["confidence"] = "moderate"
    return candidate_map


def rank_trend_candidates(candidate_map, max_results=5):
    ranked = []
    for symbol, payload in candidate_map.items():
        source_count = len(payload["source_items"])
        source_type_count = len(payload["source_types"])
        recency_bonus = 0.0
        for item in payload["source_items"][:4]:
            published_at = _parse_dt(item.get("published_at"))
            if published_at and published_at >= datetime.utcnow() - timedelta(hours=24):
                recency_bonus += 0.5
        score = (payload["mention_count"] * 2.0) + (source_type_count * 1.5) + min(source_count, 5) + recency_bonus
        top_items = payload["source_items"][:3]
        reason_bits = []
        if top_items:
            reason_bits.append(f"{source_count} source item{'s' if source_count != 1 else ''}")
            reason_bits.append(f"{source_type_count} source type{'s' if source_type_count != 1 else ''}")
            first_title = top_items[0].get("title")
            if first_title:
                reason_bits.append(first_title[:140])
        ranked.append(
            {
                "symbol": symbol,
                "score": round(score, 2),
                "mention_count": payload["mention_count"],
                "source_count": source_count,
                "source_types": sorted(payload["source_types"]),
                "reason_summary": " | ".join(reason_bits),
                "supporting_items": top_items,
                "confidence": payload["confidence"],
            }
        )
    ranked.sort(key=lambda row: (row["score"], row["mention_count"], row["source_count"]), reverse=True)
    return ranked[:max_results]
