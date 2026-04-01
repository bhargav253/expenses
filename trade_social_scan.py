from __future__ import annotations

from datetime import datetime
import json

from ai_clients import call_chat_completion
from extensions import db
from market_data import normalize_symbol
from models import Asset, TrendScanEvent, TrendScanRun, User
from ticker_ingestion import enqueue_asset_refresh
from trade_agent import TradeAgentError, run_trade_agent_analysis, serialize_trade_agent_run
from trade_social_tools import (
    fetch_trend_source_items,
    normalize_trend_scan_request,
    extract_trend_candidates,
    rank_trend_candidates,
)


class TrendScanError(Exception):
    pass


def _build_fallback_summary(prompt: str, ranked_results, source_statuses=None):
    if not ranked_results:
        status_parts = []
        for status in source_statuses or []:
            label = status.get("source_name") or "source"
            if status.get("status") == "failed":
                status_parts.append(f"{label} failed")
            else:
                status_parts.append(f"{label} items {status.get('item_count', 0)}")
        detail = f" Sources: {', '.join(status_parts)}." if status_parts else ""
        return {
            "summary": f"No strong ticker candidates surfaced for '{prompt}'.{detail}",
            "highlights": [],
        }
    leaders = ", ".join(result["symbol"] for result in ranked_results[:3])
    return {
        "summary": f"Trend scan surfaced {len(ranked_results)} candidate ticker(s) for '{prompt}'. Top names: {leaders}.",
        "highlights": [
            {
                "title": f"{result['symbol']} surfaced",
                "detail": result.get("reason_summary") or "Detected across source items.",
            }
            for result in ranked_results[:3]
        ],
    }


def _call_trend_scan_summary_llm(user, scenario_prompt, ranked_results):
    system_prompt = """
You summarize a trend-scan result set for a personal finance app.
Return JSON only.

Required keys:
- summary
- highlights

Rules:
- Use only the provided evidence.
- Do not claim live knowledge beyond the supplied source items.
- highlights must be a list of objects with title and detail.
"""
    response = call_chat_completion(
        user,
        system_prompt,
        json.dumps({
            "scenario_prompt": scenario_prompt,
            "ranked_results": ranked_results,
        }, default=str),
        max_tokens=500,
        temperature=0.2,
        expect_json=True,
    )
    if not response or not isinstance(response.get("content"), dict):
        return None
    content = response["content"]
    summary = content.get("summary")
    highlights = content.get("highlights")
    if not isinstance(summary, str):
        return None
    response["content"] = {
        "summary": summary,
        "highlights": highlights if isinstance(highlights, list) else [],
    }
    return response


def serialize_trend_scan_run(run):
    ranked_results = json.loads(run.ranked_results_json) if run.ranked_results_json else []
    warnings = json.loads(run.warnings_json) if run.warnings_json else []
    source_modes = json.loads(run.source_modes_json) if run.source_modes_json else []
    query_terms = json.loads(run.query_terms_json) if run.query_terms_json else []
    token_usage = json.loads(run.token_usage_json) if run.token_usage_json else None
    summary_json = json.loads(run.summary_json) if run.summary_json else {}
    source_statuses = json.loads(run.source_statuses_json) if run.source_statuses_json else []
    return {
        "id": run.id,
        "scenario_prompt": run.scenario_prompt,
        "status": run.status,
        "source_modes": source_modes,
        "query_terms": query_terms,
        "ranked_results": ranked_results,
        "warnings": warnings,
        "summary": summary_json.get("summary"),
        "highlights": summary_json.get("highlights") or [],
        "source_statuses": source_statuses,
        "generation_mode": run.generation_mode,
        "provider": run.provider_name,
        "model": run.model_name,
        "token_usage": token_usage,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def serialize_trend_scan_run_summary(run):
    payload = serialize_trend_scan_run(run)
    return {
        "id": payload["id"],
        "scenario_prompt": payload["scenario_prompt"],
        "status": payload["status"],
        "source_modes": payload["source_modes"],
        "summary": payload["summary"],
        "top_symbols": [item["symbol"] for item in payload["ranked_results"][:3]],
        "generation_mode": payload["generation_mode"],
        "provider": payload["provider"],
        "model": payload["model"],
        "token_usage": payload["token_usage"],
        "created_at": payload["created_at"],
    }


def run_trend_scan_analysis(dashboard_id, scenario_prompt, user_id, source_modes=None, max_results=5):
    user = User.query.get(user_id)
    if not user:
        raise TrendScanError("User not found")

    normalized_request = normalize_trend_scan_request(scenario_prompt, source_modes=source_modes, max_results=max_results)
    fetched = fetch_trend_source_items(normalized_request, user)
    source_items = fetched["items"]
    warnings = list(fetched["warnings"])
    candidate_map = extract_trend_candidates(source_items, prompt_symbols=normalized_request.get("prompt_symbols"))
    ranked_results = rank_trend_candidates(candidate_map, normalized_request["max_results"])

    for result in ranked_results:
        symbol = normalize_symbol(result.get("symbol"))
        if not symbol:
            continue
        asset = Asset.query.filter_by(symbol=symbol).first()
        if asset is None:
            continue
        try:
            trade_run = run_trade_agent_analysis(
                dashboard_id=dashboard_id,
                symbol=symbol,
                request_text=f"Trend scan follow-up for scenario: {normalized_request['scenario_prompt']}",
                user_id=user_id,
            )
            result["trade_agent_run"] = serialize_trade_agent_run(trade_run)
        except TradeAgentError as exc:
            enqueue_asset_refresh(asset, include_backfill=False, include_fundamentals=True, include_intraday=True, priority=True)
            result["trade_agent_error"] = str(exc)
        except Exception as exc:
            result["trade_agent_error"] = f"Follow-up analysis failed: {exc}"

    summary_payload = _build_fallback_summary(normalized_request["scenario_prompt"], ranked_results, fetched.get("source_statuses"))
    generation_mode = "deterministic"
    provider = None
    model = None
    token_usage = None
    llm_summary = None
    try:
        llm_summary = _call_trend_scan_summary_llm(user, normalized_request["scenario_prompt"], ranked_results) if source_items and ranked_results else None
    except Exception:
        llm_summary = None
    if llm_summary:
        summary_payload = llm_summary["content"]
        generation_mode = "ai_assisted"
        provider = llm_summary.get("provider")
        model = llm_summary.get("model")
        token_usage = llm_summary.get("usage")

    run = TrendScanRun(
        dashboard_id=dashboard_id,
        created_by=user_id,
        scenario_prompt=normalized_request["scenario_prompt"],
        source_modes_json=json.dumps(normalized_request["source_modes"]),
        query_terms_json=json.dumps(normalized_request["query_terms"]),
        ranked_results_json=json.dumps(ranked_results, default=str),
        warnings_json=json.dumps(warnings),
        summary_json=json.dumps(summary_payload),
        source_statuses_json=json.dumps(fetched.get("source_statuses") or []),
        generation_mode=generation_mode,
        provider_name=provider,
        model_name=model,
        token_usage_json=json.dumps(token_usage) if token_usage else None,
        status="completed",
    )
    db.session.add(run)
    db.session.flush()

    for event_payload in fetched["request_events"]:
        db.session.add(
            TrendScanEvent(
                trend_scan_run_id=run.id,
                event_type=event_payload["event_type"],
                event_payload_json=json.dumps(event_payload.get("event_payload") or {}),
            )
        )

    db.session.add(
        TrendScanEvent(
            trend_scan_run_id=run.id,
            event_type="trend_scan_completed",
            event_payload_json=json.dumps(
                {
                    "source_item_count": len(source_items),
                    "candidate_count": len(candidate_map),
                    "ranked_count": len(ranked_results),
                    "sources_used": fetched["sources_used"],
                }
            ),
        )
    )
    db.session.commit()
    return run
