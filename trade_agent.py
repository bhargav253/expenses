from __future__ import annotations

from datetime import datetime
import json
import re

from ai_clients import call_chat_completion
from extensions import db
from models import TradeAgentEvent, TradeAgentRun, TradeIdea, User
from ticker_ingestion import enqueue_asset_refresh
from trade_tools import (
    compute_trade_agent_features,
    derive_trade_levels,
    evaluate_trade_agent_freshness,
    load_trade_agent_context,
    required_fundamentals_status,
    summarize_watchlist_context,
)

class TradeAgentError(Exception):
    pass


def _as_string(value, *, default=None, max_length=None):
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    if max_length is not None:
        text = text[:max_length]
    return text


def _as_list_of_strings(value, *, limit=8):
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    normalized = []
    for item in value:
        text = _as_string(item, default=None, max_length=500)
        if text:
            normalized.append(text)
        if len(normalized) >= limit:
            break
    return normalized


def _extract_json_object(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if not match:
            return None
        return json.loads(match.group(0))


def _build_fallback_analysis(symbol, request_text, features, freshness, watchlist_context):
    setup_flags = features.get("setup_flags", {})
    trend_label = features.get("trend_label") or "mixed"
    levels = derive_trade_levels(features)
    warnings = list(freshness.get("warnings") or [])
    confidence = "low"

    if setup_flags.get("trend_setup") and not warnings:
        confidence = "moderate"
    if setup_flags.get("trend_setup") and setup_flags.get("breakout_setup") and not warnings:
        confidence = "moderate-high"

    setup_type = "trend"
    if setup_flags.get("breakout_setup"):
        setup_type = "breakout"
    elif setup_flags.get("pullback_setup"):
        setup_type = "pullback"

    price = features.get("price")
    summary = f"{symbol} is currently showing a {trend_label} profile with a {setup_type} bias."
    if price is not None:
        summary = f"{symbol} is trading near {price:.2f} and currently shows a {trend_label} profile with a {setup_type} bias."

    bullish_case = "Price is holding above key short/intermediate trend references."
    if features.get("returns", {}).get("return_20d") not in (None,):
        bullish_case = (
            f"Recent 20-day performance is {features['returns']['return_20d']:.2f}%, "
            "which supports a constructive momentum case if continuation holds."
        )

    bearish_case = "If the current trend loses support and volume fades, the setup weakens quickly."
    if features.get("rsi_14") and features["rsi_14"] > 70:
        bearish_case = "RSI is elevated, so the setup may be vulnerable to a sharper reset if buyers fade."

    risks = freshness.get("warnings") or []
    if not risks:
        risks = [
            "Setup quality is derived from cached local market data only.",
            "No event/news context is included in this version.",
        ]

    catalysts = []
    if watchlist_context:
        catalysts.append("Existing watchlist thesis context is available and may support follow-up review.")
    if features.get("volume_ratio") and features["volume_ratio"] > 1.2:
        catalysts.append("Volume is running above the recent average.")

    return {
        "title": f"{symbol} {setup_type.title()} Setup",
        "idea_type": "long" if trend_label != "downtrend" else "watch",
        "thesis_summary": summary,
        "setup_type": setup_type,
        "bullish_case": bullish_case,
        "bearish_case": bearish_case,
        "entry_zone": levels["entry_zone"],
        "target_1": levels["target_1"],
        "target_2": levels["target_2"],
        "invalidation": levels["invalidation"],
        "time_horizon": "days to weeks",
        "catalysts": catalysts,
        "risks": risks,
        "confidence": confidence,
        "missing_data": ["news", "sentiment"],
        "request_echo": request_text or "",
    }


def _build_fallback_critic(analysis, freshness):
    warnings = list(freshness.get("warnings") or [])
    warnings.extend([
        "This review does not include intraday structure or event timing.",
        "The suggested levels are heuristic and should be validated by the user.",
    ])
    return {
        "verdict": "cautious",
        "confidence_adjustment": "unchanged" if not freshness.get("warnings") else "lower",
        "weak_assumptions": [
            "Trend continuation is inferred from cached historical bars.",
            "No macro, earnings-calendar, or news context is included.",
        ],
        "contradictions": [],
        "warnings": warnings,
        "invalidation_focus": analysis.get("invalidation"),
    }


def _normalize_trade_analysis(symbol, request_text, payload, freshness):
    payload = payload or {}
    title = _as_string(payload.get("title"), default=f"{symbol} Trade Setup", max_length=255)
    idea_type = _as_string(payload.get("idea_type"), default="watch", max_length=50)
    if idea_type not in {"long", "short", "watch", "avoid", "options"}:
        idea_type = "watch"

    setup_type = _as_string(payload.get("setup_type"), default="general", max_length=100)
    confidence = _as_string(payload.get("confidence"), default="low", max_length=50)
    if confidence not in {"low", "moderate", "moderate-high", "high"}:
        confidence = "low"

    normalized = {
        "title": title,
        "idea_type": idea_type,
        "thesis_summary": _as_string(payload.get("thesis_summary"), default="No summary available.", max_length=2000),
        "setup_type": setup_type,
        "bullish_case": _as_string(payload.get("bullish_case"), default="No bullish case provided.", max_length=2000),
        "bearish_case": _as_string(payload.get("bearish_case"), default="No bearish case provided.", max_length=2000),
        "entry_zone": _as_string(payload.get("entry_zone"), default=None, max_length=255),
        "target_1": _as_string(payload.get("target_1"), default=None, max_length=255),
        "target_2": _as_string(payload.get("target_2"), default=None, max_length=255),
        "invalidation": _as_string(payload.get("invalidation"), default=None, max_length=255),
        "time_horizon": _as_string(payload.get("time_horizon"), default="days to weeks", max_length=100),
        "catalysts": _as_list_of_strings(payload.get("catalysts")),
        "risks": _as_list_of_strings(payload.get("risks")),
        "confidence": confidence,
        "missing_data": _as_list_of_strings(payload.get("missing_data")),
        "request_echo": _as_string(payload.get("request_echo"), default=request_text or "", max_length=1000),
    }

    for warning in freshness.get("warnings") or []:
        if warning not in normalized["risks"]:
            normalized["risks"].append(warning)
    return normalized


def _normalize_trade_critic(payload, analysis, freshness):
    payload = payload or {}
    verdict = _as_string(payload.get("verdict"), default="cautious", max_length=100)
    confidence_adjustment = _as_string(payload.get("confidence_adjustment"), default="unchanged", max_length=100)
    return {
        "verdict": verdict,
        "confidence_adjustment": confidence_adjustment,
        "weak_assumptions": _as_list_of_strings(payload.get("weak_assumptions")),
        "contradictions": _as_list_of_strings(payload.get("contradictions")),
        "warnings": _as_list_of_strings(payload.get("warnings")) or list(freshness.get("warnings") or []),
        "invalidation_focus": _as_string(payload.get("invalidation_focus"), default=analysis.get("invalidation"), max_length=255),
    }


def _call_trade_agent_llm(user, symbol, request_text, features, freshness, watchlist_context):
    system_prompt = """
You are a trading research copilot for a personal finance app.
You must stay inside the supplied data.
Return JSON only.

Required keys:
- title
- idea_type
- thesis_summary
- setup_type
- bullish_case
- bearish_case
- entry_zone
- target_1
- target_2
- invalidation
- time_horizon
- catalysts
- risks
- confidence
- missing_data

Rules:
- Do not claim live/news-aware knowledge.
- Do not give absolute financial advice.
- Use concise, data-backed language.
- If data is stale or limited, say so in risks or missing_data.
"""

    user_prompt = json.dumps({
        "symbol": symbol,
        "request_text": request_text,
        "features": features,
        "freshness": freshness,
        "watchlist_context": watchlist_context,
    }, default=str)
    response = call_chat_completion(
        user,
        system_prompt,
        user_prompt,
        max_tokens=900,
        temperature=0.2,
        expect_json=True,
    )
    if not response:
        return None
    return response


def _call_trade_agent_critic_llm(user, analysis, freshness):
    system_prompt = """
You are the critic for a trading research copilot.
Review the supplied structured trade analysis and return JSON only.

Required keys:
- verdict
- confidence_adjustment
- weak_assumptions
- contradictions
- warnings
- invalidation_focus

Do not invent external information.
"""
    response = call_chat_completion(
        user,
        system_prompt,
        json.dumps({"analysis": analysis, "freshness": freshness}, default=str),
        max_tokens=600,
        temperature=0.1,
        expect_json=True,
    )
    if not response:
        return None
    return response


def serialize_trade_agent_run(run):
    analysis = json.loads(run.analysis_json) if run.analysis_json else {}
    critic = json.loads(run.critic_json) if run.critic_json else {}
    warnings = json.loads(run.warnings_json) if run.warnings_json else []
    data_freshness = json.loads(run.data_freshness_json) if run.data_freshness_json else {}
    stage_usage = json.loads(run.stage_usage_json) if getattr(run, "stage_usage_json", None) else {}
    token_usage = json.loads(run.token_usage_json) if getattr(run, "token_usage_json", None) else None
    return {
        "id": run.id,
        "symbol": run.asset.symbol if run.asset else None,
        "asset_name": run.asset.name if run.asset else None,
        "status": run.status,
        "request_text": run.request_text,
        "analysis": analysis,
        "critic": critic,
        "warnings": warnings,
        "data_freshness": data_freshness,
        "generation_mode": getattr(run, "generation_mode", "deterministic"),
        "provider": getattr(run, "provider_name", None),
        "model": getattr(run, "model_name", None),
        "stage_usage": stage_usage,
        "token_usage": token_usage,
        "created_trade_idea_id": run.created_trade_idea_id,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def run_trade_agent_analysis(dashboard_id, symbol, request_text, user_id):
    user = User.query.get(user_id)
    if not user:
        raise TradeAgentError("User not found")

    context = load_trade_agent_context(symbol)
    if not context:
        raise TradeAgentError("Ticker not found in the local investing database yet. Add or refresh it first.")

    asset = context["asset"]
    snapshot = context["snapshot"]
    fundamentals = context["fundamentals"]
    bars = context["bars"]
    watchlist_context = summarize_watchlist_context(context["watchlist_items"])
    freshness = evaluate_trade_agent_freshness(snapshot, fundamentals, bars)
    fundamentals_status = required_fundamentals_status(snapshot, fundamentals)
    features = compute_trade_agent_features(snapshot, fundamentals, bars)

    if features.get("price") is None:
        raise TradeAgentError("Not enough price history is available to analyze this ticker.")

    analysis = None
    critic = None
    warnings = list(freshness.get("warnings") or [])
    auto_refresh_queued = False
    generation_mode = "deterministic"
    provider_used = None
    model_used = None
    stage_usage = {
        "planner": "deterministic",
        "analysis": "heuristic",
        "critic": "heuristic",
    }
    token_usage = None

    fundamentals_stale = bool(
        freshness.get("fundamentals_as_of")
        and "Fundamentals are older than the expected freshness threshold." in warnings
    )
    if (not fundamentals_status["is_complete"]) or fundamentals_stale:
        enqueue_asset_refresh(
            asset,
            include_backfill=False,
            include_fundamentals=True,
            include_intraday=False,
            priority=True,
        )
        auto_refresh_queued = True
        missing_fields_text = ", ".join(fundamentals_status["missing_fields"]) if fundamentals_status["missing_fields"] else "stale fundamentals"
        warnings.append(
            f"Queued a priority fundamentals refresh for {asset.symbol} because the local cache is incomplete for: {missing_fields_text}."
        )

    try:
        analysis_response = _call_trade_agent_llm(user, asset.symbol, request_text, features, freshness, watchlist_context)
        analysis = analysis_response["content"] if analysis_response else None
        critic_response = _call_trade_agent_critic_llm(user, analysis, freshness) if analysis else None
        critic = critic_response["content"] if critic_response else None
        if analysis and critic:
            generation_mode = "ai_assisted"
            provider_used = analysis_response.get("provider")
            model_used = analysis_response.get("model")
            stage_usage["analysis"] = "llm"
            stage_usage["critic"] = "llm"
            analysis_usage = analysis_response.get("usage") or {}
            critic_usage = critic_response.get("usage") or {}
            token_usage = {
                "analysis_input_tokens": analysis_usage.get("input_tokens", 0),
                "analysis_output_tokens": analysis_usage.get("output_tokens", 0),
                "critic_input_tokens": critic_usage.get("input_tokens", 0),
                "critic_output_tokens": critic_usage.get("output_tokens", 0),
            }
            token_usage["total_input_tokens"] = token_usage["analysis_input_tokens"] + token_usage["critic_input_tokens"]
            token_usage["total_output_tokens"] = token_usage["analysis_output_tokens"] + token_usage["critic_output_tokens"]
            token_usage["total_tokens"] = token_usage["total_input_tokens"] + token_usage["total_output_tokens"]
    except Exception:
        analysis = None
        critic = None
        warnings.append("LLM analysis was unavailable, so the report was generated from deterministic local heuristics.")

    if not analysis:
        analysis = _build_fallback_analysis(asset.symbol, request_text, features, freshness, watchlist_context)
    if not critic:
        critic = _build_fallback_critic(analysis, freshness)

    analysis = _normalize_trade_analysis(asset.symbol, request_text, analysis, freshness)
    critic = _normalize_trade_critic(critic, analysis, freshness)
    if fundamentals_status["missing_fields"]:
        missing_label_map = {
            "forward_pe": "forward P/E",
            "peg_ratio": "PEG",
            "revenue_growth": "revenue growth",
            "eps_growth": "EPS growth",
            "pe_ratio": "P/E",
        }
        missing_labels = [missing_label_map.get(item, item) for item in fundamentals_status["missing_fields"]]
        analysis["missing_data"] = sorted(set((analysis.get("missing_data") or []) + missing_labels))
        critic["warnings"] = list(critic.get("warnings") or []) + [
            "Missing fundamental growth data makes the valuation discussion incomplete until the cache refresh completes."
        ]

    warnings.extend([warning for warning in critic.get("warnings", []) if warning not in warnings])

    run = TradeAgentRun(
        dashboard_id=dashboard_id,
        asset_id=asset.id,
        created_by=user_id,
        request_text=request_text,
        status='completed',
        analysis_json=json.dumps(analysis),
        critic_json=json.dumps(critic),
        warnings_json=json.dumps(warnings),
        data_freshness_json=json.dumps(freshness),
        generation_mode=generation_mode,
        provider_name=provider_used,
        model_name=model_used,
        stage_usage_json=json.dumps(stage_usage),
        token_usage_json=json.dumps(token_usage) if token_usage else None,
    )
    db.session.add(run)
    db.session.flush()
    db.session.add_all([
        TradeAgentEvent(
            trade_agent_run_id=run.id,
            event_type='context_loaded',
            event_payload_json=json.dumps({
                "symbol": asset.symbol,
                "watchlist_context_count": len(watchlist_context),
                "history_bar_count": freshness.get("history_bar_count"),
            })
        ),
        TradeAgentEvent(
            trade_agent_run_id=run.id,
            event_type='features_built',
            event_payload_json=json.dumps(features)
        ),
        TradeAgentEvent(
            trade_agent_run_id=run.id,
            event_type='analysis_completed',
            event_payload_json=json.dumps({
                "provider_used": provider_used or "fallback",
                "model_used": model_used,
                "generation_mode": generation_mode,
                "stage_usage": stage_usage,
                "token_usage": token_usage,
                "auto_refresh_queued": auto_refresh_queued,
                "missing_fundamental_fields": fundamentals_status["missing_fields"],
                "completed_at": datetime.utcnow().isoformat(),
            })
        ),
    ])
    db.session.commit()
    return TradeAgentRun.query.get(run.id)


def save_trade_agent_run_as_trade_idea(run_id, user_id):
    run = TradeAgentRun.query.get(run_id)
    if not run:
        raise TradeAgentError("Trade-agent run not found")

    if run.created_trade_idea_id:
        idea = TradeIdea.query.get(run.created_trade_idea_id)
        return idea

    analysis = json.loads(run.analysis_json) if run.analysis_json else {}
    catalysts = analysis.get("catalysts") or []
    risks = analysis.get("risks") or []
    confidence = analysis.get("confidence")
    confidence_score = None
    if confidence == "moderate-high":
        confidence_score = 75
    elif confidence == "moderate":
        confidence_score = 65
    elif confidence == "low":
        confidence_score = 40

    idea = TradeIdea(
        dashboard_id=run.dashboard_id,
        asset_id=run.asset_id,
        created_by=user_id,
        source_type='agent',
        idea_type=analysis.get("idea_type") or 'watch',
        title=analysis.get("title") or f"{run.asset.symbol} Trade Idea",
        thesis_summary=analysis.get("thesis_summary"),
        entry_zone=analysis.get("entry_zone"),
        target_1=analysis.get("target_1"),
        target_2=analysis.get("target_2"),
        invalidation=analysis.get("invalidation"),
        time_horizon=analysis.get("time_horizon"),
        confidence_score=confidence_score,
        catalysts="\n".join(catalysts) if isinstance(catalysts, list) else str(catalysts) if catalysts else None,
        risks="\n".join(risks) if isinstance(risks, list) else str(risks) if risks else None,
    )
    db.session.add(idea)
    db.session.flush()
    run.created_trade_idea_id = idea.id
    db.session.add(TradeAgentEvent(
        trade_agent_run_id=run.id,
        event_type='trade_idea_created',
        event_payload_json=json.dumps({
            "trade_idea_id": idea.id,
            "created_by": user_id,
        })
    ))
    db.session.commit()
    return TradeIdea.query.get(idea.id)
