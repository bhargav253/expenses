from __future__ import annotations

from models import User

from .llm import llm_merge_request, llm_plan_request, llm_summarize_response
from .planner import (
    deserialize_request_context,
    finalize_request,
    is_follow_up_prompt,
    merge_follow_up_request,
    plan_expense_request,
    serialize_request_context,
)
from .workflows import (
    run_category_breakdown,
    run_category_trend,
    run_category_vs_category,
    run_monthly_review,
    run_merchant_trend,
    run_outlier_expenses,
    run_recurring_charges,
    run_savings_opportunities,
    run_what_changed,
    run_who_spent_what,
)


def run_expense_analytics_agent(dashboard_id, prompt, user_id=None, prior_request_context=None):
    user = User.query.get(user_id) if user_id else None
    previous_request = deserialize_request_context(prior_request_context)
    is_follow_up = previous_request is not None and is_follow_up_prompt(prompt)
    request = merge_follow_up_request(previous_request, prompt) if is_follow_up else plan_expense_request(prompt, user_id=user_id)
    generation_mode = "deterministic"
    planner_mode = "rule_based"
    synthesis_mode = "template"
    provider = None
    model = None
    token_usage = None

    if user:
        try:
            if is_follow_up and previous_request is not None:
                planner_response = llm_merge_request(user, prompt, serialize_request_context(previous_request))
            else:
                planner_response = llm_plan_request(user, prompt)
        except Exception:
            planner_response = None
        if planner_response:
            planner_content = planner_response["content"]
            request.workflow = planner_content.get("workflow") or request.workflow
            if planner_content.get("categories"):
                request.categories = planner_content["categories"]
            request.category_a = planner_content.get("category_a") or request.category_a
            request.category_b = planner_content.get("category_b") or request.category_b
            if not request.categories:
                request.categories = [category for category in [request.category_a, request.category_b] if category]
            request.merchant = planner_content.get("merchant") or request.merchant
            request.artifact_preference = planner_content.get("artifact_preference") or request.artifact_preference
            planner_mode = "llm"
            generation_mode = "ai_assisted"
            provider = planner_response.get("provider")
            model = planner_response.get("model")
            usage = planner_response.get("usage") or {}
            token_usage = {
                "planner_input_tokens": usage.get("input_tokens", 0),
                "planner_output_tokens": usage.get("output_tokens", 0),
                "synthesis_input_tokens": 0,
                "synthesis_output_tokens": 0,
                "total_tokens": usage.get("total_tokens", 0),
            }
    request = finalize_request(request)

    workflow_handlers = {
        "category_trend": run_category_trend,
        "category_vs_category": run_category_vs_category,
        "category_breakdown": run_category_breakdown,
        "what_changed": run_what_changed,
        "who_spent_what": run_who_spent_what,
        "recurring_charges": run_recurring_charges,
        "merchant_trend": run_merchant_trend,
        "outlier_expenses": run_outlier_expenses,
        "savings_opportunities": run_savings_opportunities,
        "monthly_review": run_monthly_review,
    }
    response = workflow_handlers.get(request.workflow, run_category_breakdown)(dashboard_id, request)

    if user:
        try:
            synthesis_response = llm_summarize_response(
                user,
                {
                    "workflow": request.workflow,
                    "categories": request.categories,
                    "category_a": request.category_a,
                    "category_b": request.category_b,
                    "merchant": request.merchant,
                    "date_range": request.date_range.label,
                    "granularity": request.granularity,
                    "artifact_preference": request.artifact_preference,
                },
                {
                    "workflow": response.workflow,
                    "summary": response.summary,
                    "findings": response.findings,
                    "actions": response.actions,
                    "critic": response.critic,
                    "trace": response.trace,
                    "rows": response.rows,
                    "labels": response.labels,
                    "data": response.data,
                },
            )
        except Exception:
            synthesis_response = None
        if synthesis_response:
            content = synthesis_response["content"]
            response.summary = content.get("summary") or response.summary
            if content.get("findings"):
                response.findings = content["findings"]
            if content.get("actions"):
                response.actions = content["actions"]
            synthesis_mode = "llm"
            generation_mode = "ai_assisted"
            provider = synthesis_response.get("provider") or provider
            model = synthesis_response.get("model") or model
            usage = synthesis_response.get("usage") or {}
            if token_usage is None:
                token_usage = {
                    "planner_input_tokens": 0,
                    "planner_output_tokens": 0,
                    "synthesis_input_tokens": 0,
                    "synthesis_output_tokens": 0,
                    "total_tokens": 0,
                }
            token_usage["synthesis_input_tokens"] = usage.get("input_tokens", 0)
            token_usage["synthesis_output_tokens"] = usage.get("output_tokens", 0)
            token_usage["total_tokens"] = (
                token_usage.get("planner_input_tokens", 0)
                + token_usage.get("planner_output_tokens", 0)
                + token_usage.get("synthesis_input_tokens", 0)
                + token_usage.get("synthesis_output_tokens", 0)
            )

    payload = {
        "workflow": response.workflow,
        "request_type": response.workflow,
        "summary": response.summary,
        "findings": response.findings,
        "actions": response.actions,
        "critic": response.critic,
        "artifacts": response.artifacts,
        "trace": response.trace,
        "chart_type": response.chart_type,
        "labels": response.labels,
        "data": response.data,
        "rows": response.rows,
        "generation_mode": generation_mode,
        "planner_mode": planner_mode,
        "synthesis_mode": synthesis_mode,
        "provider": provider,
        "model": model,
        "token_usage": token_usage,
        "normalized_request": serialize_request_context(request),
    }
    if response.datasets:
        payload["datasets"] = response.datasets
    if payload["trace"] is None:
        payload["trace"] = {}
    payload["trace"]["generation_mode"] = generation_mode
    payload["trace"]["planner_mode"] = planner_mode
    payload["trace"]["synthesis_mode"] = synthesis_mode
    payload["trace"]["provider"] = provider
    payload["trace"]["model"] = model
    return payload
