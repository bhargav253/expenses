from __future__ import annotations

from datetime import date

from .artifacts import build_bar_chart, build_line_chart, build_pie_chart, build_stat_grid, build_table
from .contracts import ExpenseAnalysisResponse, NormalizedExpenseRequest
from .tools import (
    available_period_coverage,
    category_breakdown_for_period,
    category_change_report,
    category_multi_period_totals,
    category_split_by_user,
    category_period_totals,
    category_vs_category_period_totals,
    large_outlier_transactions,
    merchant_change_report,
    merchant_period_totals,
    merchant_spike_report,
    monthly_review_report,
    recurring_expense_candidates,
    savings_opportunity_report,
)


def _base_critic(request: NormalizedExpenseRequest):
    warnings = list(request.warnings)
    return {"confidence": "moderate", "warnings": warnings}


def _prior_period(date_range, granularity: str):
    if not date_range.start_date or not date_range.end_date:
        return date_range
    if granularity == "year":
        span_years = date_range.end_date.year - date_range.start_date.year
        return type(date_range)(
            start_date=date(date_range.start_date.year - span_years, date_range.start_date.month, date_range.start_date.day),
            end_date=date(date_range.end_date.year - span_years, date_range.end_date.month, date_range.end_date.day),
            label=f"prior {date_range.label}",
        )
    start = date_range.start_date
    if start.month == 1:
        prior_start = date(start.year - 1, 12, 1)
    else:
        prior_start = date(start.year, start.month - 1, 1)
    prior_end = start
    return type(date_range)(start_date=prior_start, end_date=prior_end, label=f"prior {date_range.label}")


def run_category_trend(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = category_period_totals(
        dashboard_id,
        request.category_a,
        request.date_range,
        granularity=request.granularity,
        user_id=request.user_id,
    )
    coverage = available_period_coverage(dashboard_id, request.date_range, request.granularity, request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No spending data matched the selected category and period.")
        return ExpenseAnalysisResponse(
            workflow="category_trend",
            summary="No expense trend data was found for the selected category and period.",
            critic=critic,
            trace={"workflow_version": "v1", "tools_used": ["category_period_totals", "available_period_coverage"]},
            chart_type="bar",
        )

    labels = [row["period"] for row in rows]
    values = [row["value"] for row in rows]
    total = sum(values)
    peak = max(rows, key=lambda row: row["value"])
    low = min(rows, key=lambda row: row["value"])
    delta = values[-1] - values[0] if len(values) > 1 else 0.0
    direction = "up" if delta >= 0 else "down"
    if len(coverage) < len(labels):
        critic["warnings"].append("Some periods may be missing because there were no matching transactions.")

    findings = [
        {
            "title": f"{request.category_a.title()} total",
            "detail": f"Total tracked spend was {total:.2f} across {len(labels)} periods.",
            "evidence": {"total": total, "periods": len(labels)},
        },
        {
            "title": "Highest period",
            "detail": f"{peak['period']} was highest at {peak['value']:.2f}.",
            "evidence": peak,
        },
        {
            "title": "Lowest period",
            "detail": f"{low['period']} was lowest at {low['value']:.2f}.",
            "evidence": low,
        },
    ]
    summary = f"{request.category_a.title()} spending is trending {direction} by {abs(delta):.2f} across {len(labels)} periods in {request.date_range.label}."
    datasets = [{"label": request.category_a.title(), "data": values}]
    preferred_chart = "line" if request.artifact_preference == "line_chart" else "bar"
    artifacts = [
        build_line_chart(f"{request.category_a.title()} spending trend", labels, datasets),
        build_table("Category trend detail", rows),
    ]
    return ExpenseAnalysisResponse(
        workflow="category_trend",
        summary=summary,
        findings=findings,
        actions=["Review the peak period to see which merchants drove the increase."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["category_period_totals", "available_period_coverage"]},
        chart_type=preferred_chart,
        labels=labels,
        data=values,
        rows=rows,
        datasets=datasets,
    )


def run_category_vs_category(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    categories = list(request.categories or [])
    if not categories:
        if request.category_a:
            categories.append(request.category_a)
        if request.category_b:
            categories.append(request.category_b)
    rows = category_multi_period_totals(
        dashboard_id,
        categories[:],
        request.date_range,
        granularity=request.granularity,
        user_id=request.user_id,
    ) if len(categories) > 2 else category_vs_category_period_totals(
        dashboard_id,
        request.category_a,
        request.category_b,
        request.date_range,
        granularity=request.granularity,
        user_id=request.user_id,
    )
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No overlapping category data was found for the selected period.")
        return ExpenseAnalysisResponse(
            workflow="category_vs_category",
            summary="No category comparison data was found for the selected categories and period.",
            critic=critic,
            trace={"workflow_version": "v1", "tools_used": ["category_vs_category_period_totals"]},
        )

    labels = [row["period"] for row in rows]
    datasets = []
    totals = {}
    wins = {}
    if len(categories) > 2:
        for category in categories:
            series = [row.get(category, 0.0) for row in rows]
            datasets.append({"label": category.title(), "data": series})
            totals[category] = sum(series)
            wins[category] = [row["period"] for row in rows if row.get(category, 0.0) == max(row.get(cat, 0.0) for cat in categories)]
    else:
        series_a = [row["category_a_value"] for row in rows]
        series_b = [row["category_b_value"] for row in rows]
        datasets = [
            {"label": request.category_a.title(), "data": series_a},
            {"label": request.category_b.title(), "data": series_b},
        ]
        totals = {
            request.category_a: sum(series_a),
            request.category_b: sum(series_b),
        }
        wins = {
            request.category_a: [row["period"] for row in rows if row["category_a_value"] > row["category_b_value"]],
            request.category_b: [row["period"] for row in rows if row["category_b_value"] > row["category_a_value"]],
        }
    leader = max(totals, key=totals.get)
    totals_summary = ", ".join(f"{category.title()} {totals[category]:.2f}" for category in categories[:4])
    summary = f"{leader.title()} was higher overall in {request.date_range.label}. {totals_summary}."
    findings = [
        {
            "title": f"{leader.title()} led overall",
            "detail": totals_summary,
            "evidence": {"totals": totals},
        }
    ]
    for category in categories[:4]:
        period_wins = wins.get(category, [])
        findings.append(
            {
                "title": f"{category.title()} led {len(period_wins)} periods",
                "detail": ", ".join(period_wins[:6]) if period_wins else "No periods",
                "evidence": {"periods": period_wins},
            }
        )
    dominant_categories = [category for category, period_wins in wins.items() if not period_wins]
    if dominant_categories:
        critic["warnings"].append("Some categories never led any period, so the comparison is uneven.")
    preferred_chart = "bar" if request.artifact_preference == "bar_chart" else "line"
    artifacts = [
        build_line_chart("Category comparison", labels, datasets),
        build_table("Category comparison detail", rows),
    ]
    return ExpenseAnalysisResponse(
        workflow="category_vs_category",
        summary=summary,
        findings=findings,
        actions=["Inspect the months with the largest delta to see whether the change came from routine spend or one-off spikes."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["category_vs_category_period_totals"]},
        chart_type=preferred_chart,
        labels=labels,
        data=[],
        rows=rows,
        datasets=datasets,
    )


def run_category_breakdown(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    breakdown = category_breakdown_for_period(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    rows = breakdown["rows"]
    total = breakdown["total"]
    if not rows:
        critic["warnings"].append("No expenses were found for the selected period.")
        return ExpenseAnalysisResponse(
            workflow="category_breakdown",
            summary="No expense data was found for the selected period.",
            critic=critic,
            trace={"workflow_version": "v1", "tools_used": ["category_breakdown_for_period"]},
            chart_type="pie",
        )

    top = rows[0]
    findings = [
        {
            "title": f"{top['label'].title()} is largest",
            "detail": f"It accounted for {top['value']:.2f}, or {top['share_pct']:.1f}% of total spend.",
            "evidence": top,
        }
    ]
    labels = [row["label"] for row in rows[:8]]
    values = [row["value"] for row in rows[:8]]
    preferred_chart = "bar" if request.artifact_preference == "bar_chart" else "pie"
    summary = f"{top['label'].title()} was the largest category in {request.date_range.label} at {top['value']:.2f} out of {total:.2f} total spend."
    artifacts = [
        build_pie_chart("Expense breakdown", labels, values),
        build_table("Expense breakdown detail", rows),
    ]
    return ExpenseAnalysisResponse(
        workflow="category_breakdown",
        summary=summary,
        findings=findings,
        actions=["Review the top two categories if you want the biggest impact on overall spending."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["category_breakdown_for_period"]},
        chart_type=preferred_chart,
        labels=labels,
        data=values,
        rows=rows,
    )


def run_what_changed(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    prior_range = _prior_period(request.date_range, request.granularity)
    category_changes = category_change_report(dashboard_id, request.date_range, prior_range, request.user_id)
    merchant_changes = merchant_change_report(dashboard_id, request.date_range, prior_range, request.user_id)
    spikes = merchant_spike_report(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    if not category_changes:
        critic["warnings"].append("No change data was available for the selected period.")
        return ExpenseAnalysisResponse(
            workflow="what_changed",
            summary="No change data was available for the selected period.",
            critic=critic,
            trace={"workflow_version": "v1", "tools_used": ["category_change_report", "merchant_change_report", "merchant_spike_report"]},
        )
    top = category_changes[0]
    summary = f"{top['label'].title()} changed the most in {request.date_range.label}, moving by {top['delta']:.2f} versus the prior period."
    findings = [
        {
            "title": f"{top['label'].title()} was the top driver",
            "detail": f"Current period {top['current_value']:.2f} vs prior period {top['prior_value']:.2f}.",
            "evidence": top,
        }
    ]
    if merchant_changes:
        top_merchant = merchant_changes[0]
        findings.append({
            "title": "Merchant shift",
            "detail": f"{top_merchant['merchant']} moved by {top_merchant['delta']:.2f}.",
            "evidence": top_merchant,
        })
    if spikes:
        findings.append({
            "title": "One-off candidate",
            "detail": f"{spikes[0]['merchant']} had a max transaction of {spikes[0]['max_amount']:.2f}.",
            "evidence": spikes[0],
        })
    artifacts = [
        build_bar_chart("Top category deltas", [row["label"] for row in category_changes[:6]], [{"label": "Delta", "data": [row["delta"] for row in category_changes[:6]]}]),
        build_table("Merchant changes", merchant_changes),
    ]
    return ExpenseAnalysisResponse(
        workflow="what_changed",
        summary=summary,
        findings=findings,
        actions=["Review the top changing category and merchant to see whether the movement was recurring or one-off."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["category_change_report", "merchant_change_report", "merchant_spike_report"]},
        chart_type="table",
        rows=category_changes,
    )


def run_who_spent_what(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = category_split_by_user(dashboard_id, request.date_range, category=request.category_a, user_id=request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No user-split data was found.")
        return ExpenseAnalysisResponse(workflow="who_spent_what", summary="No user-split data was found.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["category_split_by_user"]})
    leader = rows[0]
    summary = f"{leader['label']} spent the most in {request.date_range.label}."
    findings = [{
        "title": f"{leader['label']} leads",
        "detail": f"Tracked spend totals {leader['value']:.2f}.",
        "evidence": leader,
    }]
    artifacts = [
        build_bar_chart("Spend by user", [row["label"] for row in rows], [{"label": "Spend", "data": [row["value"] for row in rows]}]),
        build_table("User spend detail", rows),
    ]
    return ExpenseAnalysisResponse(
        workflow="who_spent_what",
        summary=summary,
        findings=findings,
        actions=["Use a category filter next if you want to compare household spending inside one bucket."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["category_split_by_user"]},
        chart_type="bar",
        labels=[row["label"] for row in rows],
        data=[row["value"] for row in rows],
        rows=rows,
    )


def run_recurring_charges(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = recurring_expense_candidates(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No recurring merchants were detected.")
        return ExpenseAnalysisResponse(workflow="recurring_charges", summary="No recurring merchants were detected.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["recurring_expense_candidates"]})
    summary = f"Found {len(rows)} recurring-charge candidates in {request.date_range.label}."
    findings = [{
        "title": f"{rows[0]['merchant']} looks recurring",
        "detail": f"Seen in {rows[0]['months_seen']} months with an average charge of {rows[0]['average_amount']:.2f}.",
        "evidence": rows[0],
    }]
    artifacts = [build_table("Recurring charges", rows)]
    return ExpenseAnalysisResponse(
        workflow="recurring_charges",
        summary=summary,
        findings=findings,
        actions=["Review recurring services and subscriptions for cancellation or downgrade candidates."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["recurring_expense_candidates"]},
        chart_type="table",
        rows=rows,
    )


def run_merchant_trend(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = merchant_period_totals(dashboard_id, request.merchant or "", request.date_range, request.granularity, request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No merchant trend data matched the selected merchant and period.")
        return ExpenseAnalysisResponse(workflow="merchant_trend", summary="No merchant trend data was found.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["merchant_period_totals"]})
    labels = [row["period"] for row in rows]
    values = [row["value"] for row in rows]
    summary = f"Spend at {request.merchant} totaled {sum(values):.2f} across {len(labels)} periods in {request.date_range.label}."
    artifacts = [
        build_line_chart(f"{request.merchant} trend", labels, [{"label": request.merchant, "data": values}]),
        build_table("Merchant trend detail", rows),
    ]
    return ExpenseAnalysisResponse(
        workflow="merchant_trend",
        summary=summary,
        findings=[{"title": "Merchant total", "detail": summary, "evidence": {"total": sum(values)}}],
        actions=["Compare this merchant with the surrounding category if you want to see whether it is driving the broader trend."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["merchant_period_totals"]},
        chart_type="bar",
        labels=labels,
        data=values,
        rows=rows,
        datasets=[{"label": request.merchant, "data": values}],
    )


def run_outlier_expenses(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = large_outlier_transactions(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No outlier expenses were found.")
        return ExpenseAnalysisResponse(workflow="outlier_expenses", summary="No outlier expenses were found.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["large_outlier_transactions"]})
    summary = f"Found {len(rows)} unusually large transactions in {request.date_range.label}."
    findings = [{
        "title": "Largest transaction",
        "detail": f"{rows[0]['description']} for {rows[0]['amount']:.2f} on {rows[0]['date']}.",
        "evidence": rows[0],
    }]
    return ExpenseAnalysisResponse(
        workflow="outlier_expenses",
        summary=summary,
        findings=findings,
        actions=["Review whether the top outliers were expected one-offs or candidates for closer monitoring."],
        critic=critic,
        artifacts=[build_table("Outlier transactions", rows)],
        trace={"workflow_version": "v1", "tools_used": ["large_outlier_transactions"]},
        chart_type="table",
        rows=rows,
    )


def run_savings_opportunities(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    rows = savings_opportunity_report(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    if not rows:
        critic["warnings"].append("No clear savings opportunities were found.")
        return ExpenseAnalysisResponse(workflow="savings_opportunities", summary="No clear savings opportunities were found.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["savings_opportunity_report"]})
    summary = f"Found {len(rows)} likely savings opportunities in {request.date_range.label}."
    findings = [{
        "title": row["label"].title(),
        "detail": row["reason"],
        "evidence": row,
    } for row in rows[:3]]
    return ExpenseAnalysisResponse(
        workflow="savings_opportunities",
        summary=summary,
        findings=findings,
        actions=["Review the discretionary buckets first, then recurring services for the fastest savings impact."],
        critic=critic,
        artifacts=[build_table("Savings opportunities", rows)],
        trace={"workflow_version": "v1", "tools_used": ["savings_opportunity_report"]},
        chart_type="table",
        rows=rows,
    )


def run_monthly_review(dashboard_id: int, request: NormalizedExpenseRequest) -> ExpenseAnalysisResponse:
    report = monthly_review_report(dashboard_id, request.date_range, request.user_id)
    critic = _base_critic(request)
    top_categories = report["top_categories"]
    if not top_categories:
        critic["warnings"].append("No expenses were found for the selected review period.")
        return ExpenseAnalysisResponse(workflow="monthly_review", summary="No expenses were found for the selected review period.", critic=critic, trace={"workflow_version": "v1", "tools_used": ["monthly_review_report"]})
    summary = f"Total spend in {request.date_range.label} was {report['total']:.2f}, led by {top_categories[0]['label']}."
    findings = [
        {
            "title": "Top category",
            "detail": f"{top_categories[0]['label'].title()} led at {top_categories[0]['value']:.2f}.",
            "evidence": top_categories[0],
        }
    ]
    if report["top_outliers"]:
        findings.append({
            "title": "Largest one-off",
            "detail": f"{report['top_outliers'][0]['description']} for {report['top_outliers'][0]['amount']:.2f}.",
            "evidence": report["top_outliers"][0],
        })
    artifacts = [
        build_stat_grid("Monthly review stats", [
            {"label": "Total", "value": report["total"]},
            {"label": "Top category", "value": top_categories[0]["label"]},
            {"label": "Recurring candidates", "value": len(report["recurring"])},
        ]),
        build_table("Top categories", top_categories),
    ]
    return ExpenseAnalysisResponse(
        workflow="monthly_review",
        summary=summary,
        findings=findings,
        actions=["Check the top category, largest outlier, and recurring charges together for a full monthly review."],
        critic=critic,
        artifacts=artifacts,
        trace={"workflow_version": "v1", "tools_used": ["monthly_review_report"]},
        chart_type="table",
        rows=top_categories,
    )
