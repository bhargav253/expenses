from datetime import datetime

from expense_tools import (
    category_breakdown,
    category_change_report,
    large_outlier_transactions,
    month_bounds,
    monthly_spend_trend,
    parse_relative_period,
    period_compare_summary,
    recurring_expense_candidates,
    spend_by_user,
)
from models import EXPENSE_CATEGORIES


def classify_expense_request(prompt: str):
    text = (prompt or "").lower()

    if any(token in text for token in ["recurring", "subscription", "monthly charges"]):
        return "recurring_expenses"
    if any(token in text for token in ["outlier", "unusual", "large transaction", "spike transaction"]):
        return "outlier_detection"
    if any(token in text for token in ["compare", "vs", "versus", "change", "increased", "decreased"]):
        return "period_compare"
    if any(token in text for token in ["roommate", "housemate", "who spent", "by user"]):
        return "roommate_split"
    if any(token in text for token in ["breakdown", "share", "distribution", "pie"]):
        return "category_breakdown"
    return "trend"


def extract_category_filter(prompt: str):
    text = (prompt or "").lower()
    for category in EXPENSE_CATEGORIES:
        if category.lower() in text:
            return category.lower()
    return None


def build_current_and_prior_period():
    today = datetime.utcnow().date()
    current_period = month_bounds(today.year, today.month)

    if today.month == 1:
        prior_year = today.year - 1
        prior_month = 12
    else:
        prior_year = today.year
        prior_month = today.month - 1
    prior_period = month_bounds(prior_year, prior_month)
    return current_period, prior_period


def _build_critic(confidence, warnings):
    return {
        "confidence": confidence,
        "warnings": warnings
    }


def run_expense_analytics_agent(dashboard_id, prompt, user_id=None):
    request_type = classify_expense_request(prompt)
    parsed_period = parse_relative_period(prompt)
    category_filter = extract_category_filter(prompt)
    trace_tools = []
    artifacts = []
    findings = []
    critic = _build_critic("moderate", [])

    if request_type == "category_breakdown":
        current_period, _ = build_current_and_prior_period()
        breakdown = category_breakdown(dashboard_id, start_date=current_period[0], end_date=current_period[1], user_id=user_id)
        trace_tools.append("category_breakdown")
        total = breakdown["total"]
        top_label = breakdown["labels"][0] if breakdown["labels"] else None
        top_value = breakdown["values"][0] if breakdown["values"] else 0
        summary = "No expense data was found for the selected period."
        if top_label:
            share = (top_value / total * 100) if total else 0
            summary = f"{top_label.title()} is the largest category this month at {top_value:.2f}, about {share:.0f}% of tracked spend."
            findings.append({
                "title": f"{top_label.title()} leads current spending",
                "detail": f"It accounts for {top_value:.2f} out of {total:.2f} for the month.",
                "evidence": {"category": top_label, "value": top_value, "total": total}
            })
        artifacts.append({
            "type": "pie_chart",
            "title": "Current month category breakdown",
            "labels": breakdown["labels"],
            "data": breakdown["values"]
        })
        chart_payload = {
            "chart_type": "pie",
            "labels": breakdown["labels"],
            "data": breakdown["values"]
        }

    elif request_type == "period_compare":
        current_period, prior_period = build_current_and_prior_period()
        comparison = period_compare_summary(dashboard_id, current_period, prior_period, user_id=user_id)
        changes = category_change_report(dashboard_id, current_period, prior_period, user_id=user_id)
        trace_tools.extend(["period_compare_summary", "category_change_report"])

        direction = "up" if comparison["delta"] >= 0 else "down"
        pct_text = ""
        if comparison["pct_change"] is not None:
            pct_text = f" ({abs(comparison['pct_change']):.1f}%)"
        summary = (
            f"Spending is {direction} by {abs(comparison['delta']):.2f}{pct_text} this month compared with last month."
        )

        for row in changes[:3]:
            findings.append({
                "title": f"{row['label'].title()} changed the most",
                "detail": f"Current month {row['current_value']:.2f} vs prior month {row['prior_value']:.2f}, delta {row['delta']:.2f}.",
                "evidence": row
            })

        if changes and abs(changes[0]["delta"]) > abs(comparison["delta"]):
            critic["warnings"].append("The top category shift is larger than the net total change, which suggests offsetting movements across categories.")

        artifacts.append({
            "type": "table",
            "title": "Top category changes",
            "rows": changes
        })
        chart_payload = {
            "chart_type": "table",
            "rows": changes
        }

    elif request_type == "recurring_expenses":
        months = parsed_period.get("months", 6)
        recurring = recurring_expense_candidates(dashboard_id, months=months, user_id=user_id)
        trace_tools.append("recurring_expense_candidates")
        if not recurring:
            summary = "No strong recurring-expense candidates were found from the available expense history."
            critic["warnings"].append("Recurring detection is heuristic and depends on consistent merchant descriptions.")
        else:
            summary = f"Found {len(recurring)} recurring-expense candidates based on repeated merchants across multiple months."
            for row in recurring[:3]:
                findings.append({
                    "title": f"{row['merchant'].title()} looks recurring",
                    "detail": f"Seen in {row['months_seen']} months with an average charge of {row['average_amount']:.2f}.",
                    "evidence": row
                })
            critic["warnings"].append("Merchant normalization is heuristic, so some subscriptions may be grouped imperfectly.")

        artifacts.append({
            "type": "table",
            "title": "Recurring expense candidates",
            "rows": recurring
        })
        chart_payload = {
            "chart_type": "table",
            "rows": [
                {"label": row["merchant"], "value": row["average_amount"]}
                for row in recurring
            ]
        }

    elif request_type == "outlier_detection":
        days = parsed_period.get("days", 90)
        outliers = large_outlier_transactions(dashboard_id, days=days, user_id=user_id)
        trace_tools.append("large_outlier_transactions")
        if not outliers:
            summary = "No unusually large transactions were found."
        else:
            summary = f"Found {len(outliers)} large transactions worth reviewing."
            for row in outliers[:3]:
                findings.append({
                    "title": f"Large transaction: {row['description']}",
                    "detail": f"{row['amount']:.2f} in {row['category']} on {row['date']}.",
                    "evidence": row
                })

        artifacts.append({
            "type": "table",
            "title": "Large transactions",
            "rows": outliers
        })
        chart_payload = {
            "chart_type": "table",
            "rows": [
                {"label": row["description"], "value": row["amount"]}
                for row in outliers
            ]
        }

    elif request_type == "roommate_split":
        rows = spend_by_user(dashboard_id)
        trace_tools.append("spend_by_user")
        summary = "No roommate spending data was found."
        if rows:
            summary = f"{rows[0]['label']} has the highest tracked spend in the selected dashboard."
            for row in rows:
                findings.append({
                    "title": f"{row['label']} total spend",
                    "detail": f"Tracked spend totals {row['value']:.2f}.",
                    "evidence": row
                })
        artifacts.append({
            "type": "bar_chart",
            "title": "Spend by user",
            "labels": [row["label"] for row in rows],
            "data": [row["value"] for row in rows]
        })
        chart_payload = {
            "chart_type": "bar",
            "labels": [row["label"] for row in rows],
            "data": [row["value"] for row in rows]
        }

    else:
        months = parsed_period.get("months", 6)
        explicit_years = parsed_period.get("years")
        chart_type = "bar" if explicit_years or category_filter else "line"
        trend = monthly_spend_trend(
            dashboard_id,
            category=category_filter,
            months=months if not explicit_years else None,
            user_id=user_id,
            years=explicit_years
        )
        trace_tools.append("monthly_spend_trend")
        if not trend["labels"]:
            summary = "No expense trend data is available yet."
        else:
            first_value = trend["values"][0]
            last_value = trend["values"][-1]
            delta = last_value - first_value
            direction = "up" if delta >= 0 else "down"
            category_text = f" for {category_filter}" if category_filter else ""
            period_text = ""
            if explicit_years:
                period_text = f" in {', '.join(explicit_years)}"
            summary = f"Tracked spending{category_text} is trending {direction} by {abs(delta):.2f} across {len(trend['labels'])} periods{period_text}."
            findings.append({
                "title": "Trend direction",
                "detail": f"Latest month {last_value:.2f} versus starting month {first_value:.2f}.",
                "evidence": {"start_value": first_value, "end_value": last_value, "delta": delta}
            })
            if len(trend["values"]) < 3:
                critic["warnings"].append("Trend confidence is limited because there are fewer than 3 monthly data points.")

        artifacts.append({
            "type": "bar_chart" if chart_type == "bar" else "line_chart",
            "title": "Monthly spend trend",
            "labels": trend["labels"],
            "data": trend["values"]
        })
        chart_payload = {
            "chart_type": chart_type,
            "labels": trend["labels"],
            "data": trend["values"]
        }

    return {
        "request_type": request_type,
        "summary": summary,
        "findings": findings,
        "artifacts": artifacts,
        "critic": critic,
        "trace": {"tools_used": trace_tools},
        **chart_payload
    }
