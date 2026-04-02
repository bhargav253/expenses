from __future__ import annotations

from collections import defaultdict
import math
import re
from typing import Optional

from sqlalchemy import func

from extensions import db
from models import Expense, User

from .contracts import DateRange


def _base_query(dashboard_id: int, user_id: Optional[int] = None):
    query = Expense.query.filter_by(dashboard_id=dashboard_id)
    if user_id:
        query = query.filter_by(user_id=user_id)
    return query


def _apply_date_range(query, date_range: DateRange):
    if date_range.start_date:
        query = query.filter(Expense.date >= date_range.start_date)
    if date_range.end_date:
        query = query.filter(Expense.date < date_range.end_date)
    return query


def _period_key_expr(granularity: str):
    dialect = db.engine.dialect.name
    if dialect == "postgresql":
        return func.to_char(Expense.date, "YYYY") if granularity == "year" else func.to_char(Expense.date, "YYYY-MM")
    return func.strftime("%Y", Expense.date) if granularity == "year" else func.strftime("%Y-%m", Expense.date)


def category_period_totals(dashboard_id: int, category: str, date_range: DateRange, granularity: str = "month", user_id: Optional[int] = None):
    query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range)
    results = (
        query.filter(func.lower(Expense.category) == category.lower())
        .with_entities(
            _period_key_expr(granularity).label("period"),
            func.sum(Expense.amount).label("total"),
        )
        .group_by("period")
        .order_by("period")
        .all()
    )
    rows = [{"period": row.period, "value": float(row.total or 0)} for row in results]
    return rows


def category_vs_category_period_totals(dashboard_id: int, category_a: str, category_b: str, date_range: DateRange, granularity: str = "month", user_id: Optional[int] = None):
    rows_a = category_period_totals(dashboard_id, category_a, date_range, granularity, user_id)
    rows_b = category_period_totals(dashboard_id, category_b, date_range, granularity, user_id)
    map_a = {row["period"]: row["value"] for row in rows_a}
    map_b = {row["period"]: row["value"] for row in rows_b}
    periods = sorted(set(map_a) | set(map_b))
    combined = []
    for period in periods:
        value_a = map_a.get(period, 0.0)
        value_b = map_b.get(period, 0.0)
        combined.append(
            {
                "period": period,
                "category_a_value": value_a,
                "category_b_value": value_b,
                "delta": value_a - value_b,
            }
        )
    return combined


def category_multi_period_totals(dashboard_id: int, categories: list[str], date_range: DateRange, granularity: str = "month", user_id: Optional[int] = None):
    series_map = {}
    periods = set()
    for category in categories:
        rows = category_period_totals(dashboard_id, category, date_range, granularity, user_id)
        series_map[category] = {row["period"]: row["value"] for row in rows}
        periods.update(series_map[category].keys())

    ordered_periods = sorted(periods)
    combined = []
    for period in ordered_periods:
        row = {"period": period}
        for category in categories:
            row[category] = float(series_map.get(category, {}).get(period, 0.0))
        combined.append(row)
    return combined


def category_breakdown_for_period(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None):
    query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range)
    results = (
        query.with_entities(
            func.lower(Expense.category).label("category"),
            func.sum(Expense.amount).label("total"),
        )
        .group_by("category")
        .order_by(func.sum(Expense.amount).desc())
        .all()
    )
    rows = [{"label": row.category, "value": float(row.total or 0)} for row in results]
    total = sum(row["value"] for row in rows)
    for row in rows:
        row["share_pct"] = (row["value"] / total * 100) if total else 0.0
    return {"rows": rows, "total": total}


def period_total(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None) -> float:
    query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range)
    total = query.with_entities(func.sum(Expense.amount)).scalar()
    return float(total or 0.0)


def available_period_coverage(dashboard_id: int, date_range: DateRange, granularity: str = "month", user_id: Optional[int] = None):
    query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range)
    results = (
        query.with_entities(_period_key_expr(granularity).label("period"), func.count(Expense.id).label("count"))
        .group_by("period")
        .order_by("period")
        .all()
    )
    return [{"period": row.period, "count": int(row.count or 0)} for row in results]


def normalize_merchant(description: str) -> str:
    raw = (description or "").lower().strip()
    raw = re.sub(r"[^a-z0-9\s]", " ", raw)
    raw = re.sub(r"\s+", " ", raw)
    tokens = [token for token in raw.split() if token not in {"pos", "debit", "card", "purchase", "payment", "aplpay", "null"}]
    return " ".join(tokens[:4]).strip() or "unknown"


def category_change_report(dashboard_id: int, current_range: DateRange, prior_range: DateRange, user_id: Optional[int] = None, limit: int = 6):
    current = {row["label"]: row["value"] for row in category_breakdown_for_period(dashboard_id, current_range, user_id)["rows"]}
    prior = {row["label"]: row["value"] for row in category_breakdown_for_period(dashboard_id, prior_range, user_id)["rows"]}
    categories = sorted(set(current) | set(prior))
    rows = []
    for category in categories:
        current_value = current.get(category, 0.0)
        prior_value = prior.get(category, 0.0)
        delta = current_value - prior_value
        rows.append({
            "label": category,
            "current_value": current_value,
            "prior_value": prior_value,
            "delta": delta,
            "value": delta,
        })
    rows.sort(key=lambda row: abs(row["delta"]), reverse=True)
    return rows[:limit]


def merchant_change_report(dashboard_id: int, current_range: DateRange, prior_range: DateRange, user_id: Optional[int] = None, limit: int = 8):
    def totals_for_range(date_range: DateRange):
        query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range).all()
        totals = defaultdict(float)
        for expense in query:
            totals[normalize_merchant(expense.description)] += float(expense.amount or 0)
        return totals

    current = totals_for_range(current_range)
    prior = totals_for_range(prior_range)
    merchants = sorted(set(current) | set(prior))
    rows = []
    for merchant in merchants:
        current_value = current.get(merchant, 0.0)
        prior_value = prior.get(merchant, 0.0)
        delta = current_value - prior_value
        rows.append({
            "merchant": merchant,
            "current_value": current_value,
            "prior_value": prior_value,
            "delta": delta,
        })
    rows.sort(key=lambda row: abs(row["delta"]), reverse=True)
    return rows[:limit]


def merchant_spike_report(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None, limit: int = 6):
    expenses = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range).order_by(Expense.amount.desc()).all()
    grouped = defaultdict(list)
    for expense in expenses:
        grouped[normalize_merchant(expense.description)].append(expense)
    rows = []
    for merchant, merchant_expenses in grouped.items():
        total = sum(float(exp.amount or 0) for exp in merchant_expenses)
        max_amount = max(float(exp.amount or 0) for exp in merchant_expenses)
        rows.append({
            "merchant": merchant,
            "transactions": len(merchant_expenses),
            "total": total,
            "max_amount": max_amount,
        })
    rows.sort(key=lambda row: (row["max_amount"], row["total"]), reverse=True)
    return rows[:limit]


def recurring_expense_candidates(dashboard_id: int, date_range: Optional[DateRange] = None, user_id: Optional[int] = None, limit: int = 8):
    query = _base_query(dashboard_id, user_id=user_id)
    if date_range:
        query = _apply_date_range(query, date_range)
    expenses = query.order_by(Expense.date.desc()).all()
    merchant_map = defaultdict(list)
    for expense in expenses:
        merchant_map[normalize_merchant(expense.description)].append(expense)
    candidates = []
    for merchant, merchant_expenses in merchant_map.items():
        month_keys = {expense.date.strftime("%Y-%m") for expense in merchant_expenses}
        if len(month_keys) < 3:
            continue
        amounts = [float(exp.amount or 0) for exp in merchant_expenses]
        candidates.append({
            "merchant": merchant,
            "months_seen": len(month_keys),
            "average_amount": round(sum(amounts) / len(amounts), 2),
            "latest_amount": round(amounts[0], 2),
            "amount_variation": round(max(amounts) - min(amounts), 2),
        })
    candidates.sort(key=lambda row: (row["months_seen"], row["average_amount"]), reverse=True)
    return candidates[:limit]


def category_split_by_user(dashboard_id: int, date_range: DateRange, category: Optional[str] = None, user_id: Optional[int] = None):
    query = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range)
    if category:
        query = query.filter(func.lower(Expense.category) == category.lower())
    results = (
        query.join(User, User.id == Expense.user_id)
        .with_entities(User.name.label("user_name"), func.sum(Expense.amount).label("total"))
        .group_by(User.name)
        .order_by(func.sum(Expense.amount).desc())
        .all()
    )
    return [{"label": row.user_name, "value": float(row.total or 0)} for row in results]


def merchant_period_totals(dashboard_id: int, merchant: str, date_range: DateRange, granularity: str = "month", user_id: Optional[int] = None):
    expenses = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range).all()
    totals = defaultdict(float)
    needle = merchant.lower().strip()
    for expense in expenses:
        normalized = normalize_merchant(expense.description)
        if needle not in normalized:
            continue
        key = expense.date.strftime("%Y") if granularity == "year" else expense.date.strftime("%Y-%m")
        totals[key] += float(expense.amount or 0)
    return [{"period": period, "value": totals[period]} for period in sorted(totals)]


def large_outlier_transactions(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None, limit: int = 6):
    expenses = _apply_date_range(_base_query(dashboard_id, user_id=user_id), date_range).order_by(Expense.date.desc()).all()
    if not expenses:
        return []
    amounts = [float(exp.amount or 0) for exp in expenses]
    mean = sum(amounts) / len(amounts)
    variance = sum((amt - mean) ** 2 for amt in amounts) / len(amounts)
    threshold = mean + (2 * math.sqrt(variance))
    rows = []
    for expense in expenses:
        amount = float(expense.amount or 0)
        if amount >= threshold or len(rows) < limit:
            rows.append({
                "date": expense.date.isoformat(),
                "description": expense.description,
                "category": expense.category,
                "amount": amount,
                "user_name": expense.user.name if expense.user else "Unknown",
            })
        if len(rows) >= limit:
            break
    return rows


def savings_opportunity_report(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None, limit: int = 6):
    breakdown = category_breakdown_for_period(dashboard_id, date_range, user_id)["rows"]
    recurring = recurring_expense_candidates(dashboard_id, date_range, user_id, limit=limit)
    discretionary = [row for row in breakdown if row["label"] in {"restaurant", "shopping", "vacation", "service", "misc"}]
    report = []
    for row in discretionary[:limit]:
        report.append({
            "type": "category",
            "label": row["label"],
            "value": row["value"],
            "reason": f"{row['label'].title()} is among the largest discretionary buckets.",
        })
    for row in recurring[: max(0, limit - len(report))]:
        report.append({
            "type": "recurring",
            "label": row["merchant"],
            "value": row["average_amount"],
            "reason": f"Recurring charge seen in {row['months_seen']} months.",
        })
    return report[:limit]


def monthly_review_report(dashboard_id: int, date_range: DateRange, user_id: Optional[int] = None):
    breakdown = category_breakdown_for_period(dashboard_id, date_range, user_id)
    total = breakdown["total"]
    top_categories = breakdown["rows"][:5]
    top_outliers = large_outlier_transactions(dashboard_id, date_range, user_id, limit=5)
    user_split = category_split_by_user(dashboard_id, date_range, user_id=user_id)
    recurring = recurring_expense_candidates(dashboard_id, date_range, user_id, limit=5)
    return {
        "total": total,
        "top_categories": top_categories,
        "top_outliers": top_outliers,
        "user_split": user_split,
        "recurring": recurring,
    }
