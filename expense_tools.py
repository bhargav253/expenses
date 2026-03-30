from collections import defaultdict
from datetime import date, datetime
import math
import re

from sqlalchemy import func

from extensions import db
from models import Expense, User


def month_bounds(year: int, month: int):
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


def parse_relative_period(query_text: str):
    today = datetime.utcnow().date()
    text = (query_text or "").lower()
    years = sorted(set(re.findall(r"20\d{2}", text)))

    if "last 6 month" in text or "last six month" in text or "6 months" in text:
        return {"months": 6, "years": years}
    if "last 12 month" in text or "12 months" in text or "1 year" in text:
        return {"months": 12, "years": years}
    if "last 3 month" in text or "3 months" in text:
        return {"months": 3, "years": years}
    if "this month" in text or "current month" in text:
        return {"current_month": (today.year, today.month), "years": years}
    if "last month" in text or "previous month" in text:
        year = today.year
        month = today.month - 1
        if month == 0:
            year -= 1
            month = 12
        return {"single_month": (year, month), "years": years}
    if "last 90 days" in text or "90 days" in text:
        return {"days": 90, "years": years}
    return {"months": 6, "years": years}


def normalize_merchant(description: str):
    raw = (description or "").lower().strip()
    raw = re.sub(r"[^a-z0-9\s]", " ", raw)
    raw = re.sub(r"\s+", " ", raw)
    tokens = [token for token in raw.split() if token not in {"pos", "debit", "card", "purchase", "payment"}]
    return " ".join(tokens[:4]).strip() or "unknown"


def base_expense_query(dashboard_id, user_id=None):
    query = Expense.query.filter_by(dashboard_id=dashboard_id)
    if user_id:
        query = query.filter_by(user_id=user_id)
    return query


def monthly_spend_trend(dashboard_id, category=None, months=6, user_id=None, years=None):
    query = base_expense_query(dashboard_id, user_id=user_id)
    if category:
        query = query.filter(func.lower(Expense.category) == category.lower())
    if years:
        query = query.filter(func.strftime('%Y', Expense.date).in_(years))

    results = (
        query.with_entities(
            func.strftime('%Y-%m', Expense.date).label('month'),
            func.sum(Expense.amount).label('total')
        )
        .group_by('month')
        .order_by('month')
        .all()
    )

    trimmed = results[-months:] if months else results
    labels = [row.month for row in trimmed]
    values = [float(row.total or 0) for row in trimmed]
    return {
        "labels": labels,
        "values": values,
        "rows": [{"label": label, "value": value} for label, value in zip(labels, values)]
    }


def category_breakdown(dashboard_id, start_date=None, end_date=None, user_id=None, limit=8):
    query = base_expense_query(dashboard_id, user_id=user_id)
    if start_date:
        query = query.filter(Expense.date >= start_date)
    if end_date:
        query = query.filter(Expense.date < end_date)

    results = (
        query.with_entities(
            Expense.category.label('category'),
            func.sum(Expense.amount).label('total')
        )
        .group_by(Expense.category)
        .order_by(func.sum(Expense.amount).desc())
        .all()
    )

    labels = [row.category for row in results[:limit]]
    values = [float(row.total or 0) for row in results[:limit]]
    total = sum(values)
    return {
        "labels": labels,
        "values": values,
        "total": total,
        "rows": [{"label": label, "value": value} for label, value in zip(labels, values)]
    }


def period_total(dashboard_id, start_date, end_date, user_id=None):
    query = base_expense_query(dashboard_id, user_id=user_id)
    total = (
        query.filter(Expense.date >= start_date, Expense.date < end_date)
        .with_entities(func.sum(Expense.amount))
        .scalar()
    )
    return float(total or 0)


def category_change_report(dashboard_id, current_period, prior_period, user_id=None, limit=6):
    current_start, current_end = current_period
    prior_start, prior_end = prior_period

    def category_totals(start_date, end_date):
        query = base_expense_query(dashboard_id, user_id=user_id)
        rows = (
            query.filter(Expense.date >= start_date, Expense.date < end_date)
            .with_entities(
                func.lower(Expense.category).label('category'),
                func.sum(Expense.amount).label('total')
            )
            .group_by('category')
            .all()
        )
        return {row.category: float(row.total or 0) for row in rows}

    current = category_totals(current_start, current_end)
    prior = category_totals(prior_start, prior_end)
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
            "value": delta,
            "delta": delta
        })

    rows.sort(key=lambda row: abs(row["delta"]), reverse=True)
    return rows[:limit]


def period_compare_summary(dashboard_id, current_period, prior_period, user_id=None):
    current_total = period_total(dashboard_id, current_period[0], current_period[1], user_id=user_id)
    prior_total = period_total(dashboard_id, prior_period[0], prior_period[1], user_id=user_id)
    delta = current_total - prior_total
    pct_change = None
    if prior_total:
        pct_change = (delta / prior_total) * 100
    return {
        "current_total": current_total,
        "prior_total": prior_total,
        "delta": delta,
        "pct_change": pct_change
    }


def recurring_expense_candidates(dashboard_id, months=6, user_id=None, limit=8):
    trend = monthly_spend_trend(dashboard_id, months=months, user_id=user_id)
    if not trend["labels"]:
        return []

    query = base_expense_query(dashboard_id, user_id=user_id)
    expenses = query.order_by(Expense.date.desc()).all()

    merchant_map = defaultdict(list)
    for expense in expenses:
        merchant_map[normalize_merchant(expense.description)].append(expense)

    candidates = []
    for merchant, merchant_expenses in merchant_map.items():
        if len(merchant_expenses) < 3:
            continue

        month_keys = {expense.date.strftime('%Y-%m') for expense in merchant_expenses}
        if len(month_keys) < 3:
            continue

        amounts = [expense.amount for expense in merchant_expenses]
        avg_amount = sum(amounts) / len(amounts)
        spread = max(amounts) - min(amounts)

        candidates.append({
            "merchant": merchant,
            "months_seen": len(month_keys),
            "average_amount": round(avg_amount, 2),
            "latest_amount": round(merchant_expenses[0].amount, 2),
            "amount_variation": round(spread, 2)
        })

    candidates.sort(key=lambda row: (row["months_seen"], row["average_amount"]), reverse=True)
    return candidates[:limit]


def large_outlier_transactions(dashboard_id, days=90, user_id=None, limit=6):
    query = base_expense_query(dashboard_id, user_id=user_id)
    expenses = query.order_by(Expense.date.desc()).all()
    if not expenses:
        return []

    amount_values = [expense.amount for expense in expenses]
    mean_value = sum(amount_values) / len(amount_values)
    variance = sum((value - mean_value) ** 2 for value in amount_values) / len(amount_values)
    std_dev = math.sqrt(variance)
    threshold = mean_value + (2 * std_dev)

    outliers = []
    for expense in expenses:
        if expense.amount >= threshold or len(outliers) < limit:
            outliers.append({
                "date": expense.date.isoformat(),
                "description": expense.description,
                "category": expense.category,
                "amount": round(expense.amount, 2),
                "user_name": expense.user.name if expense.user else "Unknown"
            })
        if len(outliers) >= limit:
            break

    return outliers


def spend_by_user(dashboard_id, start_date=None, end_date=None):
    query = base_expense_query(dashboard_id)
    if start_date:
        query = query.filter(Expense.date >= start_date)
    if end_date:
        query = query.filter(Expense.date < end_date)

    results = (
        query.join(User, User.id == Expense.user_id)
        .with_entities(User.name.label('user_name'), func.sum(Expense.amount).label('total'))
        .group_by(User.name)
        .order_by(func.sum(Expense.amount).desc())
        .all()
    )

    return [{"label": row.user_name, "value": float(row.total or 0)} for row in results]
