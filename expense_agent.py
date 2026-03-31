"""Compatibility wrapper for the new expense analysis engine."""

from expense_analysis.agent import run_expense_analytics_agent
from expense_analysis.planner import plan_expense_request


def classify_expense_request(prompt: str):
    return plan_expense_request(prompt).workflow
