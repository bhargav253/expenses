from dataclasses import dataclass, field
from datetime import date
from typing import Any, Optional


@dataclass
class DateRange:
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    label: Optional[str] = None


@dataclass
class NormalizedExpenseRequest:
    prompt: str
    workflow: str
    date_range: DateRange
    granularity: str = "month"
    categories: list[str] = field(default_factory=list)
    category_a: Optional[str] = None
    category_b: Optional[str] = None
    merchant: Optional[str] = None
    user_id: Optional[int] = None
    artifact_preference: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class ExpenseAnalysisResponse:
    workflow: str
    summary: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    critic: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    trace: dict[str, Any] = field(default_factory=dict)
    chart_type: str = "table"
    labels: list[str] = field(default_factory=list)
    data: list[float] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
