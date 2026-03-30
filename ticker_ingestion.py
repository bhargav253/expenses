from __future__ import annotations

import json
import logging
import os
import socket
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
from sqlalchemy.exc import OperationalError
try:
    import yfinance as yf
except Exception:  # pragma: no cover - graceful fallback when optional dependency is absent
    yf = None

from extensions import db
from market_data import normalize_symbol
from models import (
    Asset,
    TickerDailyBar,
    TickerFetchState,
    TickerFundamentalsLatest,
    TickerIntradayBar,
    TickerSnapshotLatest,
    WorkerLease,
)


DEFAULT_RETRY_DELAY = timedelta(hours=6)
DEFAULT_INTRADAY_REFRESH_INTERVAL = timedelta(hours=1)
DEFAULT_FUNDAMENTALS_REFRESH_INTERVAL = timedelta(hours=24)
DEFAULT_LEASE_SECONDS = 90
DEFAULT_YFINANCE_BATCH_SIZE = 50
DEFAULT_YFINANCE_BATCH_INTERVAL = timedelta(minutes=1)
US_EASTERN = ZoneInfo("America/New_York")
UTC_TZ = timezone.utc
logger = logging.getLogger(__name__)
WORKER_STDOUT_ENABLED = os.environ.get("TICKER_WORKER_STDOUT", "true").lower() == "true"
WORKER_VERBOSE_IDLE = os.environ.get("TICKER_WORKER_VERBOSE_IDLE", "false").lower() == "true"


def utcnow():
    return datetime.utcnow()


def _to_eastern(value: datetime):
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC_TZ)
    return value.astimezone(US_EASTERN)


def _us_market_holidays(year: int):
    holidays = {
        _observed_date(date(year, 1, 1)),
        _nth_weekday(year, 1, 0, 3),   # MLK Day
        _nth_weekday(year, 2, 0, 3),   # Presidents Day
        _good_friday(year),
        _last_weekday(year, 5, 0),     # Memorial Day
        _observed_date(date(year, 6, 19)),
        _observed_date(date(year, 7, 4)),
        _nth_weekday(year, 9, 0, 1),   # Labor Day
        _nth_weekday(year, 11, 3, 4),  # Thanksgiving
        _observed_date(date(year, 12, 25)),
    }
    return holidays


def _observed_date(day: date):
    if day.weekday() == 5:
        return day - timedelta(days=1)
    if day.weekday() == 6:
        return day + timedelta(days=1)
    return day


def _nth_weekday(year: int, month: int, weekday: int, occurrence: int):
    current = date(year, month, 1)
    while current.weekday() != weekday:
        current += timedelta(days=1)
    current += timedelta(weeks=occurrence - 1)
    return current


def _last_weekday(year: int, month: int, weekday: int):
    if month == 12:
        current = date(year + 1, 1, 1) - timedelta(days=1)
    else:
        current = date(year, month + 1, 1) - timedelta(days=1)
    while current.weekday() != weekday:
        current -= timedelta(days=1)
    return current


def _easter_sunday(year: int):
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(year, month, day)


def _good_friday(year: int):
    return _easter_sunday(year) - timedelta(days=2)


def _market_session_info(now_utc: datetime | None = None):
    now_utc = now_utc or utcnow()
    now_et = _to_eastern(now_utc)
    current_date = now_et.date()
    is_weekend = current_date.weekday() >= 5
    holidays = _us_market_holidays(current_date.year)
    is_holiday = current_date in holidays
    open_at = now_et.replace(hour=9, minute=30, second=0, microsecond=0)
    close_at = now_et.replace(hour=16, minute=0, second=0, microsecond=0)
    is_trading_day = not is_weekend and not is_holiday
    during_market = is_trading_day and open_at <= now_et < close_at
    after_close = is_trading_day and now_et >= close_at
    before_open = is_trading_day and now_et < open_at
    return {
        "now_et": now_et,
        "trade_date": current_date,
        "is_trading_day": is_trading_day,
        "during_market": during_market,
        "after_close": after_close,
        "before_open": before_open,
        "market_open_et": open_at,
        "market_close_et": close_at,
    }


def _same_trade_date(timestamp: datetime | None, trade_date: date):
    if timestamp is None:
        return False
    return _to_eastern(timestamp).date() == trade_date


def _is_trading_day(trade_date: date):
    return trade_date.weekday() < 5 and trade_date not in _us_market_holidays(trade_date.year)


def _previous_trading_day(trade_date: date):
    current = trade_date - timedelta(days=1)
    while not _is_trading_day(current):
        current -= timedelta(days=1)
    return current


def _last_completed_trading_day(session_info):
    if session_info["is_trading_day"] and session_info["after_close"]:
        return session_info["trade_date"]
    return _previous_trading_day(session_info["trade_date"])


def _has_market_close_data(fetch_state: TickerFetchState, target_trade_date: date):
    market_close_trade_date = fetch_state.last_market_close_trade_date
    daily_bar_trade_date = fetch_state.last_daily_bar_date
    best_trade_date = max(
        [value for value in (market_close_trade_date, daily_bar_trade_date) if value is not None],
        default=None,
    )
    return best_trade_date is not None and best_trade_date >= target_trade_date


def _has_fundamentals_for_trade_date(fetch_state: TickerFetchState, target_trade_date: date):
    trade_date = fetch_state.last_fundamentals_trade_date
    return trade_date is not None and trade_date >= target_trade_date


def emit_worker_status(message):
    if WORKER_STDOUT_ENABLED:
        print(message, flush=True)


def _format_session_state(session_info):
    if not session_info["is_trading_day"]:
        return "market=closed"
    if session_info["during_market"]:
        return "market=open"
    if session_info["before_open"]:
        return "market=preopen"
    if session_info["after_close"]:
        return "market=postclose"
    return "market=closed"


def _is_sqlite_locked_error(exc: Exception):
    return "database is locked" in str(exc).lower()


def _safe_float(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_timestamp(value):
    if value is None:
        return None
    if hasattr(value, "to_pydatetime"):
        value = value.to_pydatetime()
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    return None


def _quote_payload_from_bars(rows: list[dict]):
    if not rows:
        return {}
    latest = rows[-1]
    return {
        "c": latest.get("close"),
        "o": latest.get("open"),
        "h": latest.get("high"),
        "l": latest.get("low"),
    }


def _http_status_code(exc):
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None)


def _percent_off(current, reference):
    if current is None or reference in (None, 0):
        return None
    return ((current - reference) / reference) * 100.0


def _annualized_return(total_return_percent, years):
    if total_return_percent is None or years <= 0:
        return None
    growth_multiple = 1 + (total_return_percent / 100.0)
    if growth_multiple <= 0:
        return None
    return ((growth_multiple ** (1 / years)) - 1) * 100.0


def _performance_percent(current, prior):
    if current is None or prior in (None, 0):
        return None
    return ((current - prior) / prior) * 100.0


def _series_value(values, window):
    if len(values) < window:
        return None
    subset = values[-window:]
    return sum(subset) / len(subset)


def _days_since_extreme(rows, extreme_key, high=True):
    if not rows:
        return None
    key_fn = max if high else min
    target_value = key_fn(row[extreme_key] for row in rows if row[extreme_key] is not None)
    target_rows = [row for row in rows if row[extreme_key] == target_value]
    if not target_rows:
        return None
    target_date = target_rows[-1]["bar_date"]
    return (rows[-1]["bar_date"] - target_date).days


def _average_volume(daily_bars, window):
    volumes = [row.volume for row in daily_bars if row.volume is not None]
    if len(volumes) < window:
        return None
    subset = volumes[-window:]
    return sum(subset) / len(subset)


def _window_performance(close_series, window):
    if not close_series or len(close_series) < max(window, 2):
        return None
    prior = close_series[-window]
    current = close_series[-1]
    return _performance_percent(current, prior)


def _window_annualized(close_series, window, years):
    total_return = _window_performance(close_series, window)
    return _annualized_return(total_return, years)


def refresh_ticker_snapshot_from_sources(asset: Asset, quote_payload: dict | None = None):
    quote_payload = quote_payload or {}
    fundamentals = TickerFundamentalsLatest.query.filter_by(asset_id=asset.id).first()
    daily_bars = (
        TickerDailyBar.query.filter_by(asset_id=asset.id)
        .order_by(TickerDailyBar.bar_date.asc())
        .all()
    )
    intraday_bars = (
        TickerIntradayBar.query.filter_by(asset_id=asset.id)
        .order_by(TickerIntradayBar.bar_timestamp.asc())
        .all()
    )

    snapshot = TickerSnapshotLatest.query.filter_by(asset_id=asset.id).first()
    if snapshot is None:
        snapshot = TickerSnapshotLatest(asset_id=asset.id)
        db.session.add(snapshot)

    close_series = [row.close for row in daily_bars if row.close is not None]
    latest_daily_bar = daily_bars[-1] if daily_bars else None
    latest_intraday_bar = intraday_bars[-1] if intraday_bars else None

    current_price = _safe_float(quote_payload.get("c"))
    if current_price is None:
        current_price = latest_intraday_bar.close if latest_intraday_bar and latest_intraday_bar.close is not None else latest_daily_bar.close if latest_daily_bar else None
    previous_close = _safe_float(quote_payload.get("pc"))
    if previous_close is None and latest_daily_bar and latest_daily_bar.close is not None:
        previous_close = latest_daily_bar.close

    snapshot.last_price = current_price
    snapshot.day_open = _safe_float(quote_payload.get("o"))
    snapshot.day_high = _safe_float(quote_payload.get("h"))
    snapshot.day_low = _safe_float(quote_payload.get("l"))
    snapshot.day_close = previous_close or (latest_daily_bar.close if latest_daily_bar else None)
    snapshot.today_change_percent = _performance_percent(current_price, previous_close)
    snapshot.market_cap = fundamentals.market_cap if fundamentals else snapshot.market_cap
    snapshot.pe_ratio = fundamentals.pe_ratio if fundamentals else snapshot.pe_ratio
    snapshot.peg_ratio = fundamentals.peg_ratio if fundamentals else snapshot.peg_ratio
    snapshot.revenue = fundamentals.revenue if fundamentals else snapshot.revenue
    snapshot.dividend_yield = fundamentals.dividend_yield if fundamentals else snapshot.dividend_yield
    snapshot.avg_volume = _average_volume(daily_bars, 20)
    snapshot.volume = latest_intraday_bar.volume if latest_intraday_bar and latest_intraday_bar.volume is not None else latest_daily_bar.volume if latest_daily_bar else None
    snapshot.quote_as_of = utcnow() if quote_payload else snapshot.quote_as_of
    snapshot.fundamentals_as_of = fundamentals.fetched_at if fundamentals else snapshot.fundamentals_as_of

    if daily_bars:
        trailing_252 = daily_bars[-252:] if len(daily_bars) >= 252 else daily_bars
        high_52 = max((row.high for row in trailing_252 if row.high is not None), default=None)
        low_52 = min((row.low for row in trailing_252 if row.low is not None), default=None)
        snapshot.fifty_two_week_high = high_52
        snapshot.fifty_two_week_low = low_52
        snapshot.days_since_52_week_high = _days_since_extreme(
            [{"bar_date": row.bar_date, "high": row.high} for row in trailing_252 if row.high is not None],
            "high",
            high=True,
        )
        snapshot.days_since_52_week_low = _days_since_extreme(
            [{"bar_date": row.bar_date, "low": row.low} for row in trailing_252 if row.low is not None],
            "low",
            high=False,
        )
        snapshot.sma_10 = _series_value(close_series, 10)
        snapshot.sma_20 = _series_value(close_series, 20)
        snapshot.moving_average_50 = _series_value(close_series, 50)
        snapshot.moving_average_200 = _series_value(close_series, 200)
        snapshot.price_performance_5d = _window_performance(close_series, 5)
        snapshot.price_performance_4w = _window_performance(close_series, 20)
        snapshot.price_performance_13w = _window_performance(close_series, 65)
        snapshot.price_performance_52w = _window_performance(close_series, 252)
        snapshot.annualized_return_1y = snapshot.price_performance_52w
        snapshot.annualized_return_3y = _window_annualized(close_series, 252 * 3, 3)
        snapshot.annualized_return_5y = _window_annualized(close_series, 252 * 5, 5)
        snapshot.annualized_return_10y = _window_annualized(close_series, 252 * 10, 10)
        snapshot.total_return = _window_performance(close_series, len(close_series))
        snapshot.percent_below_52_week_high = _percent_off(current_price, high_52)
        if snapshot.percent_below_52_week_high is not None:
            snapshot.percent_below_52_week_high *= -1
        snapshot.percent_above_52_week_low = _performance_percent(current_price, low_52)
        snapshot.percent_price_off_10day_sma = _percent_off(current_price, snapshot.sma_10)
        snapshot.percent_price_off_20day_sma = _percent_off(current_price, snapshot.sma_20)
        snapshot.percent_price_off_50day_sma = _percent_off(current_price, snapshot.moving_average_50)
        snapshot.percent_price_off_200day_sma = _percent_off(current_price, snapshot.moving_average_200)

    snapshot.updated_at = utcnow()
    db.session.flush()
    return snapshot


def get_or_create_fetch_state(asset: Asset) -> TickerFetchState:
    fetch_state = asset.ticker_fetch_state
    if fetch_state is not None:
        return fetch_state

    fetch_state = TickerFetchState(asset_id=asset.id)
    db.session.add(fetch_state)
    db.session.flush()
    return fetch_state


def enqueue_asset_refresh(asset: Asset, *, include_backfill=False, include_fundamentals=True, include_intraday=True, priority=False):
    fetch_state = get_or_create_fetch_state(asset)
    now = utcnow()
    if include_backfill:
        fetch_state.is_backfill_pending = True
    else:
        fetch_state.is_backfill_pending = False
    if include_fundamentals:
        fetch_state.is_fundamentals_pending = True
    if include_intraday:
        fetch_state.is_intraday_pending = True
    if priority:
        fetch_state.priority_requested_at = now
    fetch_state.next_retry_at = now
    fetch_state.updated_at = now
    asset.updated_at = now
    return fetch_state


class TickerIngestionError(Exception):
    pass


class InvalidTickerError(TickerIngestionError):
    pass


class FinnhubClient:
    base_url = "https://finnhub.io/api/v1"

    def __init__(self, api_key: str | None = None, session: requests.Session | None = None, timeout_seconds: int = 20):
        self.api_key = api_key or os.environ.get("FINNHUB_API_KEY")
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        if not self.api_key:
            raise TickerIngestionError("FINNHUB_API_KEY is required for the ticker ingestion worker")

    def _request(self, path: str, params: dict):
        response = self.session.get(
            f"{self.base_url}{path}",
            params={**params, "token": self.api_key},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def get_quote(self, symbol: str):
        return self._request("/quote", {"symbol": symbol})

    def get_company_profile(self, symbol: str):
        return self._request("/stock/profile2", {"symbol": symbol})

    def get_basic_financials(self, symbol: str):
        return self._request("/stock/metric", {"symbol": symbol, "metric": "all"})

    def get_candles(self, symbol: str, resolution: str, start_at: datetime, end_at: datetime):
        return self._request(
            "/stock/candle",
            {
                "symbol": symbol,
                "resolution": resolution,
                "from": int(start_at.timestamp()),
                "to": int(end_at.timestamp()),
            },
        )


class YFinanceBatchClient:
    def __init__(self, *, period: str = "5d", interval: str = "1h", timeout_seconds: int = 20):
        if yf is None:
            raise TickerIngestionError("yfinance is required for batch ticker price updates")
        self.period = period
        self.interval = interval
        self.timeout_seconds = timeout_seconds

    def get_hourly_bars(self, symbols: list[str]):
        normalized_symbols = [normalize_symbol(symbol) for symbol in symbols if normalize_symbol(symbol)]
        if not normalized_symbols:
            return {}

        data = yf.download(
            tickers=" ".join(normalized_symbols),
            period=self.period,
            interval=self.interval,
            group_by="ticker",
            auto_adjust=False,
            threads=True,
            progress=False,
            prepost=False,
            timeout=self.timeout_seconds,
            multi_level_index=True,
        )
        return self._parse_download(normalized_symbols, data)

    def _parse_download(self, symbols: list[str], dataframe):
        if dataframe is None or getattr(dataframe, "empty", True):
            return {}

        payload = {}
        for symbol in symbols:
            frame = self._extract_symbol_frame(dataframe, symbol)
            if frame is None or getattr(frame, "empty", True):
                continue

            bars = []
            frame = frame.dropna(how="all")
            for timestamp, row in frame.iterrows():
                bar_timestamp = _normalize_timestamp(timestamp)
                close_value = _safe_float(row.get("Close"))
                if bar_timestamp is None or close_value is None:
                    continue
                bars.append(
                    {
                        "timestamp": bar_timestamp,
                        "open": _safe_float(row.get("Open")),
                        "high": _safe_float(row.get("High")),
                        "low": _safe_float(row.get("Low")),
                        "close": close_value,
                        "volume": _safe_float(row.get("Volume")),
                    }
                )
            if bars:
                payload[symbol] = bars
        return payload

    @staticmethod
    def _extract_symbol_frame(dataframe, symbol: str):
        columns = getattr(dataframe, "columns", None)
        if columns is None:
            return None
        if getattr(columns, "nlevels", 1) == 1:
            return dataframe
        if symbol in columns.get_level_values(0):
            return dataframe[symbol]
        last_level = columns.nlevels - 1
        if symbol in columns.get_level_values(last_level):
            return dataframe.xs(symbol, axis=1, level=last_level)
        return None


@dataclass
class RateBudget:
    max_calls_per_minute: int

    def __post_init__(self):
        self._call_times = deque()

    def consume(self):
        if self.max_calls_per_minute <= 0:
            return
        now = time.monotonic()
        while self._call_times and now - self._call_times[0] >= 60:
            self._call_times.popleft()
        if len(self._call_times) >= self.max_calls_per_minute:
            sleep_seconds = 60 - (now - self._call_times[0])
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
            now = time.monotonic()
            while self._call_times and now - self._call_times[0] >= 60:
                self._call_times.popleft()
        self._call_times.append(time.monotonic())


class TickerIngestionWorker:
    def __init__(
        self,
        client: FinnhubClient | None = None,
        price_client: YFinanceBatchClient | None = None,
        *,
        owner_id: str | None = None,
        lease_name: str = "ticker_ingestion",
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        intraday_refresh_interval: timedelta = DEFAULT_INTRADAY_REFRESH_INTERVAL,
        fundamentals_refresh_interval: timedelta = DEFAULT_FUNDAMENTALS_REFRESH_INTERVAL,
        retry_delay: timedelta = DEFAULT_RETRY_DELAY,
        max_calls_per_minute: int | None = None,
        intraday_batch_size: int = DEFAULT_YFINANCE_BATCH_SIZE,
        intraday_batch_interval: timedelta = DEFAULT_YFINANCE_BATCH_INTERVAL,
    ):
        self.client = client or FinnhubClient()
        self.price_client = price_client or YFinanceBatchClient()
        self.owner_id = owner_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.lease_name = lease_name
        self.lease_seconds = lease_seconds
        self.intraday_refresh_interval = intraday_refresh_interval
        self.fundamentals_refresh_interval = fundamentals_refresh_interval
        self.retry_delay = retry_delay
        self.intraday_batch_size = intraday_batch_size
        self.intraday_batch_interval = intraday_batch_interval
        self.last_intraday_batch_at = None
        self.rate_budget = RateBudget(max_calls_per_minute or int(os.environ.get("FINNHUB_RATE_LIMIT_PER_MINUTE", "45")))

    def _priority_order(self, query):
        return query.order_by(
            TickerFetchState.priority_requested_at.is_(None).asc(),
            TickerFetchState.priority_requested_at.asc(),
            TickerFetchState.updated_at.asc(),
        )

    def acquire_lease(self):
        now = utcnow()
        lease = WorkerLease.query.filter_by(lease_name=self.lease_name).first()
        if lease is None:
            lease = WorkerLease(
                lease_name=self.lease_name,
                owner_id=self.owner_id,
                leased_until=now + timedelta(seconds=self.lease_seconds),
                heartbeat_at=now,
            )
            db.session.add(lease)
            db.session.commit()
            emit_worker_status(f"[ticker_worker] lease mode=new owner={self.owner_id}")
            return True

        if lease.owner_id == self.owner_id or lease.leased_until is None or lease.leased_until <= now:
            lease.owner_id = self.owner_id
            lease.leased_until = now + timedelta(seconds=self.lease_seconds)
            lease.heartbeat_at = now
            lease.updated_at = now
            db.session.commit()
            if WORKER_VERBOSE_IDLE:
                emit_worker_status(f"[ticker_worker] lease mode=renew owner={self.owner_id}")
            return True

        if WORKER_VERBOSE_IDLE:
            emit_worker_status(
                f"[ticker_worker] lease busy owner={lease.owner_id} until={lease.leased_until.isoformat() if lease.leased_until else 'none'}"
            )
        return False

    def heartbeat_lease(self):
        for attempt in range(3):
            try:
                lease = WorkerLease.query.filter_by(lease_name=self.lease_name, owner_id=self.owner_id).first()
                if lease is None:
                    return False
                now = utcnow()
                lease.leased_until = now + timedelta(seconds=self.lease_seconds)
                lease.heartbeat_at = now
                lease.updated_at = now
                db.session.commit()
                return True
            except OperationalError as exc:
                db.session.rollback()
                if not _is_sqlite_locked_error(exc) or attempt == 2:
                    raise
                time.sleep(0.25 * (attempt + 1))
        return False

    def run_forever(self, sleep_seconds: int = 10):
        emit_worker_status(f"[ticker_worker] started owner={self.owner_id} poll={sleep_seconds}s")
        while True:
            processed = self.run_once()
            if processed == 0:
                if WORKER_VERBOSE_IDLE:
                    emit_worker_status(f"[ticker_worker] idle sleep={sleep_seconds}s")
                time.sleep(sleep_seconds)

    def run_once(self):
        if not self.acquire_lease():
            return 0

        session_info = _market_session_info()
        self._clear_closed_market_priority_requests(session_info)
        progress = get_worker_status_summary()
        processed = 0
        intraday_candidates = self.select_intraday_candidates(limit=self.intraday_batch_size)
        fundamentals_candidates = self.select_fundamentals_candidates()
        backfill_candidates = self.select_backfill_candidates()
        priority_intraday_candidates = [state for state in intraday_candidates if state.priority_requested_at is not None]
        has_work = bool(intraday_candidates or fundamentals_candidates or backfill_candidates or progress["priority_pending"])
        if has_work or WORKER_VERBOSE_IDLE:
            emit_worker_status(
                "[ticker_worker] cycle "
                f"{_format_session_state(session_info)} "
                f"assets={progress['assets_total']} "
                f"ready={progress['snapshots_ready']} "
                f"priority={progress['priority_pending']} "
                f"queue(intraday={len(intraday_candidates)},fundamentals={len(fundamentals_candidates)},backfill={len(backfill_candidates)})"
            )
        if priority_intraday_candidates:
            self.heartbeat_lease()
            processed += self.process_intraday_batch(priority_intraday_candidates[:self.intraday_batch_size], priority=True)
        elif intraday_candidates and self._background_intraday_batch_due():
            self.heartbeat_lease()
            processed += self.process_intraday_batch(intraday_candidates, priority=False)

        for fetch_state in fundamentals_candidates:
            self.heartbeat_lease()
            processed += self.process_fundamentals(fetch_state)

        for fetch_state in backfill_candidates:
            self.heartbeat_lease()
            processed += self.process_backfill(fetch_state)
        self.heartbeat_lease()
        progress = get_worker_status_summary()
        if processed or has_work or WORKER_VERBOSE_IDLE:
            emit_worker_status(
                "[ticker_worker] cycle complete "
                f"processed={processed} "
                f"runnable={progress['runnable_pending']} "
                f"priority={progress['priority_pending']} "
                f"ready={progress['snapshots_ready']}"
            )
        return processed

    def _clear_closed_market_priority_requests(self, session_info):
        if session_info["is_trading_day"] and not session_info["before_open"]:
            return

        target_trade_date = _last_completed_trading_day(session_info)
        priority_states = (
            TickerFetchState.query.filter(TickerFetchState.priority_requested_at.isnot(None))
            .all()
        )
        if not priority_states:
            return

        message = (
            "Ticker refresh is only available on US trading days during the session or after the close update."
        )
        for fetch_state in priority_states:
            needs_market_data = not _has_market_close_data(fetch_state, target_trade_date)
            needs_fundamentals = not _has_fundamentals_for_trade_date(fetch_state, target_trade_date)
            if needs_market_data or needs_fundamentals:
                continue
            fetch_state.priority_requested_at = None
            fetch_state.last_error_at = utcnow()
            fetch_state.last_error_type = "MarketClosed"
            fetch_state.last_error_message = message
            fetch_state.updated_at = utcnow()
        db.session.commit()
        emit_worker_status("[ticker_worker] cleared priority refreshes because the market is closed")

    def _background_intraday_batch_due(self):
        if self.last_intraday_batch_at is None:
            return True
        return utcnow() - self.last_intraday_batch_at >= self.intraday_batch_interval

    def select_intraday_candidates(self, limit: int = DEFAULT_YFINANCE_BATCH_SIZE):
        session_info = _market_session_info()
        if session_info["before_open"]:
            return []

        now = utcnow()
        query = (
            TickerFetchState.query.join(Asset)
            .filter((Asset.is_active.is_(True)) | (Asset.is_active.is_(None)))
            .filter(Asset.status != "invalid")
            .filter((TickerFetchState.next_retry_at.is_(None)) | (TickerFetchState.next_retry_at <= now))
            .filter(
                (TickerFetchState.is_intraday_pending.is_(True))
                | (TickerFetchState.intraday_fetched_at.is_(None))
                | (TickerFetchState.intraday_fetched_at <= now - self.intraday_refresh_interval)
            )
        )
        query = self._priority_order(query.order_by(TickerFetchState.intraday_fetched_at.asc().nullsfirst()))
        candidates = query.limit(limit).all()
        if not session_info["is_trading_day"]:
            target_trade_date = _last_completed_trading_day(session_info)
            return [
                fetch_state
                for fetch_state in candidates
                if fetch_state.priority_requested_at is not None
            ]
        if session_info["after_close"]:
            return [
                fetch_state
                for fetch_state in candidates
                if fetch_state.priority_requested_at is not None or not _has_market_close_data(fetch_state, session_info["trade_date"])
            ]
        return candidates

    def select_fundamentals_candidates(self, limit: int = 25):
        session_info = _market_session_info()
        target_trade_date = _last_completed_trading_day(session_info)

        now = utcnow()
        query = (
            TickerFetchState.query.join(Asset)
            .filter((Asset.is_active.is_(True)) | (Asset.is_active.is_(None)))
            .filter(Asset.status != "invalid")
            .filter((TickerFetchState.next_retry_at.is_(None)) | (TickerFetchState.next_retry_at <= now))
        )
        query = self._priority_order(query.order_by(TickerFetchState.daily_fundamentals_fetched_at.asc().nullsfirst()))
        candidates = []
        for fetch_state in query.limit(limit * 3).all():
            if not session_info["is_trading_day"] and fetch_state.priority_requested_at is None:
                continue
            needs_refresh = fetch_state.is_fundamentals_pending or not _has_fundamentals_for_trade_date(fetch_state, target_trade_date)
            if needs_refresh:
                candidates.append(fetch_state)
            if len(candidates) >= limit:
                break
        return candidates

    def select_backfill_candidates(self, limit: int = 10):
        now = utcnow()
        query = (
            TickerFetchState.query.join(Asset)
            .filter((Asset.is_active.is_(True)) | (Asset.is_active.is_(None)))
            .filter(Asset.status != "invalid")
            .filter((TickerFetchState.next_retry_at.is_(None)) | (TickerFetchState.next_retry_at <= now))
            .filter(TickerFetchState.is_backfill_pending.is_(True))
        )
        query = self._priority_order(query.order_by(TickerFetchState.history_backfilled_at.asc().nullsfirst()))
        return query.limit(limit).all()

    def process_intraday_batch(self, fetch_states: list[TickerFetchState], *, priority: bool):
        if not fetch_states:
            return 0

        session_info = _market_session_info()
        target_trade_date = _last_completed_trading_day(session_info)
        if session_info["before_open"]:
            emit_worker_status("[ticker_worker] intraday batch skipped reason=before_open")
            return 0
        if not session_info["is_trading_day"]:
            eligible_states = [
                fetch_state
                for fetch_state in fetch_states
                if fetch_state.priority_requested_at is not None
            ]
            if not eligible_states:
                emit_worker_status("[ticker_worker] intraday batch skipped reason=market_closed")
                return 0
            fetch_states = eligible_states

        state_ids = [fetch_state.id for fetch_state in fetch_states]
        symbols = []
        for state_id in state_ids:
            fetch_state = TickerFetchState.query.get(state_id)
            if fetch_state is None or fetch_state.asset is None:
                continue
            symbols.append(fetch_state.asset.symbol)
            logger.info("ticker_worker intraday_start symbol=%s asset_id=%s", fetch_state.asset.symbol, fetch_state.asset.id)
            emit_worker_status(f"[ticker_worker] intraday start symbol={fetch_state.asset.symbol} asset_id={fetch_state.asset.id}")
            self._mark_attempt(fetch_state)

        if not symbols:
            return 0

        batch_label = "priority" if priority else "background"
        emit_worker_status(
            f"[ticker_worker] intraday batch start mode={batch_label} count={len(symbols)} symbols={','.join(symbols[:10])}"
        )

        try:
            bars_by_symbol = self.price_client.get_hourly_bars(symbols)
            self.last_intraday_batch_at = utcnow()
        except Exception as exc:
            for state_id in state_ids:
                fetch_state = TickerFetchState.query.get(state_id)
                if fetch_state is not None:
                    self._mark_failure(fetch_state, exc)
            logger.exception("ticker_worker intraday_batch_failed mode=%s symbols=%s", batch_label, ",".join(symbols))
            emit_worker_status(f"[ticker_worker] intraday batch failed mode={batch_label} error={exc}")
            return 0

        processed = 0
        failures = 0
        for state_id in state_ids:
            fetch_state = TickerFetchState.query.get(state_id)
            if fetch_state is None or fetch_state.asset is None:
                continue

            asset = fetch_state.asset
            try:
                bars = bars_by_symbol.get(asset.symbol) or []
                if not bars:
                    raise TickerIngestionError(f"No yfinance hourly data returned for {asset.symbol}")
                self._upsert_intraday_bars_from_rows(asset, bars)
                self._refresh_snapshot_from_sources(asset, quote_payload=_quote_payload_from_bars(bars))
                fetch_state.is_intraday_pending = False
                fetch_state.intraday_fetched_at = utcnow()
                fetch_state.last_market_refresh_at = utcnow()
                fetch_state.last_intraday_bar_timestamp = self._latest_intraday_timestamp(asset)
                if session_info["after_close"] or not session_info["is_trading_day"]:
                    fetch_state.last_market_close_trade_date = target_trade_date
                self._mark_success(fetch_state)
                logger.info("ticker_worker intraday_success symbol=%s asset_id=%s", asset.symbol, asset.id)
                emit_worker_status(f"[ticker_worker] intraday success symbol={asset.symbol} asset_id={asset.id}")
                processed += 1
            except Exception as exc:
                self._mark_failure(fetch_state, exc)
                logger.exception("ticker_worker intraday_failed symbol=%s asset_id=%s", asset.symbol, asset.id)
                emit_worker_status(f"[ticker_worker] intraday failed symbol={asset.symbol} asset_id={asset.id} error={exc}")
                failures += 1

        emit_worker_status(
            f"[ticker_worker] intraday batch complete mode={batch_label} success={processed} failed={failures}"
        )
        return processed

    def process_fundamentals(self, fetch_state: TickerFetchState):
        asset = fetch_state.asset
        session_info = _market_session_info()
        target_trade_date = _last_completed_trading_day(session_info)
        if not session_info["is_trading_day"] and _has_fundamentals_for_trade_date(fetch_state, target_trade_date):
            fetch_state.is_fundamentals_pending = False
            if not (
                fetch_state.is_intraday_pending
                or fetch_state.is_backfill_pending
            ):
                fetch_state.priority_requested_at = None
            fetch_state.updated_at = utcnow()
            db.session.commit()
            return 0
        logger.info("ticker_worker fundamentals_start symbol=%s asset_id=%s", asset.symbol, asset.id)
        emit_worker_status(f"[ticker_worker] fundamentals start symbol={asset.symbol} asset_id={asset.id}")
        self._mark_attempt(fetch_state)
        try:
            self.rate_budget.consume()
            payload = self.client.get_basic_financials(asset.symbol)
            profile = self._fetch_profile(asset.symbol)
            self._apply_profile(asset, profile)
            self._upsert_fundamentals_latest(asset, payload)
            self._refresh_snapshot_from_sources(asset)
            fetch_state.is_fundamentals_pending = False
            fetch_state.daily_fundamentals_fetched_at = utcnow()
            fetch_state.last_fundamentals_trade_date = target_trade_date
            self._mark_success(fetch_state)
            logger.info("ticker_worker fundamentals_success symbol=%s asset_id=%s", asset.symbol, asset.id)
            emit_worker_status(f"[ticker_worker] fundamentals success symbol={asset.symbol} asset_id={asset.id}")
            return 1
        except InvalidTickerError as exc:
            self._mark_invalid(fetch_state, asset, exc)
            logger.warning("ticker_worker fundamentals_invalid symbol=%s asset_id=%s error=%s", asset.symbol, asset.id, exc)
            emit_worker_status(f"[ticker_worker] fundamentals invalid symbol={asset.symbol} asset_id={asset.id} error={exc}")
            return 0
        except Exception as exc:
            self._mark_failure(fetch_state, exc)
            logger.exception("ticker_worker fundamentals_failed symbol=%s asset_id=%s", asset.symbol, asset.id)
            emit_worker_status(f"[ticker_worker] fundamentals failed symbol={asset.symbol} asset_id={asset.id} error={exc}")
            return 0

    def process_backfill(self, fetch_state: TickerFetchState):
        asset = fetch_state.asset
        logger.info("ticker_worker backfill_start symbol=%s asset_id=%s", asset.symbol, asset.id)
        emit_worker_status(f"[ticker_worker] historical backfill start symbol={asset.symbol} asset_id={asset.id}")
        self._mark_attempt(fetch_state)
        try:
            self._refresh_snapshot_from_sources(asset)
            fetch_state.is_backfill_pending = False
            fetch_state.history_backfilled_at = utcnow() if self._latest_daily_date(asset) else fetch_state.history_backfilled_at
            fetch_state.last_daily_bar_date = self._latest_daily_date(asset)
            self._mark_success(fetch_state)
            logger.info("ticker_worker backfill_skipped symbol=%s asset_id=%s", asset.symbol, asset.id)
            emit_worker_status(f"[ticker_worker] historical backfill skipped symbol={asset.symbol} asset_id={asset.id}; use Stooq import")
            return 1
        except InvalidTickerError as exc:
            self._mark_invalid(fetch_state, asset, exc)
            logger.warning("ticker_worker backfill_invalid symbol=%s asset_id=%s error=%s", asset.symbol, asset.id, exc)
            emit_worker_status(f"[ticker_worker] historical backfill invalid symbol={asset.symbol} asset_id={asset.id} error={exc}")
            return 0
        except Exception as exc:
            self._mark_failure(fetch_state, exc)
            logger.exception("ticker_worker backfill_failed symbol=%s asset_id=%s", asset.symbol, asset.id)
            emit_worker_status(f"[ticker_worker] historical backfill failed symbol={asset.symbol} asset_id={asset.id} error={exc}")
            return 0

    def _fetch_profile(self, symbol: str):
        self.rate_budget.consume()
        payload = self.client.get_company_profile(symbol)
        return payload or {}

    def _apply_profile(self, asset: Asset, profile: dict):
        if not profile:
            return
        asset.name = profile.get("name") or asset.name
        asset.exchange = profile.get("exchange") or asset.exchange
        asset.currency = profile.get("currency") or asset.currency
        asset.industry = profile.get("finnhubIndustry") or asset.industry
        asset.status = "active"
        asset.is_active = True
        asset.updated_at = utcnow()
        db.session.flush()

    def _upsert_daily_bars(self, asset: Asset, payload: dict):
        status = payload.get("s")
        if status not in {"ok", "no_data"}:
            raise TickerIngestionError(f"Unexpected daily candle status for {asset.symbol}: {status}")
        if status == "no_data":
            raise InvalidTickerError(f"No daily candle data returned for {asset.symbol}")

        existing = {
            row.bar_date: row
            for row in TickerDailyBar.query.filter_by(asset_id=asset.id).all()
        }
        timestamps = payload.get("t") or []
        opens = payload.get("o") or []
        highs = payload.get("h") or []
        lows = payload.get("l") or []
        closes = payload.get("c") or []
        volumes = payload.get("v") or []

        for index, timestamp in enumerate(timestamps):
            bar_date = datetime.utcfromtimestamp(timestamp).date()
            row = existing.get(bar_date)
            if row is None:
                row = TickerDailyBar(asset_id=asset.id, bar_date=bar_date)
                db.session.add(row)
            row.open = _safe_float(opens[index]) if index < len(opens) else None
            row.high = _safe_float(highs[index]) if index < len(highs) else None
            row.low = _safe_float(lows[index]) if index < len(lows) else None
            row.close = _safe_float(closes[index]) if index < len(closes) else None
            row.volume = _safe_float(volumes[index]) if index < len(volumes) else None
            row.source = "finnhub"
        db.session.flush()

    def _upsert_intraday_bars(self, asset: Asset, payload: dict):
        status = payload.get("s")
        if status not in {"ok", "no_data"}:
            raise TickerIngestionError(f"Unexpected intraday candle status for {asset.symbol}: {status}")
        if status == "no_data":
            return

        cutoff = utcnow() - timedelta(days=3)
        TickerIntradayBar.query.filter(
            TickerIntradayBar.asset_id == asset.id,
            TickerIntradayBar.bar_timestamp < cutoff,
        ).delete(synchronize_session=False)

        existing = {
            row.bar_timestamp: row
            for row in TickerIntradayBar.query.filter_by(asset_id=asset.id).all()
        }
        timestamps = payload.get("t") or []
        opens = payload.get("o") or []
        highs = payload.get("h") or []
        lows = payload.get("l") or []
        closes = payload.get("c") or []
        volumes = payload.get("v") or []

        for index, timestamp in enumerate(timestamps):
            bar_timestamp = datetime.utcfromtimestamp(timestamp)
            row = existing.get(bar_timestamp)
            if row is None:
                row = TickerIntradayBar(asset_id=asset.id, bar_timestamp=bar_timestamp)
                db.session.add(row)
            row.open = _safe_float(opens[index]) if index < len(opens) else None
            row.high = _safe_float(highs[index]) if index < len(highs) else None
            row.low = _safe_float(lows[index]) if index < len(lows) else None
            row.close = _safe_float(closes[index]) if index < len(closes) else None
            row.volume = _safe_float(volumes[index]) if index < len(volumes) else None
            row.source = "finnhub"
        db.session.flush()

    def _upsert_intraday_bars_from_rows(self, asset: Asset, rows: list[dict]):
        cutoff = utcnow() - timedelta(days=7)
        TickerIntradayBar.query.filter(
            TickerIntradayBar.asset_id == asset.id,
            TickerIntradayBar.bar_timestamp < cutoff,
        ).delete(synchronize_session=False)

        existing = {
            row.bar_timestamp: row
            for row in TickerIntradayBar.query.filter_by(asset_id=asset.id).all()
        }
        for payload in rows:
            bar_timestamp = payload["timestamp"]
            row = existing.get(bar_timestamp)
            if row is None:
                row = TickerIntradayBar(asset_id=asset.id, bar_timestamp=bar_timestamp)
                db.session.add(row)
            row.open = payload.get("open")
            row.high = payload.get("high")
            row.low = payload.get("low")
            row.close = payload.get("close")
            row.volume = payload.get("volume")
            row.source = "yfinance"
        db.session.flush()

    def _upsert_fundamentals_latest(self, asset: Asset, payload: dict):
        metric = payload.get("metric") or {}
        fundamentals = TickerFundamentalsLatest.query.filter_by(asset_id=asset.id).first()
        if fundamentals is None:
            fundamentals = TickerFundamentalsLatest(asset_id=asset.id)
            db.session.add(fundamentals)

        fundamentals.market_cap = _safe_float(metric.get("marketCapitalization"))
        fundamentals.pe_ratio = _safe_float(metric.get("peNormalizedAnnual") or metric.get("peTTM"))
        fundamentals.peg_ratio = _safe_float(metric.get("pegRatio"))
        fundamentals.revenue = _safe_float(
            metric.get("totalRevenueAnnual")
            or metric.get("revenuePerShareTTM")
            or metric.get("salesPerShareTTM")
        )
        fundamentals.dividend_yield = _safe_float(
            metric.get("dividendYieldIndicatedAnnual")
            or metric.get("dividendYield5Y")
        )
        fundamentals.shares_outstanding = _safe_float(metric.get("shareOutstanding"))
        fundamentals.as_of_date = utcnow().date()
        fundamentals.fetched_at = utcnow()
        fundamentals.raw_payload_json = json.dumps(payload, default=str)
        db.session.flush()

    def _refresh_snapshot_from_sources(self, asset: Asset, quote_payload: dict | None = None):
        refresh_ticker_snapshot_from_sources(asset, quote_payload=quote_payload)

    def _quote_change_percent(self, quote_payload, current_price):
        previous_close = _safe_float(quote_payload.get("pc"))
        return _performance_percent(current_price, previous_close)

    def _average_volume(self, daily_bars, window):
        return _average_volume(daily_bars, window)

    def _window_performance(self, close_series, window):
        return _window_performance(close_series, window)

    def _window_annualized(self, close_series, window, years):
        return _window_annualized(close_series, window, years)

    def _latest_daily_date(self, asset: Asset):
        row = (
            TickerDailyBar.query.filter_by(asset_id=asset.id)
            .order_by(TickerDailyBar.bar_date.desc())
            .first()
        )
        return row.bar_date if row else None

    def _latest_intraday_timestamp(self, asset: Asset):
        row = (
            TickerIntradayBar.query.filter_by(asset_id=asset.id)
            .order_by(TickerIntradayBar.bar_timestamp.desc())
            .first()
        )
        return row.bar_timestamp if row else None

    def _mark_attempt(self, fetch_state: TickerFetchState):
        fetch_state.last_attempt_at = utcnow()
        fetch_state.updated_at = utcnow()
        db.session.commit()

    def _mark_success(self, fetch_state: TickerFetchState):
        now = utcnow()
        fetch_state.last_success_at = now
        fetch_state.last_error_at = None
        fetch_state.last_error_type = None
        fetch_state.last_error_message = None
        fetch_state.failure_count = 0
        fetch_state.next_retry_at = now
        if not (
            fetch_state.is_intraday_pending
            or fetch_state.is_fundamentals_pending
            or fetch_state.is_backfill_pending
        ):
            fetch_state.priority_requested_at = None
        fetch_state.updated_at = now
        db.session.commit()

    def _mark_failure(self, fetch_state: TickerFetchState, exc: Exception):
        db.session.rollback()
        fetch_state = TickerFetchState.query.get(fetch_state.id)
        now = utcnow()
        fetch_state.last_error_at = now
        fetch_state.last_error_type = exc.__class__.__name__
        fetch_state.last_error_message = str(exc)
        fetch_state.failure_count = (fetch_state.failure_count or 0) + 1
        fetch_state.next_retry_at = now + self.retry_delay
        fetch_state.priority_requested_at = None
        fetch_state.updated_at = now
        db.session.commit()

    def _mark_invalid(self, fetch_state: TickerFetchState, asset: Asset, exc: Exception):
        db.session.rollback()
        fetch_state = TickerFetchState.query.get(fetch_state.id)
        asset = Asset.query.get(asset.id)
        now = utcnow()
        asset.status = "invalid"
        asset.is_active = False
        asset.updated_at = now
        fetch_state.last_error_at = now
        fetch_state.last_error_type = exc.__class__.__name__
        fetch_state.last_error_message = str(exc)
        fetch_state.next_retry_at = now + self.retry_delay
        fetch_state.priority_requested_at = None
        fetch_state.updated_at = now
        db.session.commit()


def seed_assets_from_symbols(symbols: list[str], *, added_source: str = "seed"):
    normalized_symbols = [normalize_symbol(symbol) for symbol in symbols if normalize_symbol(symbol)]
    created_assets = []
    for symbol in normalized_symbols:
        asset = Asset.query.filter_by(symbol=symbol).first()
        if asset is None:
            asset = Asset(symbol=symbol, asset_type="equity", added_source=added_source, status="active")
            db.session.add(asset)
            db.session.flush()
            created_assets.append(asset)
        enqueue_asset_refresh(asset)
    db.session.commit()
    return created_assets


def get_worker_status_summary():
    assets_total = Asset.query.count()
    snapshots_ready = TickerSnapshotLatest.query.count()
    session_info = _market_session_info()
    target_trade_date = _last_completed_trading_day(session_info)
    pending_assets = (
        TickerFetchState.query.filter(
            (TickerFetchState.is_backfill_pending.is_(True))
            | (TickerFetchState.is_fundamentals_pending.is_(True))
            | (TickerFetchState.is_intraday_pending.is_(True))
        ).count()
    )
    runnable_intraday = 0
    for fetch_state in TickerFetchState.query.all():
        if fetch_state.priority_requested_at is not None and not _has_market_close_data(fetch_state, target_trade_date):
            runnable_intraday += 1
            continue
        if session_info["before_open"]:
            continue
        if not session_info["is_trading_day"]:
            continue
        if session_info["after_close"]:
            if not _has_market_close_data(fetch_state, session_info["trade_date"]):
                runnable_intraday += 1
        elif (
            fetch_state.is_intraday_pending
            or fetch_state.intraday_fetched_at is None
            or fetch_state.intraday_fetched_at <= utcnow() - DEFAULT_INTRADAY_REFRESH_INTERVAL
        ):
            runnable_intraday += 1
    runnable_fundamentals = 0
    for fetch_state in TickerFetchState.query.all():
        if fetch_state.priority_requested_at is None and not session_info["is_trading_day"]:
            continue
        if fetch_state.is_fundamentals_pending or not _has_fundamentals_for_trade_date(fetch_state, target_trade_date):
            runnable_fundamentals += 1
    runnable_backfill = TickerFetchState.query.filter(TickerFetchState.is_backfill_pending.is_(True)).count()
    return {
        "assets_total": assets_total,
        "assets_active": Asset.query.filter_by(is_active=True).count(),
        "assets_invalid": Asset.query.filter_by(status="invalid").count(),
        "backfill_pending": TickerFetchState.query.filter_by(is_backfill_pending=True).count(),
        "fundamentals_pending": TickerFetchState.query.filter_by(is_fundamentals_pending=True).count(),
        "intraday_pending": TickerFetchState.query.filter_by(is_intraday_pending=True).count(),
        "priority_pending": TickerFetchState.query.filter(TickerFetchState.priority_requested_at.isnot(None)).count(),
        "failed_rows": TickerFetchState.query.filter(TickerFetchState.failure_count > 0).count(),
        "snapshots_ready": snapshots_ready,
        "done_assets": snapshots_ready,
        "pending_assets": pending_assets,
        "runnable_pending": runnable_intraday + runnable_fundamentals + runnable_backfill,
        "runnable_intraday": runnable_intraday,
        "runnable_fundamentals": runnable_fundamentals,
        "runnable_backfill": runnable_backfill,
        "fundamentals_ready": TickerFundamentalsLatest.query.count(),
        "daily_bars": TickerDailyBar.query.count(),
        "intraday_bars": TickerIntradayBar.query.count(),
        "lease": _serialize_lease(WorkerLease.query.filter_by(lease_name="ticker_ingestion").first()),
    }


def _serialize_lease(lease):
    if lease is None:
        return None
    return {
        "lease_name": lease.lease_name,
        "owner_id": lease.owner_id,
        "leased_until": lease.leased_until.isoformat() if lease.leased_until else None,
        "heartbeat_at": lease.heartbeat_at.isoformat() if lease.heartbeat_at else None,
    }
