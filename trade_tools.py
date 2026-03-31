from __future__ import annotations

from datetime import datetime, timedelta

from models import Asset, TickerDailyBar, TickerFundamentalsLatest, TickerSnapshotLatest, WatchlistItem


MIN_HISTORY_BARS = 60
SNAPSHOT_STALE_AFTER = timedelta(hours=2)
FUNDAMENTALS_STALE_AFTER = timedelta(days=14)
REQUIRED_FUNDAMENTAL_FIELDS = (
    "pe_ratio",
    "forward_pe",
    "peg_ratio",
    "revenue_growth",
    "eps_growth",
)


def _safe_round(value, digits=2):
    if value is None:
        return None
    return round(float(value), digits)


def _mean(values):
    if not values:
        return None
    return sum(values) / len(values)


def _sample(values, length):
    if length <= 0:
        return []
    return values[-length:]


def _pct_change(current, previous):
    if current is None or previous in (None, 0):
        return None
    return ((current - previous) / previous) * 100.0


def _compute_rsi(closes, period=14):
    if len(closes) <= period:
        return None

    gains = []
    losses = []
    for index in range(1, len(closes)):
        delta = closes[index] - closes[index - 1]
        gains.append(max(delta, 0.0))
        losses.append(abs(min(delta, 0.0)))

    recent_gains = _sample(gains, period)
    recent_losses = _sample(losses, period)
    avg_gain = _mean(recent_gains) or 0.0
    avg_loss = _mean(recent_losses) or 0.0
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return 100.0 - (100.0 / (1.0 + rs))


def _compute_atr(bars, period=14):
    if len(bars) <= period:
        return None

    true_ranges = []
    for index, bar in enumerate(bars):
        high = float(bar.high) if bar.high is not None else None
        low = float(bar.low) if bar.low is not None else None
        close = float(bar.close) if bar.close is not None else None
        prev_close = float(bars[index - 1].close) if index > 0 and bars[index - 1].close is not None else None
        if high is None or low is None:
            continue
        components = [high - low]
        if prev_close is not None:
            components.extend([abs(high - prev_close), abs(low - prev_close)])
        true_ranges.append(max(components))

    if not true_ranges:
        return None
    return _mean(_sample(true_ranges, period))


def load_trade_agent_context(symbol: str):
    normalized = (symbol or "").strip().upper()
    if not normalized:
        return None

    asset = Asset.query.filter_by(symbol=normalized).first()
    if not asset:
        return None

    snapshot = TickerSnapshotLatest.query.filter_by(asset_id=asset.id).first()
    fundamentals = TickerFundamentalsLatest.query.filter_by(asset_id=asset.id).first()
    bars = (
        TickerDailyBar.query.filter_by(asset_id=asset.id)
        .order_by(TickerDailyBar.bar_date.asc())
        .all()
    )
    watchlist_items = WatchlistItem.query.filter_by(asset_id=asset.id).all()
    return {
        "asset": asset,
        "snapshot": snapshot,
        "fundamentals": fundamentals,
        "bars": bars,
        "watchlist_items": watchlist_items,
    }


def evaluate_trade_agent_freshness(snapshot, fundamentals, bars):
    now = datetime.utcnow()
    snapshot_as_of = snapshot.quote_as_of if snapshot else None
    fundamentals_as_of = fundamentals.fetched_at if fundamentals else None
    daily_bars_as_of = bars[-1].bar_date.isoformat() if bars else None
    warnings = []

    if not snapshot:
        warnings.append("No latest ticker snapshot is available.")
    elif snapshot_as_of and now - snapshot_as_of > SNAPSHOT_STALE_AFTER:
        warnings.append("Latest ticker snapshot is older than the expected freshness threshold.")

    if fundamentals and fundamentals_as_of and now - fundamentals_as_of > FUNDAMENTALS_STALE_AFTER:
        warnings.append("Fundamentals are older than the expected freshness threshold.")

    if len(bars) < MIN_HISTORY_BARS:
        warnings.append(f"Only {len(bars)} daily bars are available; setup analysis confidence is limited.")

    return {
        "snapshot_as_of": snapshot_as_of.isoformat() if snapshot_as_of else None,
        "fundamentals_as_of": fundamentals_as_of.isoformat() if fundamentals_as_of else None,
        "daily_bars_as_of": daily_bars_as_of,
        "history_bar_count": len(bars),
        "warnings": warnings,
    }


def required_fundamentals_status(snapshot, fundamentals):
    data_source = fundamentals or snapshot
    missing_fields = []
    if data_source is None:
        return {
            "missing_fields": list(REQUIRED_FUNDAMENTAL_FIELDS),
            "is_complete": False,
        }
    for field_name in REQUIRED_FUNDAMENTAL_FIELDS:
        if getattr(data_source, field_name, None) is None:
            missing_fields.append(field_name)
    return {
        "missing_fields": missing_fields,
        "is_complete": not missing_fields,
    }


def compute_trade_agent_features(snapshot, fundamentals, bars):
    closes = [float(bar.close) for bar in bars if bar.close is not None]
    volumes = [float(bar.volume) for bar in bars if bar.volume is not None]
    latest_close = closes[-1] if closes else None
    close_20 = _mean(_sample(closes, 20))
    close_50 = _mean(_sample(closes, 50))
    close_200 = _mean(_sample(closes, 200))
    avg_volume_20 = _mean(_sample(volumes, 20))
    high_52w = max(_sample(closes, 252)) if closes else None
    low_52w = min(_sample(closes, 252)) if closes else None
    rsi_14 = _compute_rsi(closes, 14)
    atr_14 = _compute_atr(bars, 14)

    returns = {
        "return_5d": _pct_change(latest_close, closes[-6]) if len(closes) >= 6 else None,
        "return_20d": _pct_change(latest_close, closes[-21]) if len(closes) >= 21 else None,
        "return_60d": _pct_change(latest_close, closes[-61]) if len(closes) >= 61 else None,
    }

    if latest_close is None:
        range_position = None
    elif high_52w is None or low_52w is None or high_52w == low_52w:
        range_position = None
    else:
        range_position = ((latest_close - low_52w) / (high_52w - low_52w)) * 100.0

    volume_ratio = None
    if snapshot and snapshot.volume is not None and avg_volume_20 not in (None, 0):
        volume_ratio = float(snapshot.volume) / avg_volume_20

    trend_label = "mixed"
    if latest_close is not None and close_20 and close_50:
        if latest_close > close_20 > close_50:
            trend_label = "uptrend"
        elif latest_close < close_20 < close_50:
            trend_label = "downtrend"

    setup_flags = {
        "trend_setup": bool(latest_close and close_20 and close_50 and latest_close > close_20 > close_50),
        "pullback_setup": bool(latest_close and close_20 and close_50 and close_20 <= latest_close <= close_20 * 1.03 and close_20 > close_50),
        "breakout_setup": bool(latest_close and high_52w and latest_close >= high_52w * 0.98),
    }

    valuation = {
        "pe_ratio": getattr(snapshot, "pe_ratio", None) if snapshot else None,
        "forward_pe": getattr(snapshot, "forward_pe", None) if snapshot else None,
        "peg_ratio": getattr(snapshot, "peg_ratio", None) if snapshot else None,
        "price_to_sales": getattr(snapshot, "price_to_sales", None) if snapshot else None,
        "revenue_growth": getattr(snapshot, "revenue_growth", None) if snapshot else None,
        "eps_growth": getattr(snapshot, "eps_growth", None) if snapshot else None,
        "gross_margin": getattr(snapshot, "gross_margin", None) if snapshot else None,
        "operating_margin": getattr(snapshot, "operating_margin", None) if snapshot else None,
        "free_cash_flow": getattr(snapshot, "free_cash_flow", None) if snapshot else None,
        "debt_to_equity": getattr(snapshot, "debt_to_equity", None) if snapshot else None,
        "return_on_equity": getattr(snapshot, "return_on_equity", None) if snapshot else None,
    }
    if fundamentals:
        valuation.update({
            "pe_ratio": getattr(fundamentals, "pe_ratio", None) if getattr(fundamentals, "pe_ratio", None) is not None else valuation["pe_ratio"],
            "forward_pe": getattr(fundamentals, "forward_pe", None) if getattr(fundamentals, "forward_pe", None) is not None else valuation["forward_pe"],
            "price_to_sales": getattr(fundamentals, "price_to_sales", None) if getattr(fundamentals, "price_to_sales", None) is not None else valuation["price_to_sales"],
            "revenue_growth": getattr(fundamentals, "revenue_growth", None) if getattr(fundamentals, "revenue_growth", None) is not None else valuation["revenue_growth"],
            "eps_growth": getattr(fundamentals, "eps_growth", None) if getattr(fundamentals, "eps_growth", None) is not None else valuation["eps_growth"],
            "gross_margin": getattr(fundamentals, "gross_margin", None) if getattr(fundamentals, "gross_margin", None) is not None else valuation["gross_margin"],
            "operating_margin": getattr(fundamentals, "operating_margin", None) if getattr(fundamentals, "operating_margin", None) is not None else valuation["operating_margin"],
            "free_cash_flow": getattr(fundamentals, "free_cash_flow", None) if getattr(fundamentals, "free_cash_flow", None) is not None else valuation["free_cash_flow"],
            "debt_to_equity": getattr(fundamentals, "debt_to_equity", None) if getattr(fundamentals, "debt_to_equity", None) is not None else valuation["debt_to_equity"],
            "return_on_equity": getattr(fundamentals, "return_on_equity", None) if getattr(fundamentals, "return_on_equity", None) is not None else valuation["return_on_equity"],
        })

    return {
        "price": _safe_round(latest_close),
        "sma_20": _safe_round(close_20),
        "sma_50": _safe_round(close_50),
        "sma_200": _safe_round(close_200),
        "avg_volume_20": _safe_round(avg_volume_20, 0),
        "rsi_14": _safe_round(rsi_14),
        "atr_14": _safe_round(atr_14),
        "fifty_two_week_high": _safe_round(high_52w),
        "fifty_two_week_low": _safe_round(low_52w),
        "range_position_pct": _safe_round(range_position),
        "volume_ratio": _safe_round(volume_ratio),
        "trend_label": trend_label,
        "returns": {key: _safe_round(value) for key, value in returns.items()},
        "setup_flags": setup_flags,
        "snapshot_change_percent": _safe_round(getattr(snapshot, "today_change_percent", None) if snapshot else None),
        "market_cap": _safe_round(getattr(snapshot, "market_cap", None), 0) if snapshot else None,
        "valuation": {
            key: _safe_round(value)
            for key, value in valuation.items()
        },
    }


def summarize_watchlist_context(watchlist_items):
    if not watchlist_items:
        return []

    summaries = []
    for item in watchlist_items[:3]:
        summaries.append({
            "watchlist_name": item.watchlist.name if item.watchlist else None,
            "position_status": item.position_status,
            "thesis_summary": item.thesis_summary,
            "bull_case": item.bull_case,
            "bear_case": item.bear_case,
            "target_price": item.target_price,
            "invalidation_price": item.invalidation_price,
            "time_horizon": item.time_horizon,
        })
    return summaries


def derive_trade_levels(features):
    price = features.get("price")
    atr = features.get("atr_14")
    sma_20 = features.get("sma_20")
    sma_50 = features.get("sma_50")
    if price is None:
        return {
            "entry_zone": None,
            "target_1": None,
            "target_2": None,
            "invalidation": None,
        }

    if atr in (None, 0):
        atr = max(price * 0.03, 1.0)

    entry_low = price - (atr * 0.25)
    entry_high = price + (atr * 0.25)
    invalidation = sma_20 or sma_50 or (price - atr)
    target_1 = price + atr
    target_2 = price + (2 * atr)

    return {
        "entry_zone": f"{entry_low:.2f} - {entry_high:.2f}",
        "target_1": f"{target_1:.2f}",
        "target_2": f"{target_2:.2f}",
        "invalidation": f"{float(invalidation):.2f}" if invalidation is not None else None,
    }
