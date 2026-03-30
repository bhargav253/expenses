from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json

from models import Asset, FundamentalSnapshot, MarketSnapshot, TickerSnapshotLatest
from extensions import db

try:
    import yfinance as yf
except Exception:  # pragma: no cover - graceful fallback when optional dependency is absent
    yf = None

try:
    from tradingview_screener import Query, col
except Exception:  # pragma: no cover - graceful fallback when optional dependency is absent
    Query = None
    col = None


class MarketDataError(Exception):
    pass


class TradingViewScreenerError(Exception):
    pass


def _safe_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_symbol(symbol: str) -> str:
    return (symbol or "").strip().upper()


def _percent_difference(numerator_value, denominator_value, *, mode: str):
    if numerator_value is None or denominator_value in (None, 0):
        return None
    if mode == "below":
        return ((denominator_value - numerator_value) / denominator_value) * 100.0
    if mode == "above":
        return ((numerator_value - denominator_value) / denominator_value) * 100.0
    if mode == "off":
        return ((numerator_value - denominator_value) / denominator_value) * 100.0
    raise ValueError(f"Unsupported mode: {mode}")


@dataclass
class QuoteSnapshot:
    symbol: str
    name: str | None
    asset_type: str
    exchange: str | None
    currency: str | None
    sector: str | None
    industry: str | None
    price: float | None
    change_percent: float | None
    market_cap: float | None
    volume: float | None
    avg_volume: float | None
    fifty_two_week_high: float | None
    fifty_two_week_low: float | None
    moving_average_50: float | None
    moving_average_200: float | None
    raw_payload: dict


@dataclass
class FundamentalsSnapshotData:
    symbol: str
    pe_ratio: float | None
    forward_pe: float | None
    price_to_sales: float | None
    revenue_growth: float | None
    eps_growth: float | None
    gross_margin: float | None
    operating_margin: float | None
    free_cash_flow: float | None
    debt_to_equity: float | None
    return_on_equity: float | None
    raw_payload: dict


class MarketDataProvider:
    provider_name = "base"

    def get_quote_snapshot(self, symbol: str) -> QuoteSnapshot:
        raise NotImplementedError

    def get_fundamentals_snapshot(self, symbol: str) -> FundamentalsSnapshotData:
        raise NotImplementedError


class YFinanceMarketDataProvider(MarketDataProvider):
    provider_name = "yfinance"

    def __init__(self):
        if yf is None:
            raise MarketDataError("yfinance is not installed or unavailable in this environment")

    def _ticker_info(self, symbol: str):
        ticker = yf.Ticker(symbol)
        try:
            info = ticker.fast_info
        except Exception:
            info = {}

        try:
            full_info = ticker.info or {}
        except Exception:
            full_info = {}

        return ticker, info, full_info

    def get_quote_snapshot(self, symbol: str) -> QuoteSnapshot:
        normalized = normalize_symbol(symbol)
        ticker, fast_info, info = self._ticker_info(normalized)
        payload = {"fast_info": dict(fast_info or {}), "info": dict(info or {})}

        return QuoteSnapshot(
            symbol=normalized,
            name=info.get("shortName") or info.get("longName"),
            asset_type=(info.get("quoteType") or "EQUITY").lower(),
            exchange=info.get("exchange"),
            currency=info.get("currency") or "USD",
            sector=info.get("sector"),
            industry=info.get("industry"),
            price=_safe_float(fast_info.get("lastPrice") or info.get("currentPrice") or info.get("regularMarketPrice")),
            change_percent=_safe_float(info.get("regularMarketChangePercent")),
            market_cap=_safe_float(fast_info.get("marketCap") or info.get("marketCap")),
            volume=_safe_float(fast_info.get("lastVolume") or info.get("volume")),
            avg_volume=_safe_float(info.get("averageVolume")),
            fifty_two_week_high=_safe_float(info.get("fiftyTwoWeekHigh")),
            fifty_two_week_low=_safe_float(info.get("fiftyTwoWeekLow")),
            moving_average_50=_safe_float(info.get("fiftyDayAverage")),
            moving_average_200=_safe_float(info.get("twoHundredDayAverage")),
            raw_payload=payload
        )

    def get_fundamentals_snapshot(self, symbol: str) -> FundamentalsSnapshotData:
        normalized = normalize_symbol(symbol)
        _, _, info = self._ticker_info(normalized)
        payload = {"info": dict(info or {})}

        return FundamentalsSnapshotData(
            symbol=normalized,
            pe_ratio=_safe_float(info.get("trailingPE")),
            forward_pe=_safe_float(info.get("forwardPE")),
            price_to_sales=_safe_float(info.get("priceToSalesTrailing12Months")),
            revenue_growth=_safe_float(info.get("revenueGrowth")),
            eps_growth=_safe_float(info.get("earningsGrowth")),
            gross_margin=_safe_float(info.get("grossMargins")),
            operating_margin=_safe_float(info.get("operatingMargins")),
            free_cash_flow=_safe_float(info.get("freeCashflow")),
            debt_to_equity=_safe_float(info.get("debtToEquity")),
            return_on_equity=_safe_float(info.get("returnOnEquity")),
            raw_payload=payload
        )


class MarketDataService:
    def __init__(self, provider: MarketDataProvider | None = None):
        self.provider = provider or YFinanceMarketDataProvider()

    def get_or_create_asset(self, symbol: str) -> Asset:
        normalized = normalize_symbol(symbol)
        if not normalized:
            raise MarketDataError("A ticker symbol is required")

        asset = Asset.query.filter_by(symbol=normalized).first()
        if asset:
            return asset

        asset = Asset(symbol=normalized, asset_type='equity', status='active', added_source='user')
        db.session.add(asset)
        db.session.commit()
        return asset

    def refresh_quote_snapshot(self, symbol: str) -> MarketSnapshot:
        quote = self.provider.get_quote_snapshot(symbol)
        asset = self.get_or_create_asset(quote.symbol)
        asset.name = quote.name or asset.name
        asset.asset_type = quote.asset_type or asset.asset_type
        asset.exchange = quote.exchange or asset.exchange
        asset.currency = quote.currency or asset.currency
        asset.sector = quote.sector or asset.sector
        asset.industry = quote.industry or asset.industry
        asset.updated_at = datetime.utcnow()

        snapshot = MarketSnapshot(
            asset_id=asset.id,
            provider=self.provider.provider_name,
            snapshot_date=datetime.utcnow().date(),
            price=quote.price,
            change_percent=quote.change_percent,
            market_cap=quote.market_cap,
            volume=quote.volume,
            avg_volume=quote.avg_volume,
            fifty_two_week_high=quote.fifty_two_week_high,
            fifty_two_week_low=quote.fifty_two_week_low,
            moving_average_50=quote.moving_average_50,
            moving_average_200=quote.moving_average_200,
            raw_payload_json=json.dumps(quote.raw_payload, default=str),
        )
        db.session.add(snapshot)
        db.session.flush()
        self._upsert_ticker_snapshot_latest(
            asset,
            quote_data=quote,
            quote_as_of=snapshot.fetched_at,
        )
        db.session.commit()
        return snapshot

    def refresh_fundamental_snapshot(self, symbol: str) -> FundamentalSnapshot:
        fundamentals = self.provider.get_fundamentals_snapshot(symbol)
        asset = self.get_or_create_asset(fundamentals.symbol)
        snapshot = FundamentalSnapshot(
            asset_id=asset.id,
            provider=self.provider.provider_name,
            as_of_date=datetime.utcnow().date(),
            pe_ratio=fundamentals.pe_ratio,
            forward_pe=fundamentals.forward_pe,
            price_to_sales=fundamentals.price_to_sales,
            revenue_growth=fundamentals.revenue_growth,
            eps_growth=fundamentals.eps_growth,
            gross_margin=fundamentals.gross_margin,
            operating_margin=fundamentals.operating_margin,
            free_cash_flow=fundamentals.free_cash_flow,
            debt_to_equity=fundamentals.debt_to_equity,
            return_on_equity=fundamentals.return_on_equity,
            raw_payload_json=json.dumps(fundamentals.raw_payload, default=str),
        )
        db.session.add(snapshot)
        db.session.flush()
        self._upsert_ticker_snapshot_latest(
            asset,
            fundamentals_data=fundamentals,
            fundamentals_as_of=snapshot.fetched_at,
        )
        db.session.commit()
        return snapshot

    def get_latest_market_snapshot(self, asset_id: int):
        return (
            MarketSnapshot.query.filter_by(asset_id=asset_id)
            .order_by(MarketSnapshot.snapshot_date.desc(), MarketSnapshot.fetched_at.desc())
            .first()
        )

    def get_latest_fundamental_snapshot(self, asset_id: int):
        return (
            FundamentalSnapshot.query.filter_by(asset_id=asset_id)
            .order_by(FundamentalSnapshot.as_of_date.desc(), FundamentalSnapshot.fetched_at.desc())
            .first()
        )

    def _upsert_ticker_snapshot_latest(self, asset: Asset, quote_data: QuoteSnapshot | None = None, fundamentals_data: FundamentalsSnapshotData | None = None, quote_as_of=None, fundamentals_as_of=None):
        snapshot = TickerSnapshotLatest.query.filter_by(asset_id=asset.id).first()
        if snapshot is None:
            snapshot = TickerSnapshotLatest(asset_id=asset.id)
            db.session.add(snapshot)

        if quote_data is not None:
            snapshot.last_price = quote_data.price
            snapshot.day_close = quote_data.price
            snapshot.today_change_percent = quote_data.change_percent
            snapshot.market_cap = quote_data.market_cap
            snapshot.volume = quote_data.volume
            snapshot.avg_volume = quote_data.avg_volume
            snapshot.fifty_two_week_high = quote_data.fifty_two_week_high
            snapshot.fifty_two_week_low = quote_data.fifty_two_week_low
            snapshot.moving_average_50 = quote_data.moving_average_50
            snapshot.moving_average_200 = quote_data.moving_average_200
            snapshot.percent_below_52_week_high = _percent_difference(quote_data.price, quote_data.fifty_two_week_high, mode="below")
            snapshot.percent_above_52_week_low = _percent_difference(quote_data.price, quote_data.fifty_two_week_low, mode="above")
            snapshot.percent_price_off_50day_sma = _percent_difference(quote_data.price, quote_data.moving_average_50, mode="off")
            snapshot.percent_price_off_200day_sma = _percent_difference(quote_data.price, quote_data.moving_average_200, mode="off")
            snapshot.quote_as_of = quote_as_of or datetime.utcnow()

        if fundamentals_data is not None:
            snapshot.pe_ratio = fundamentals_data.pe_ratio
            snapshot.forward_pe = fundamentals_data.forward_pe
            snapshot.revenue_growth = fundamentals_data.revenue_growth
            snapshot.eps_growth = fundamentals_data.eps_growth
            snapshot.fundamentals_as_of = fundamentals_as_of or datetime.utcnow()

        snapshot.updated_at = datetime.utcnow()


class TradingViewWatchlistScreenerService:
    SELECT_FIELDS = [
        'ticker',
        'name',
        'sector',
        'industry',
        'close',
        'volume',
        'market_cap_basic',
        'price_earnings_ttm',
        'dividend_yield_recent',
        'change',
        'price_52_week_high',
        'price_52_week_low',
        'Perf.All',
        'Perf.5D',
        'Perf.1M',
        'Perf.3M',
        'Perf.Y',
        'Perf.3Y',
        'Perf.5Y',
        'Perf.10Y',
        'SMA10',
        'SMA20',
        'SMA50',
        'SMA200',
        'total_revenue',
    ]

    def __init__(self, query_cls=None, column_factory=None):
        self.query_cls = query_cls or Query
        self.column_factory = column_factory or col
        if self.query_cls is None or self.column_factory is None:
            raise TradingViewScreenerError("tradingview-screener is not installed in this environment")

    def screen_symbols(self, symbols: list[str]):
        normalized_symbols = [normalize_symbol(symbol) for symbol in symbols if normalize_symbol(symbol)]
        if not normalized_symbols:
            return []

        query = (
            self.query_cls()
            .set_markets('america')
            .select(*self.SELECT_FIELDS)
            .where(self.column_factory('name').isin(normalized_symbols))
            .limit(max(len(normalized_symbols), 50))
        )
        _, df = query.get_scanner_data()
        if df is None:
            return []

        rows = []
        for record in df.to_dict(orient='records'):
            price = _safe_float(record.get('close'))
            high_52 = _safe_float(record.get('price_52_week_high'))
            low_52 = _safe_float(record.get('price_52_week_low'))
            sma_10 = _safe_float(record.get('SMA10'))
            sma_20 = _safe_float(record.get('SMA20'))
            sma_50 = _safe_float(record.get('SMA50'))
            sma_200 = _safe_float(record.get('SMA200'))
            perf_3y = _safe_float(record.get('Perf.3Y'))
            perf_5y = _safe_float(record.get('Perf.5Y'))
            perf_10y = _safe_float(record.get('Perf.10Y'))

            rows.append({
                'symbol': normalize_symbol(record.get('name')),
                'ticker': record.get('ticker'),
                'sector': record.get('sector'),
                'industry': record.get('industry'),
                'price': price,
                'volume': _safe_float(record.get('volume')),
                'market_cap': _safe_float(record.get('market_cap_basic')),
                'pe_ratio': _safe_float(record.get('price_earnings_ttm')),
                'peg_ratio': None,
                'revenue': _safe_float(record.get('total_revenue')),
                'dividend_yield': _safe_float(record.get('dividend_yield_recent')),
                'today_change_percent': _safe_float(record.get('change')),
                'percent_below_52_week_high': self._percent_below(price, high_52),
                'percent_above_52_week_low': self._percent_above(price, low_52),
                'days_since_52_week_high': None,
                'total_return': _safe_float(record.get('Perf.All')),
                'annualized_return_1y': _safe_float(record.get('Perf.Y')),
                'annualized_return_3y': self._annualize_percent(perf_3y, 3),
                'annualized_return_5y': self._annualize_percent(perf_5y, 5),
                'annualized_return_10y': self._annualize_percent(perf_10y, 10),
                'price_performance_5d': _safe_float(record.get('Perf.5D')),
                'price_performance_4w': _safe_float(record.get('Perf.1M')),
                'price_performance_13w': _safe_float(record.get('Perf.3M')),
                'price_performance_52w': _safe_float(record.get('Perf.Y')),
                'percent_price_off_10day_sma': self._percent_off(price, sma_10),
                'percent_price_off_20day_sma': self._percent_off(price, sma_20),
                'percent_price_off_50day_sma': self._percent_off(price, sma_50),
                'percent_price_off_200day_sma': self._percent_off(price, sma_200),
            })

        symbol_order = {symbol: index for index, symbol in enumerate(normalized_symbols)}
        rows.sort(key=lambda row: symbol_order.get(row.get('symbol'), len(symbol_order)))
        return rows

    @staticmethod
    def _annualize_percent(percent_value, years):
        if percent_value is None:
            return None
        growth = 1 + (percent_value / 100.0)
        if growth <= 0:
            return None
        return ((growth ** (1 / years)) - 1) * 100.0

    @staticmethod
    def _percent_below(price, reference):
        if price is None or reference in (None, 0):
            return None
        return ((reference - price) / reference) * 100.0

    @staticmethod
    def _percent_above(price, reference):
        if price is None or reference in (None, 0):
            return None
        return ((price - reference) / reference) * 100.0

    @staticmethod
    def _percent_off(price, moving_average):
        if price is None or moving_average in (None, 0):
            return None
        return ((price - moving_average) / moving_average) * 100.0
