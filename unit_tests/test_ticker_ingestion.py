#!/usr/bin/env python3

import os
import sys
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unit_tests.test_bootstrap import configure_test_db

configure_test_db(os.path.basename(__file__))

from app import app, db
from models import (
    Asset,
    TickerDailyBar,
    TickerFetchState,
    TickerFundamentalsLatest,
    TickerIntradayBar,
    TickerSnapshotLatest,
    WorkerLease,
)
from ticker_ingestion import YFinanceBatchClient, TickerFundamentalsWorker, TickerIngestionWorker, TickerMarketWorker, TickerPriorityWorker, enqueue_asset_refresh


class FakeFinnhubClient:
    def get_company_profile(self, symbol):
        return {
            "name": f"{symbol} Corp",
            "exchange": "NASDAQ",
            "currency": "USD",
            "finnhubIndustry": "Technology",
        }

    def get_basic_financials(self, symbol):
        return {
            "metric": {
                "marketCapitalization": 1500000000,
                "peNormalizedAnnual": 21.5,
                "peForwardAnnual": 18.3,
                "pegRatio": 1.8,
                "priceToSalesAnnual": 4.2,
                "revenueGrowthTTMYoy": 22.0,
                "epsGrowthTTMYoy": 31.0,
                "grossMarginTTM": 68.0,
                "operatingMarginTTM": 31.0,
                "totalRevenueAnnual": 184000000.0,
                "currentEv/freeCashFlowTTM": 25.0,
                "totalDebt/totalEquityAnnual": 0.45,
                "roeTTM": 19.0,
                "dividendYieldIndicatedAnnual": 0.8,
                "shareOutstanding": 25000000,
            }
        }

class FakeYFinanceBatchClient:
    def get_hourly_bars(self, symbols):
        base = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=3)
        payload = {}
        for symbol in symbols:
            payload[symbol] = [
                {
                    "timestamp": base + timedelta(hours=index),
                    "open": 107.0 + index,
                    "high": 108.0 + index,
                    "low": 106.5 + index,
                    "close": 108.0 + (index * 0.5) + 0.5,
                    "volume": 1000 + (index * 200),
                }
                for index in range(4)
            ]
        return payload

    def get_daily_bars(self, symbols, *, period="10d", interval="1d"):
        base_day = datetime(2026, 3, 26)
        payload = {}
        for symbol in symbols:
            payload[symbol] = [
                {
                    "timestamp": base_day,
                    "open": 100.0,
                    "high": 101.0,
                    "low": 99.0,
                    "close": 100.0,
                    "volume": 1000,
                },
                {
                    "timestamp": base_day + timedelta(days=1),
                    "open": 102.0,
                    "high": 111.0,
                    "low": 101.0,
                    "close": 110.0,
                    "volume": 1200,
                },
            ]
        return payload


class TestTickerIngestionWorker(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        with app.app_context():
            db.create_all()
            WorkerLease.query.delete(synchronize_session=False)
            TickerIntradayBar.query.delete(synchronize_session=False)
            TickerDailyBar.query.delete(synchronize_session=False)
            TickerFundamentalsLatest.query.delete(synchronize_session=False)
            TickerSnapshotLatest.query.delete(synchronize_session=False)
            TickerFetchState.query.delete(synchronize_session=False)
            Asset.query.filter_by(symbol="WORK").delete(synchronize_session=False)
            db.session.commit()
            asset = Asset(symbol="WORK", asset_type="equity", status="active", added_source="user")
            db.session.add(asset)
            db.session.flush()
            enqueue_asset_refresh(asset, include_backfill=False)
            db.session.commit()
            self.asset_id = asset.id

    def tearDown(self):
        with app.app_context():
            TickerIntradayBar.query.delete(synchronize_session=False)
            TickerDailyBar.query.delete(synchronize_session=False)
            TickerFundamentalsLatest.query.delete(synchronize_session=False)
            TickerSnapshotLatest.query.delete(synchronize_session=False)
            TickerFetchState.query.delete(synchronize_session=False)
            WorkerLease.query.delete(synchronize_session=False)
            Asset.query.filter_by(id=getattr(self, "asset_id", None)).delete()
            db.session.commit()

    def test_worker_run_once_populates_ticker_tables(self):
        with app.app_context():
            worker = TickerIngestionWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 11, 0, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": True,
                    "after_close": False,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                processed = worker.run_once()
            self.assertGreaterEqual(processed, 1)

            asset = Asset.query.get(self.asset_id)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            snapshot = TickerSnapshotLatest.query.filter_by(asset_id=self.asset_id).first()
            fundamentals = TickerFundamentalsLatest.query.filter_by(asset_id=self.asset_id).first()

            self.assertIsNotNone(fetch_state)
            self.assertIsNotNone(snapshot)
            self.assertIsNotNone(fundamentals)
            self.assertFalse(fetch_state.is_intraday_pending)
            self.assertFalse(fetch_state.is_fundamentals_pending)
            self.assertFalse(fetch_state.is_backfill_pending)
            self.assertEqual(asset.name, "WORK Corp")
            self.assertAlmostEqual(snapshot.last_price, 110.0, places=2)
            self.assertAlmostEqual(snapshot.pe_ratio, 21.5, places=2)
            self.assertAlmostEqual(snapshot.forward_pe, 18.3, places=2)
            self.assertAlmostEqual(snapshot.revenue_growth, 22.0, places=2)
            self.assertAlmostEqual(snapshot.eps_growth, 31.0, places=2)
            self.assertAlmostEqual(fundamentals.return_on_equity, 19.0, places=2)
            self.assertAlmostEqual(fundamentals.debt_to_equity, 0.45, places=2)
            self.assertGreater(TickerIntradayBar.query.filter_by(asset_id=self.asset_id).count(), 0)

    def test_worker_allows_priority_catchup_refresh_on_non_trading_day_when_db_is_stale(self):
        with app.app_context():
            asset = Asset.query.get(self.asset_id)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            fetch_state.priority_requested_at = datetime.utcnow()
            db.session.commit()

            worker = TickerIngestionWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 28, 12, 0, 0),
                    "trade_date": datetime(2026, 3, 28).date(),
                    "is_trading_day": False,
                    "during_market": False,
                    "after_close": False,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 28, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 28, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 2)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            self.assertIsNone(fetch_state.priority_requested_at)
            self.assertIsNone(fetch_state.last_error_type)
            self.assertIsNotNone(fetch_state.last_market_close_trade_date)
            self.assertIsNotNone(fetch_state.last_fundamentals_trade_date)

    def test_market_worker_only_processes_intraday_lane(self):
        with app.app_context():
            worker = TickerMarketWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 11, 0, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": True,
                    "after_close": False,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 1)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            self.assertFalse(fetch_state.is_intraday_pending)
            self.assertTrue(fetch_state.is_fundamentals_pending)

    def test_market_worker_after_close_uses_daily_close_update(self):
        with app.app_context():
            worker = TickerMarketWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 16, 30, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": False,
                    "after_close": True,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 1)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            snapshot = TickerSnapshotLatest.query.filter_by(asset_id=self.asset_id).first()
            latest_daily = (
                TickerDailyBar.query.filter_by(asset_id=self.asset_id)
                .order_by(TickerDailyBar.bar_date.desc())
                .first()
            )
            self.assertEqual(fetch_state.last_market_close_trade_date.isoformat(), "2026-03-27")
            self.assertEqual(fetch_state.last_daily_bar_date.isoformat(), "2026-03-27")
            self.assertEqual(latest_daily.close, 110.0)
            self.assertAlmostEqual(snapshot.day_close, 100.0, places=2)
            self.assertAlmostEqual(snapshot.last_price, 110.0, places=2)
            self.assertAlmostEqual(snapshot.today_change_percent, 10.0, places=2)

    def test_after_close_selects_symbol_even_if_intraday_refresh_is_recent(self):
        with app.app_context():
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            fetch_state.is_intraday_pending = False
            fetch_state.intraday_fetched_at = datetime(2026, 3, 27, 19, 30, 0)
            fetch_state.last_market_close_trade_date = datetime(2026, 3, 26).date()
            fetch_state.last_daily_bar_date = datetime(2026, 3, 26).date()
            db.session.commit()

            worker = TickerMarketWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 16, 30, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": False,
                    "after_close": True,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                candidates = worker.select_intraday_candidates(limit=50)

            self.assertEqual([candidate.asset_id for candidate in candidates], [self.asset_id])

    def test_preopen_selects_symbol_when_prior_session_close_is_missing(self):
        with app.app_context():
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            fetch_state.is_intraday_pending = False
            fetch_state.intraday_fetched_at = datetime(2026, 3, 31, 20, 0, 0)
            fetch_state.last_market_close_trade_date = datetime(2026, 3, 30).date()
            fetch_state.last_daily_bar_date = datetime(2026, 3, 30).date()
            db.session.commit()

            worker = TickerMarketWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 4, 1, 8, 0, 0),
                    "trade_date": datetime(2026, 4, 1).date(),
                    "is_trading_day": True,
                    "during_market": False,
                    "after_close": False,
                    "before_open": True,
                    "market_open_et": datetime(2026, 4, 1, 9, 30, 0),
                    "market_close_et": datetime(2026, 4, 1, 16, 0, 0),
                },
            ):
                candidates = worker.select_intraday_candidates(limit=50)

            self.assertEqual([candidate.asset_id for candidate in candidates], [self.asset_id])

    def test_preopen_run_once_backfills_prior_session_close_with_daily_data(self):
        with app.app_context():
            class PreopenCloseFillClient(FakeYFinanceBatchClient):
                def get_daily_bars(self, symbols, *, period="10d", interval="1d"):
                    base_day = datetime(2026, 3, 30)
                    payload = {}
                    for symbol in symbols:
                        payload[symbol] = [
                            {
                                "timestamp": base_day,
                                "open": 100.0,
                                "high": 101.0,
                                "low": 99.0,
                                "close": 100.0,
                                "volume": 1000,
                            },
                            {
                                "timestamp": base_day + timedelta(days=1),
                                "open": 102.0,
                                "high": 111.0,
                                "low": 101.0,
                                "close": 110.0,
                                "volume": 1200,
                            },
                        ]
                    return payload

            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            fetch_state.is_intraday_pending = True
            fetch_state.intraday_fetched_at = None
            fetch_state.last_market_close_trade_date = datetime(2026, 3, 30).date()
            fetch_state.last_daily_bar_date = datetime(2026, 3, 30).date()
            db.session.commit()

            worker = TickerMarketWorker(
                client=FakeFinnhubClient(),
                price_client=PreopenCloseFillClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 4, 1, 8, 0, 0),
                    "trade_date": datetime(2026, 4, 1).date(),
                    "is_trading_day": True,
                    "during_market": False,
                    "after_close": False,
                    "before_open": True,
                    "market_open_et": datetime(2026, 4, 1, 9, 30, 0),
                    "market_close_et": datetime(2026, 4, 1, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 1)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            snapshot = TickerSnapshotLatest.query.filter_by(asset_id=self.asset_id).first()
            latest_daily = (
                TickerDailyBar.query.filter_by(asset_id=self.asset_id)
                .order_by(TickerDailyBar.bar_date.desc())
                .first()
            )
            self.assertEqual(fetch_state.last_market_close_trade_date.isoformat(), "2026-03-31")
            self.assertEqual(fetch_state.last_daily_bar_date.isoformat(), "2026-03-31")
            self.assertEqual(latest_daily.close, 110.0)
            self.assertAlmostEqual(snapshot.day_close, 100.0, places=2)
            self.assertAlmostEqual(snapshot.last_price, 110.0, places=2)
            self.assertEqual(worker.stats["yfinance_intraday_requests"], 0)
            self.assertEqual(worker.stats["yfinance_close_requests"], 1)

    def test_yfinance_symbol_normalization_maps_dot_symbols(self):
        client = object.__new__(YFinanceBatchClient)
        self.assertEqual(client.normalize_yfinance_symbol("BRK.B"), "BRK-B")
        self.assertEqual(client.normalize_yfinance_symbol("BF.A"), "BF-A")
        self.assertEqual(client.normalize_yfinance_symbol("MSFT"), "MSFT")

    def test_fundamentals_worker_only_processes_fundamentals_lane(self):
        with app.app_context():
            worker = TickerFundamentalsWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 11, 0, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": True,
                    "after_close": False,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 1)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            self.assertFalse(fetch_state.is_fundamentals_pending)
            self.assertTrue(fetch_state.is_intraday_pending)

    def test_priority_worker_processes_priority_market_and_fundamentals(self):
        with app.app_context():
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            fetch_state.priority_requested_at = datetime.utcnow()
            db.session.commit()

            worker = TickerPriorityWorker(
                client=FakeFinnhubClient(),
                price_client=FakeYFinanceBatchClient(),
                max_calls_per_minute=0,
            )
            with patch(
                "ticker_ingestion._market_session_info",
                return_value={
                    "now_et": datetime(2026, 3, 27, 11, 0, 0),
                    "trade_date": datetime(2026, 3, 27).date(),
                    "is_trading_day": True,
                    "during_market": True,
                    "after_close": False,
                    "before_open": False,
                    "market_open_et": datetime(2026, 3, 27, 9, 30, 0),
                    "market_close_et": datetime(2026, 3, 27, 16, 0, 0),
                },
            ):
                processed = worker.run_once()

            self.assertEqual(processed, 2)
            fetch_state = TickerFetchState.query.filter_by(asset_id=self.asset_id).first()
            self.assertFalse(fetch_state.is_intraday_pending)
            self.assertFalse(fetch_state.is_fundamentals_pending)
            self.assertIsNone(fetch_state.priority_requested_at)


if __name__ == "__main__":
    unittest.main()
