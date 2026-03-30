#!/usr/bin/env python3

import os
import sys
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
from ticker_ingestion import TickerIngestionWorker, enqueue_asset_refresh


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
                "pegRatio": 1.8,
                "totalRevenueAnnual": 184000000.0,
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


if __name__ == "__main__":
    unittest.main()
