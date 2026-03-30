#!/usr/bin/env python3

import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from market_data import (
    FundamentalsSnapshotData,
    MarketDataService,
    QuoteSnapshot,
    normalize_symbol,
)
from models import Asset, FundamentalSnapshot, MarketSnapshot


class FakeProvider:
    provider_name = 'fake'

    def get_quote_snapshot(self, symbol):
        return QuoteSnapshot(
            symbol=normalize_symbol(symbol),
            name='Apple Inc.',
            asset_type='equity',
            exchange='NASDAQ',
            currency='USD',
            sector='Technology',
            industry='Consumer Electronics',
            price=211.32,
            change_percent=1.8,
            market_cap=3200000000000,
            volume=45000000,
            avg_volume=52000000,
            fifty_two_week_high=220.0,
            fifty_two_week_low=145.0,
            moving_average_50=205.0,
            moving_average_200=190.0,
            raw_payload={'source': 'quote'}
        )

    def get_fundamentals_snapshot(self, symbol):
        return FundamentalsSnapshotData(
            symbol=normalize_symbol(symbol),
            pe_ratio=32.1,
            forward_pe=29.7,
            price_to_sales=8.5,
            revenue_growth=0.07,
            eps_growth=0.11,
            gross_margin=0.45,
            operating_margin=0.31,
            free_cash_flow=98000000000,
            debt_to_equity=1.2,
            return_on_equity=1.5,
            raw_payload={'source': 'fundamentals'}
        )


class TestMarketDataService(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.service = MarketDataService(provider=FakeProvider())
        self.created_symbols = ['AAPL', 'MSFT']

        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            assets = Asset.query.filter(Asset.symbol.in_(self.created_symbols)).all()
            asset_ids = [asset.id for asset in assets]
            if asset_ids:
                FundamentalSnapshot.query.filter(FundamentalSnapshot.asset_id.in_(asset_ids)).delete(synchronize_session=False)
                MarketSnapshot.query.filter(MarketSnapshot.asset_id.in_(asset_ids)).delete(synchronize_session=False)
                Asset.query.filter(Asset.id.in_(asset_ids)).delete(synchronize_session=False)
                db.session.commit()
            db.session.remove()

    def test_refresh_quote_snapshot_creates_asset_and_snapshot(self):
        with app.app_context():
            snapshot = self.service.refresh_quote_snapshot('aapl')

            self.assertIsNotNone(snapshot.id)
            asset = Asset.query.filter_by(symbol='AAPL').first()
            self.assertIsNotNone(asset)
            self.assertEqual(asset.name, 'Apple Inc.')
            self.assertEqual(asset.exchange, 'NASDAQ')
            self.assertGreaterEqual(MarketSnapshot.query.filter_by(asset_id=asset.id).count(), 1)
            self.assertAlmostEqual(snapshot.price, 211.32, places=2)

    def test_refresh_fundamentals_reuses_existing_asset(self):
        with app.app_context():
            self.service.refresh_quote_snapshot('AAPL')
            snapshot = self.service.refresh_fundamental_snapshot('AAPL')

            asset = Asset.query.filter_by(symbol='AAPL').first()
            self.assertEqual(Asset.query.filter_by(symbol='AAPL').count(), 1)
            self.assertGreaterEqual(FundamentalSnapshot.query.filter_by(asset_id=asset.id).count(), 1)
            self.assertAlmostEqual(snapshot.forward_pe, 29.7, places=2)

    def test_latest_snapshot_helpers_return_most_recent_records(self):
        with app.app_context():
            quote_one = self.service.refresh_quote_snapshot('MSFT')
            quote_two = self.service.refresh_quote_snapshot('MSFT')

            latest = self.service.get_latest_market_snapshot(quote_two.asset_id)
            self.assertIsNotNone(latest)
            self.assertEqual(latest.id, quote_two.id)


if __name__ == '__main__':
    unittest.main()
