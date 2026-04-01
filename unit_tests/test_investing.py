#!/usr/bin/env python3

import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unit_tests.test_bootstrap import configure_test_db

configure_test_db(os.path.basename(__file__))

import app as app_module
import trade_social_scan as trade_social_scan_module
from app import (
    DEFAULT_SAVED_SCREENER_NAME,
    DEFAULT_SCREENER_WATCHLIST_NAME,
    app,
    db,
)
from market_data import FundamentalsSnapshotData, MarketDataService, QuoteSnapshot, normalize_symbol
from models import Asset, Dashboard, DashboardMember, FundamentalSnapshot, MarketSnapshot, ScreenerDefinition, TickerDailyBar, TickerFetchState, TickerFundamentalsLatest, TickerIntradayBar, TickerSnapshotLatest, TradeIdea, User, UserDashboardSettings, Watchlist, WatchlistItem, WorkerLease
from models import TradeAgentRun, TradeAgentEvent, TrendScanRun, TrendScanEvent


class FakeProvider:
    provider_name = 'fake'

    def get_quote_snapshot(self, symbol):
        symbol = normalize_symbol(symbol)
        return QuoteSnapshot(
            symbol=symbol,
            name=f'{symbol} Corp.',
            asset_type='equity',
            exchange='NASDAQ',
            currency='USD',
            sector='Technology',
            industry='Software',
            price=123.45,
            change_percent=2.5,
            market_cap=987654321,
            volume=1000000,
            avg_volume=1200000,
            fifty_two_week_high=150.0,
            fifty_two_week_low=80.0,
            moving_average_50=118.0,
            moving_average_200=110.0,
            raw_payload={'symbol': symbol}
        )

    def get_fundamentals_snapshot(self, symbol):
        symbol = normalize_symbol(symbol)
        return FundamentalsSnapshotData(
            symbol=symbol,
            pe_ratio=25.1,
            forward_pe=21.4,
            price_to_sales=5.2,
            revenue_growth=0.18,
            eps_growth=0.22,
            gross_margin=0.61,
            operating_margin=0.29,
            free_cash_flow=1250000000,
            debt_to_equity=0.4,
            return_on_equity=0.19,
            raw_payload={'symbol': symbol}
        )


class FakeTradingViewScreenerService:
    def screen_symbols(self, symbols):
        rows = []
        for symbol in symbols:
            if symbol == 'AAPL':
                rows.append({
                    'symbol': 'AAPL',
                    'ticker': 'NASDAQ:AAPL',
                    'sector': 'Technology',
                    'industry': 'Consumer Electronics',
                    'price': 195.0,
                    'volume': 55000000,
                    'market_cap': 2900000000000,
                    'pe_ratio': 28.5,
                    'peg_ratio': None,
                    'revenue': 391000000000,
                    'dividend_yield': 0.45,
                    'today_change_percent': 1.4,
                    'percent_below_52_week_high': 2.1,
                    'percent_above_52_week_low': 31.0,
                    'days_since_52_week_high': None,
                    'total_return': 850.0,
                    'annualized_return_1y': 18.0,
                    'annualized_return_3y': 12.5,
                    'annualized_return_5y': 19.0,
                    'annualized_return_10y': 24.0,
                    'price_performance_5d': 2.8,
                    'price_performance_4w': 4.2,
                    'price_performance_13w': 9.7,
                    'price_performance_52w': 18.0,
                    'percent_price_off_10day_sma': 1.3,
                    'percent_price_off_20day_sma': 2.2,
                    'percent_price_off_50day_sma': 4.8,
                    'percent_price_off_200day_sma': 13.7,
                })
            elif symbol == 'MSFT':
                rows.append({
                    'symbol': 'MSFT',
                    'ticker': 'NASDAQ:MSFT',
                    'sector': 'Technology',
                    'industry': 'Software',
                    'price': 420.0,
                    'volume': 21000000,
                    'market_cap': 3100000000000,
                    'pe_ratio': 34.0,
                    'peg_ratio': None,
                    'revenue': 245000000000,
                    'dividend_yield': 0.68,
                    'today_change_percent': -0.6,
                    'percent_below_52_week_high': 5.4,
                    'percent_above_52_week_low': 28.0,
                    'days_since_52_week_high': None,
                    'total_return': 1100.0,
                    'annualized_return_1y': 14.0,
                    'annualized_return_3y': 11.2,
                    'annualized_return_5y': 17.5,
                    'annualized_return_10y': 27.0,
                    'price_performance_5d': 0.4,
                    'price_performance_4w': 1.1,
                    'price_performance_13w': 6.3,
                    'price_performance_52w': 14.0,
                    'percent_price_off_10day_sma': -0.4,
                    'percent_price_off_20day_sma': 0.8,
                    'percent_price_off_50day_sma': 3.2,
                    'percent_price_off_200day_sma': 16.4,
                })
        return rows


class TestInvestingWorkspace(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.original_market_service = app_module.MARKET_DATA_SERVICE
        self.original_tradingview_service = app_module.TRADINGVIEW_SCREENER_SERVICE
        app_module.MARKET_DATA_SERVICE = MarketDataService(provider=FakeProvider())
        app_module.TRADINGVIEW_SCREENER_SERVICE = FakeTradingViewScreenerService()

        with app.app_context():
            db.create_all()
            DashboardMember.query.delete(synchronize_session=False)
            Dashboard.query.filter_by(name='Investing Dashboard').delete(synchronize_session=False)
            WatchlistItem.query.delete(synchronize_session=False)
            Watchlist.query.delete(synchronize_session=False)
            TradeIdea.query.delete(synchronize_session=False)
            ScreenerDefinition.query.delete(synchronize_session=False)
            UserDashboardSettings.query.delete(synchronize_session=False)
            db.session.commit()

            suffix = uuid.uuid4().hex[:8]
            owner = User(email=f'invest-owner-{suffix}@example.com', name='Owner User', username=f'investowner-{suffix}')
            owner.set_password('password')
            outsider = User(email=f'invest-outsider-{suffix}@example.com', name='Outsider User', username=f'investoutsider-{suffix}')
            outsider.set_password('password')
            db.session.add_all([owner, outsider])
            db.session.commit()
            self.owner_id = owner.id
            self.outsider_id = outsider.id

            dashboard = Dashboard(name='Investing Dashboard', description='Testing investing routes', created_by=owner.id)
            db.session.add(dashboard)
            db.session.commit()
            self.dashboard_id = dashboard.id

            member = DashboardMember(dashboard_id=dashboard.id, user_id=owner.id, role='owner')
            db.session.add(member)
            db.session.commit()
            self.member_id = member.id

    def tearDown(self):
        app_module.MARKET_DATA_SERVICE = self.original_market_service
        app_module.TRADINGVIEW_SCREENER_SERVICE = self.original_tradingview_service
        with app.app_context():
            watchlists = Watchlist.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).all()
            watchlist_ids = [watchlist.id for watchlist in watchlists]
            if watchlist_ids:
                WatchlistItem.query.filter(WatchlistItem.watchlist_id.in_(watchlist_ids)).delete(synchronize_session=False)
            Watchlist.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            TradeIdea.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            TradeAgentEvent.query.delete(synchronize_session=False)
            TradeAgentRun.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            TrendScanEvent.query.delete(synchronize_session=False)
            TrendScanRun.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            ScreenerDefinition.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            UserDashboardSettings.query.filter_by(dashboard_id=getattr(self, 'dashboard_id', None)).delete()
            FundamentalSnapshot.query.delete(synchronize_session=False)
            MarketSnapshot.query.delete(synchronize_session=False)
            TickerIntradayBar.query.delete(synchronize_session=False)
            TickerDailyBar.query.delete(synchronize_session=False)
            TickerFundamentalsLatest.query.delete(synchronize_session=False)
            TickerFetchState.query.delete(synchronize_session=False)
            WorkerLease.query.delete(synchronize_session=False)
            TickerSnapshotLatest.query.delete(synchronize_session=False)
            Asset.query.delete(synchronize_session=False)

            DashboardMember.query.filter_by(id=getattr(self, 'member_id', None)).delete()
            Dashboard.query.filter_by(id=getattr(self, 'dashboard_id', None)).delete()
            User.query.filter(User.id.in_([getattr(self, 'owner_id', -1), getattr(self, 'outsider_id', -1)])).delete(synchronize_session=False)
            db.session.commit()

    def test_investing_workspace_denies_non_member(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.outsider_id

        response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(response.status_code, 403)

    def test_investing_workspace_renders_for_member(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

    def test_investing_workspace_bootstraps_default_universe_and_screener(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

        with app.app_context():
            default_watchlist = Watchlist.query.filter_by(
                dashboard_id=self.dashboard_id,
                name=DEFAULT_SCREENER_WATCHLIST_NAME
            ).first()
            self.assertIsNotNone(default_watchlist)
            self.assertEqual(
                WatchlistItem.query.filter_by(watchlist_id=default_watchlist.id).count(),
                len(app_module.load_default_screener_symbols())
            )

            default_screener = ScreenerDefinition.query.filter_by(
                dashboard_id=self.dashboard_id,
                name=DEFAULT_SAVED_SCREENER_NAME
            ).first()
            self.assertIsNotNone(default_screener)

    def test_create_watchlist_and_add_symbol(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Core', 'description': 'Long-term ideas'}
        )
        self.assertEqual(create_response.status_code, 201, create_response.get_data(as_text=True))
        watchlist = create_response.get_json()['watchlist']
        self.assertEqual(watchlist['name'], 'Core')

        add_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist["id"]}/items',
            json={'symbol': 'aapl', 'thesis_summary': 'High quality compounder'}
        )
        self.assertEqual(add_response.status_code, 201, add_response.get_data(as_text=True))
        payload = add_response.get_json()
        self.assertEqual(payload['item']['symbol'], 'AAPL')
        self.assertIsNone(payload['item']['snapshot'])

        with app.app_context():
            asset = Asset.query.filter_by(symbol='AAPL').first()
            self.assertEqual(Asset.query.filter_by(symbol='AAPL').count(), 1)
            self.assertEqual(MarketSnapshot.query.filter_by(asset_id=asset.id).count(), 0)
            self.assertEqual(FundamentalSnapshot.query.filter_by(asset_id=asset.id).count(), 0)
            self.assertIsNone(TickerSnapshotLatest.query.filter_by(asset_id=asset.id).first())
            fetch_state = TickerFetchState.query.filter_by(asset_id=asset.id).first()
            self.assertIsNotNone(fetch_state)
            self.assertTrue(fetch_state.is_intraday_pending)
            self.assertTrue(fetch_state.is_fundamentals_pending)
            self.assertFalse(fetch_state.is_backfill_pending)

    def test_selected_watchlist_persists_for_rendering(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Focus List', 'description': 'Selected card'}
        )
        selected_watchlist_id = create_response.get_json()['watchlist']['id']

        update_response = self.client.put(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlist-selection',
            json={'watchlist_id': selected_watchlist_id}
        )
        self.assertEqual(update_response.status_code, 200, update_response.get_data(as_text=True))

        with app.app_context():
            settings = UserDashboardSettings.query.filter_by(
                user_id=self.owner_id,
                dashboard_id=self.dashboard_id
            ).first()
            self.assertIsNotNone(settings)
            self.assertEqual(settings.selected_investing_watchlist_id, selected_watchlist_id)

        page_response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(page_response.status_code, 200, page_response.get_data(as_text=True))
        page_text = page_response.get_data(as_text=True)
        self.assertIn(f'<option value="{selected_watchlist_id}" selected>', page_text)
        self.assertIn('loadSelectedWatchlist(selectedWatchlistId);', page_text)

    def test_selected_watchlist_renders_all_rows_in_scroll_table(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Paged List', 'description': 'Large list'}
        )
        watchlist_id = create_response.get_json()['watchlist']['id']

        with app.app_context():
            watchlist = Watchlist.query.get(watchlist_id)
            assets = []
            for index in range(55):
                symbol = f'T{index:03d}'
                asset = Asset(symbol=symbol, name=f'Ticker {index}', asset_type='equity')
                db.session.add(asset)
                assets.append(asset)
            db.session.flush()
            for asset in assets:
                db.session.add(WatchlistItem(
                    watchlist_id=watchlist.id,
                    asset_id=asset.id,
                    added_by=self.owner_id
                ))
            db.session.commit()

        self.client.put(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlist-selection',
            json={'watchlist_id': watchlist_id}
        )

        page_response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(page_response.status_code, 200, page_response.get_data(as_text=True))
        detail_response = self.client.get(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}?page=1&page_size=100'
        )
        self.assertEqual(detail_response.status_code, 200, detail_response.get_data(as_text=True))
        watchlist_payload = detail_response.get_json()['watchlist']
        self.assertEqual(len(watchlist_payload['items']), 55)
        symbols = [item['symbol'] for item in watchlist_payload['items']]
        self.assertIn('T050', symbols)
        self.assertIn('T054', symbols)
        self.assertEqual(watchlist_payload['page_size'], 100)
        self.assertEqual(watchlist_payload['sort_by'], 'market_cap')

    def test_selected_screener_persists_for_rendering(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        save_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners',
            json={
                'name': 'Momentum Focus',
                'filters': {
                    'criteria': [
                        {
                            'criterion_id': 'price_performance_4w',
                            'selected_band_ids': ['5_15']
                        }
                    ]
                },
                'sort': {
                    'direction': 'desc'
                }
            }
        )
        self.assertEqual(save_response.status_code, 201, save_response.get_data(as_text=True))
        selected_screener_id = save_response.get_json()['screener']['id']

        update_response = self.client.put(
            f'/api/dashboard/{self.dashboard_id}/investing/screener-selection',
            json={'screener_id': selected_screener_id}
        )
        self.assertEqual(update_response.status_code, 200, update_response.get_data(as_text=True))

        with app.app_context():
            settings = UserDashboardSettings.query.filter_by(
                user_id=self.owner_id,
                dashboard_id=self.dashboard_id
            ).first()
            self.assertIsNotNone(settings)
            self.assertEqual(settings.selected_investing_screener_id, selected_screener_id)

        page_response = self.client.get(f'/dashboard/{self.dashboard_id}/investing')
        self.assertEqual(page_response.status_code, 200, page_response.get_data(as_text=True))
        page_text = page_response.get_data(as_text=True)
        self.assertIn(f'<option value="{selected_screener_id}" selected>', page_text)

    def test_refresh_asset_endpoint_queues_priority_refresh(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.post(f'/api/dashboard/{self.dashboard_id}/investing/assets/MSFT/refresh')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload['asset']['symbol'], 'MSFT')
        self.assertIn('Queued MSFT for priority refresh', payload['message'])

        with app.app_context():
            asset = Asset.query.filter_by(symbol='MSFT').first()
            fetch_state = TickerFetchState.query.filter_by(asset_id=asset.id).first()
            self.assertIsNotNone(fetch_state.priority_requested_at)

    def test_delete_watchlist_item(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Momentum'}
        )
        watchlist_id = create_response.get_json()['watchlist']['id']

        add_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'AAPL'}
        )
        item_id = add_response.get_json()['item']['id']

        delete_response = self.client.delete(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items/{item_id}'
        )
        self.assertEqual(delete_response.status_code, 200, delete_response.get_data(as_text=True))

        with app.app_context():
            self.assertEqual(WatchlistItem.query.filter_by(id=item_id).count(), 0)

    def test_update_watchlist_item_thesis(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Core'}
        )
        watchlist_id = create_response.get_json()['watchlist']['id']

        add_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'AAPL', 'thesis_summary': 'Initial thesis'}
        )
        item_id = add_response.get_json()['item']['id']

        update_response = self.client.put(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items/{item_id}',
            json={'thesis_summary': 'Updated thesis note'}
        )
        self.assertEqual(update_response.status_code, 200, update_response.get_data(as_text=True))
        payload = update_response.get_json()
        self.assertEqual(payload['item']['thesis_summary'], 'Updated thesis note')

    def test_create_trade_idea(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-ideas',
            json={
                'symbol': 'MSFT',
                'title': 'Cloud strength pullback setup',
                'idea_type': 'long',
                'thesis_summary': 'Looking for a durable cloud-led reacceleration.'
            }
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload['trade_idea']['asset_symbol'], 'MSFT')
        self.assertEqual(payload['trade_idea']['idea_type'], 'long')

        list_response = self.client.get(f'/api/dashboard/{self.dashboard_id}/investing/trade-ideas')
        self.assertEqual(list_response.status_code, 200, list_response.get_data(as_text=True))
        ideas = list_response.get_json()['trade_ideas']
        self.assertEqual(len(ideas), 1)
        self.assertEqual(ideas[0]['title'], 'Cloud strength pullback setup')

    def test_run_trade_agent_and_save_as_trade_idea(self):
        with app.app_context():
            asset = Asset(symbol='NVDA', name='NVIDIA', asset_type='equity', sector='Technology')
            db.session.add(asset)
            db.session.commit()

            db.session.add(TickerSnapshotLatest(
                asset_id=asset.id,
                last_price=920.0,
                today_change_percent=2.1,
                market_cap=2200000000000,
                volume=42000000,
                avg_volume=32000000,
                pe_ratio=41.0,
                peg_ratio=1.5,
                revenue_growth=0.62,
                eps_growth=0.71,
                moving_average_50=880.0,
                moving_average_200=760.0,
                quote_as_of=datetime.utcnow(),
                fundamentals_as_of=datetime.utcnow(),
            ))
            for offset in range(120):
                close = 700.0 + (offset * 1.8)
                db.session.add(TickerDailyBar(
                    asset_id=asset.id,
                    bar_date=datetime.utcnow().date() - timedelta(days=(120 - offset)),
                    open=close - 3,
                    high=close + 5,
                    low=close - 6,
                    close=close,
                    volume=25000000 + (offset * 10000),
                    source='fake'
                ))
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        run_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/run',
            json={'symbol': 'NVDA', 'request_text': 'Analyze this as a swing long setup'}
        )
        self.assertEqual(run_response.status_code, 201, run_response.get_data(as_text=True))
        payload = run_response.get_json()
        self.assertEqual(payload['run']['symbol'], 'NVDA')
        self.assertIn('analysis', payload['run'])
        self.assertIn('critic', payload['run'])
        self.assertIn('generation_mode', payload['run'])
        self.assertIn('stage_usage', payload['run'])
        self.assertIn('token_usage', payload['run'])

        run_id = payload['run']['id']
        save_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/runs/{run_id}/save-idea'
        )
        self.assertEqual(save_response.status_code, 201, save_response.get_data(as_text=True))
        save_payload = save_response.get_json()
        self.assertEqual(save_payload['trade_idea']['asset_symbol'], 'NVDA')
        self.assertEqual(save_payload['trade_idea']['title'], payload['run']['analysis']['title'])

        with app.app_context():
            run = TradeAgentRun.query.get(run_id)
            self.assertIsNotNone(run)
            self.assertIsNotNone(run.created_trade_idea_id)
            self.assertGreaterEqual(TradeAgentEvent.query.filter_by(trade_agent_run_id=run_id).count(), 3)

    def test_run_trade_agent_rejects_symbol_without_local_history(self):
        with app.app_context():
            asset = Asset(symbol='SHOP', name='Shopify', asset_type='equity', sector='Technology')
            db.session.add(asset)
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/run',
            json={'symbol': 'SHOP', 'request_text': 'Analyze this setup'}
        )
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertIn('Not enough price history', response.get_json()['error'])

    def test_trade_agent_auto_queues_fundamentals_refresh_when_fields_are_missing(self):
        with app.app_context():
            asset = Asset(symbol='AMD', name='AMD', asset_type='equity', sector='Technology')
            db.session.add(asset)
            db.session.commit()

            db.session.add(TickerSnapshotLatest(
                asset_id=asset.id,
                last_price=182.0,
                today_change_percent=-1.0,
                market_cap=290000000000,
                volume=38000000,
                avg_volume=42000000,
                pe_ratio=33.0,
                moving_average_50=176.0,
                moving_average_200=155.0,
                quote_as_of=datetime.utcnow(),
                fundamentals_as_of=datetime.utcnow(),
            ))
            db.session.add(TickerFundamentalsLatest(
                asset_id=asset.id,
                market_cap=290000000000,
                pe_ratio=33.0,
                as_of_date=datetime.utcnow().date(),
                fetched_at=datetime.utcnow(),
                raw_payload_json='{}'
            ))
            for offset in range(90):
                close = 140.0 + (offset * 0.5)
                db.session.add(TickerDailyBar(
                    asset_id=asset.id,
                    bar_date=datetime.utcnow().date() - timedelta(days=(90 - offset)),
                    open=close - 1,
                    high=close + 2,
                    low=close - 2,
                    close=close,
                    volume=28000000 + (offset * 3000),
                    source='fake'
                ))
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/run',
            json={'symbol': 'AMD', 'request_text': 'Analyze valuation and setup'}
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        payload = response.get_json()['run']
        joined_warnings = ' '.join(payload['warnings'])
        self.assertIn('Queued a priority fundamentals refresh for AMD', joined_warnings)
        self.assertEqual(payload['generation_mode'], 'deterministic')
        self.assertEqual(payload['stage_usage']['analysis'], 'heuristic')

        with app.app_context():
            fetch_state = TickerFetchState.query.filter_by(asset_id=Asset.query.filter_by(symbol='AMD').first().id).first()
            self.assertIsNotNone(fetch_state)
            self.assertTrue(fetch_state.is_fundamentals_pending)
            self.assertIsNotNone(fetch_state.priority_requested_at)

    def test_update_and_delete_trade_idea(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-ideas',
            json={
                'symbol': 'AAPL',
                'title': 'Initial idea',
                'idea_type': 'watch',
                'thesis_summary': 'Initial thesis'
            }
        )
        self.assertEqual(create_response.status_code, 201, create_response.get_data(as_text=True))
        idea_id = create_response.get_json()['trade_idea']['id']

        update_response = self.client.put(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-ideas/{idea_id}',
            json={
                'symbol': 'MSFT',
                'title': 'Updated cloud setup',
                'idea_type': 'long',
                'status': 'active',
                'entry_zone': '410 - 420',
                'target_1': '450',
                'target_2': '470',
                'invalidation': '398',
                'time_horizon': '2-6 weeks',
                'confidence_score': 72,
                'catalysts': 'Azure strength',
                'risks': 'Multiple compression'
            }
        )
        self.assertEqual(update_response.status_code, 200, update_response.get_data(as_text=True))
        updated = update_response.get_json()['trade_idea']
        self.assertEqual(updated['asset_symbol'], 'MSFT')
        self.assertEqual(updated['title'], 'Updated cloud setup')
        self.assertEqual(updated['target_2'], '470')

        delete_response = self.client.delete(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-ideas/{idea_id}'
        )
        self.assertEqual(delete_response.status_code, 200, delete_response.get_data(as_text=True))

        with app.app_context():
            self.assertIsNone(TradeIdea.query.get(idea_id))

    def test_list_trade_agent_runs(self):
        with app.app_context():
            asset = Asset(symbol='AMD', name='AMD', asset_type='equity', sector='Technology')
            db.session.add(asset)
            db.session.commit()

            db.session.add(TickerSnapshotLatest(
                asset_id=asset.id,
                last_price=180.0,
                today_change_percent=1.1,
                market_cap=300000000000,
                volume=50000000,
                avg_volume=42000000,
                moving_average_50=170.0,
                moving_average_200=150.0,
                quote_as_of=datetime.utcnow(),
                fundamentals_as_of=datetime.utcnow(),
            ))
            for offset in range(90):
                close = 120.0 + (offset * 0.7)
                db.session.add(TickerDailyBar(
                    asset_id=asset.id,
                    bar_date=datetime.utcnow().date() - timedelta(days=(90 - offset)),
                    open=close - 2,
                    high=close + 4,
                    low=close - 3,
                    close=close,
                    volume=30000000 + (offset * 5000),
                    source='fake'
                ))
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        run_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/run',
            json={'symbol': 'AMD', 'request_text': 'Review this ticker'}
        )
        self.assertEqual(run_response.status_code, 201, run_response.get_data(as_text=True))

        list_response = self.client.get(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/runs'
        )
        self.assertEqual(list_response.status_code, 200, list_response.get_data(as_text=True))
        runs = list_response.get_json()['runs']
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]['symbol'], 'AMD')

    def test_delete_trade_agent_run(self):
        with app.app_context():
            asset = Asset(symbol='AMD', name='AMD', asset_type='equity', sector='Technology')
            db.session.add(asset)
            db.session.commit()

            run = TradeAgentRun(
                dashboard_id=self.dashboard_id,
                asset_id=asset.id,
                created_by=self.owner_id,
                request_text='Test run',
                analysis_json='{}',
                critic_json='{}',
            )
            db.session.add(run)
            db.session.flush()
            db.session.add(TradeAgentEvent(
                trade_agent_run_id=run.id,
                event_type='test',
                event_payload_json='{}',
            ))
            db.session.commit()
            run_id = run.id

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.delete(
            f'/api/dashboard/{self.dashboard_id}/investing/trade-agent/runs/{run_id}'
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

        with app.app_context():
            self.assertIsNone(TradeAgentRun.query.get(run_id))
            self.assertEqual(TradeAgentEvent.query.filter_by(trade_agent_run_id=run_id).count(), 0)

    def test_run_trend_scan_and_list_runs(self):
        original_fetch = trade_social_scan_module.fetch_trend_source_items
        try:
            def fake_fetch(normalized_request, user):
                return {
                    'items': [
                        {
                            'source_name': 'gdelt',
                            'title': 'Lumentum (LITE) draws attention after optical supplier chatter',
                            'body_snippet': 'Traders are discussing Lumentum (LITE) as an optical beneficiary.',
                            'url': 'https://example.com/lite',
                            'published_at': datetime.utcnow().isoformat(),
                            'author_or_source': 'Example Source',
                            'engagement_hint': None,
                        }
                    ],
                    'warnings': [],
                    'sources_used': ['gdelt'],
                    'request_events': [],
                }

            trade_social_scan_module.fetch_trend_source_items = fake_fetch

            with app.app_context():
                asset = Asset(symbol='LITE', name='Lumentum Holdings', asset_type='equity', sector='Technology')
                db.session.add(asset)
                db.session.commit()
                db.session.add(TickerSnapshotLatest(
                    asset_id=asset.id,
                    last_price=55.0,
                    today_change_percent=3.0,
                    market_cap=4000000000,
                    volume=2400000,
                    avg_volume=1800000,
                    moving_average_50=50.0,
                    moving_average_200=47.0,
                    quote_as_of=datetime.utcnow(),
                    fundamentals_as_of=datetime.utcnow(),
                ))
                for offset in range(90):
                    close = 40.0 + (offset * 0.15)
                    db.session.add(TickerDailyBar(
                        asset_id=asset.id,
                        bar_date=datetime.utcnow().date() - timedelta(days=(90 - offset)),
                        open=close - 1,
                        high=close + 1.5,
                        low=close - 1.25,
                        close=close,
                        volume=1500000 + (offset * 1000),
                        source='fake'
                    ))
                db.session.commit()

            with self.client.session_transaction() as sess:
                sess['user_id'] = self.owner_id

            run_response = self.client.post(
                f'/api/dashboard/{self.dashboard_id}/investing/trend-scan/run',
                json={'scenario_prompt': 'nvidia gtc optical asic suppliers', 'source_modes': ['gdelt'], 'max_results': 3}
            )
            self.assertEqual(run_response.status_code, 201, run_response.get_data(as_text=True))
            payload = run_response.get_json()['run']
            self.assertEqual(payload['scenario_prompt'], 'nvidia gtc optical asic suppliers')
            self.assertEqual(payload['source_modes'], ['gdelt'])
            self.assertGreaterEqual(len(payload['ranked_results']), 1)
            self.assertEqual(payload['ranked_results'][0]['symbol'], 'LITE')

            list_response = self.client.get(
                f'/api/dashboard/{self.dashboard_id}/investing/trend-scan/runs'
            )
            self.assertEqual(list_response.status_code, 200, list_response.get_data(as_text=True))
            runs = list_response.get_json()['runs']
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]['top_symbols'][0], 'LITE')

            with app.app_context():
                run = TrendScanRun.query.first()
                self.assertIsNotNone(run)
                self.assertGreaterEqual(TrendScanEvent.query.filter_by(trend_scan_run_id=run.id).count(), 1)
        finally:
            trade_social_scan_module.fetch_trend_source_items = original_fetch

    def test_delete_trend_scan_run(self):
        with app.app_context():
            run = TrendScanRun(
                dashboard_id=self.dashboard_id,
                created_by=self.owner_id,
                scenario_prompt='oil shock',
                source_modes_json='["gdelt"]',
                ranked_results_json='[]',
                summary_json='{}',
            )
            db.session.add(run)
            db.session.flush()
            db.session.add(TrendScanEvent(
                trend_scan_run_id=run.id,
                event_type='test',
                event_payload_json='{}',
            ))
            db.session.commit()
            run_id = run.id

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        response = self.client.delete(
            f'/api/dashboard/{self.dashboard_id}/investing/trend-scan/runs/{run_id}'
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

        with app.app_context():
            self.assertIsNone(TrendScanRun.query.get(run_id))
            self.assertEqual(TrendScanEvent.query.filter_by(trend_scan_run_id=run_id).count(), 0)

    def test_save_and_run_screener_against_cached_snapshots(self):
        with app.app_context():
            nvda = Asset(symbol='NVDA', name='NVIDIA', asset_type='equity', sector='Technology')
            ibm = Asset(symbol='IBM', name='IBM', asset_type='equity', sector='Technology')
            db.session.add_all([nvda, ibm])
            db.session.commit()

            db.session.add_all([
                MarketSnapshot(
                    asset_id=nvda.id,
                    provider='fake',
                    price=910.0,
                    change_percent=4.8,
                    market_cap=2200000000000,
                    volume=42000000,
                    avg_volume=35000000,
                    moving_average_50=870.0,
                    moving_average_200=760.0
                ),
                MarketSnapshot(
                    asset_id=ibm.id,
                    provider='fake',
                    price=180.0,
                    change_percent=0.9,
                    market_cap=170000000000,
                    volume=3800000,
                    avg_volume=5000000,
                    moving_average_50=185.0,
                    moving_average_200=170.0
                ),
                FundamentalSnapshot(
                    asset_id=nvda.id,
                    provider='fake',
                    forward_pe=28.0,
                    revenue_growth=0.24,
                    eps_growth=0.31
                ),
                FundamentalSnapshot(
                    asset_id=ibm.id,
                    provider='fake',
                    forward_pe=19.0,
                    revenue_growth=0.04,
                    eps_growth=0.06
                ),
            ])
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        save_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners',
            json={
                'name': 'High Growth Tech',
                'description': 'Growth names already above trend',
                'filters': {
                    'sector_query': 'Tech',
                    'min_revenue_growth': 0.10,
                    'above_ma50': True
                },
                'sort': {
                    'by': 'revenue_growth',
                    'direction': 'desc'
                }
            }
        )
        self.assertEqual(save_response.status_code, 201, save_response.get_data(as_text=True))
        screener = save_response.get_json()['screener']
        self.assertEqual(screener['name'], 'High Growth Tech')

        run_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners/run',
            json={'screener_id': screener['id'], 'limit': 10}
        )
        self.assertEqual(run_response.status_code, 200, run_response.get_data(as_text=True))
        payload = run_response.get_json()
        self.assertEqual(payload['total_matches'], 1)
        self.assertEqual(payload['results'][0]['symbol'], 'NVDA')
        self.assertAlmostEqual(payload['results'][0]['revenue_growth'], 0.24, places=2)

    def test_run_screener_denies_non_member(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.outsider_id

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners/run',
            json={'filters': {'min_market_cap': 1000}}
        )
        self.assertEqual(response.status_code, 403)

    def test_run_watchlist_cached_screener_uses_selected_watchlist_symbols(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Core'}
        )
        watchlist_id = create_response.get_json()['watchlist']['id']
        self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'AAPL'}
        )
        self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'MSFT'}
        )

        with app.app_context():
            aapl = Asset.query.filter_by(symbol='AAPL').first()
            msft = Asset.query.filter_by(symbol='MSFT').first()
            aapl_market = MarketSnapshot(
                asset_id=aapl.id,
                provider='test',
                snapshot_date=app_module.datetime.utcnow().date(),
                price=123.45,
                market_cap=1500000000,
                volume=1200000,
                avg_volume=1000000,
            )
            msft_market = MarketSnapshot(
                asset_id=msft.id,
                provider='test',
                snapshot_date=app_module.datetime.utcnow().date(),
                price=234.56,
                market_cap=2500000000,
                volume=2200000,
                avg_volume=1800000,
            )
            db.session.add_all([aapl_market, msft_market])
            aapl_fundamentals = FundamentalSnapshot(asset_id=aapl.id, provider='test', as_of_date=app_module.datetime.utcnow().date())
            msft_fundamentals = FundamentalSnapshot(asset_id=msft.id, provider='test', as_of_date=app_module.datetime.utcnow().date())
            db.session.add_all([aapl_fundamentals, msft_fundamentals])
            aapl_fundamentals.forward_pe = 18.0
            msft_fundamentals.forward_pe = 36.0
            db.session.commit()

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners/run',
            json={
                'filters': {
                    'watchlist_id': watchlist_id,
                    'max_forward_pe': 30
                },
                'sort': {
                    'by': 'market_cap',
                    'direction': 'desc'
                }
            }
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload['watchlist']['id'], watchlist_id)
        self.assertEqual(payload['total_matches'], 1)
        self.assertEqual(payload['results'][0]['symbol'], 'AAPL')
        self.assertAlmostEqual(payload['results'][0]['forward_pe'], 18.0, places=2)

    def test_run_watchlist_cached_screener_with_faceted_criteria(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.owner_id

        create_response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists',
            json={'name': 'Facet Test'}
        )
        watchlist_id = create_response.get_json()['watchlist']['id']
        self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'AAPL'}
        )
        self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/watchlists/{watchlist_id}/items',
            json={'symbol': 'MSFT'}
        )

        with app.app_context():
            aapl = Asset.query.filter_by(symbol='AAPL').first()
            msft = Asset.query.filter_by(symbol='MSFT').first()
            aapl_snapshot = MarketSnapshot(
                asset_id=aapl.id,
                provider='test',
                snapshot_date=app_module.datetime.utcnow().date(),
                price=123.45,
                market_cap=1500000000,
                volume=1200000,
                avg_volume=1000000,
            )
            msft_snapshot = MarketSnapshot(
                asset_id=msft.id,
                provider='test',
                snapshot_date=app_module.datetime.utcnow().date(),
                price=234.56,
                market_cap=2500000000,
                volume=2200000,
                avg_volume=1800000,
            )
            db.session.add_all([aapl_snapshot, msft_snapshot])
            aapl_snapshot.moving_average_50 = 100.0
            msft_snapshot.moving_average_50 = 220.0
            db.session.commit()

        response = self.client.post(
            f'/api/dashboard/{self.dashboard_id}/investing/screeners/run',
            json={
                'filters': {
                    'watchlist_id': watchlist_id,
                    'criteria': [
                        {
                            'criterion_id': 'percent_price_off_50day_sma',
                            'selected_band_ids': ['gt_10']
                        }
                    ]
                },
                'sort': {
                    'by': 'percent_price_off_50day_sma',
                    'direction': 'desc'
                }
            }
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload['total_matches'], 1)
        self.assertEqual(payload['results'][0]['symbol'], 'AAPL')


if __name__ == '__main__':
    unittest.main()
