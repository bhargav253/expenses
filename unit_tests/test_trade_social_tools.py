#!/usr/bin/env python3

import os
import sys
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unit_tests.test_bootstrap import configure_test_db

configure_test_db(os.path.basename(__file__))

from app import app, db  # noqa: E402
from models import User  # noqa: E402
from trade_social_tools import (  # noqa: E402
    extract_trend_candidates,
    fetch_gdelt_items,
    fetch_newsapi_items,
    fetch_reddit_items,
    fetch_stocktwits_items,
    fetch_trend_source_items,
    normalize_trend_scan_request,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"{self.status_code} error")

    def json(self):
        return self._payload


class TestTradeSocialTools(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            suffix = uuid.uuid4().hex[:8]
            user = User(
                email=f"social-tools-{suffix}@example.com",
                name="Social Tools User",
                username=f"social-tools-{suffix}",
            )
            user.set_password("password")
            user.set_encrypted_api_key("newsapi_api_key", "test-news-key")
            user.newsapi_daily_limit = 10
            db.session.add(user)
            db.session.commit()
            self.user_id = user.id

    def tearDown(self):
        with app.app_context():
            User.query.filter_by(id=getattr(self, "user_id", None)).delete()
            db.session.commit()

    @patch("trade_social_tools.requests.get")
    def test_fetch_gdelt_items_normalizes_articles(self, mock_get):
        mock_get.return_value = FakeResponse(
            {
                "articles": [
                    {
                        "title": "Oil stocks jump as conflict risk rises",
                        "url": "https://example.com/oil-1",
                        "domain": "example.com",
                        "seendate": "20260331083000",
                    },
                    {
                        "title": "Oil stocks jump as conflict risk rises",
                        "url": "https://example.com/oil-1",
                        "domain": "example.com",
                        "seendate": "20260331083000",
                    },
                ]
            }
        )

        items = fetch_gdelt_items(["iran war oil stocks"], limit=5)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_name"], "gdelt")
        self.assertEqual(items[0]["author_or_source"], "example.com")
        self.assertEqual(items[0]["url"], "https://example.com/oil-1")

    @patch("trade_social_tools.requests.get")
    def test_fetch_newsapi_items_uses_user_key_and_normalizes_articles(self, mock_get):
        mock_get.return_value = FakeResponse(
            {
                "articles": [
                    {
                        "title": "Defense shares rally",
                        "description": "RTX and LMT rise on geopolitical worries",
                        "url": "https://example.com/defense",
                        "publishedAt": "2026-03-31T12:00:00Z",
                        "source": {"name": "Reuters"},
                    }
                ]
            }
        )

        with app.app_context():
            user = User.query.get(self.user_id)
            items = fetch_newsapi_items(["iran war defense stocks"], user, limit=5)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_name"], "newsapi")
        self.assertEqual(items[0]["author_or_source"], "Reuters")
        self.assertIn("RTX", items[0]["body_snippet"])

    @patch("trade_social_tools.requests.get")
    def test_fetch_reddit_items_filters_to_allowed_subreddits(self, mock_get):
        mock_get.return_value = FakeResponse(
            {
                "data": {
                    "children": [
                        {
                            "data": {
                                "title": "LITE looks interesting after GTC",
                                "selftext": "Possible optics sympathy play",
                                "permalink": "/r/wallstreetbets/comments/abc123/lite/",
                                "created_utc": 1774958400,
                                "score": 123,
                                "subreddit": "wallstreetbets",
                            }
                        },
                        {
                            "data": {
                                "title": "Ignore this off-topic result",
                                "selftext": "Not from an allowed investing subreddit",
                                "permalink": "/r/pics/comments/abc123/nope/",
                                "created_utc": 1774958400,
                                "score": 15,
                                "subreddit": "pics",
                            }
                        },
                    ]
                }
            }
        )

        items = fetch_reddit_items(["nvidia gtc optical asic suppliers"], limit=5)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_name"], "reddit")
        self.assertEqual(items[0]["author_or_source"], "wallstreetbets")

    @patch("trade_social_tools.requests.get")
    def test_fetch_stocktwits_items_normalizes_trending_symbols(self, mock_get):
        mock_get.return_value = FakeResponse(
            {
                "symbols": [
                    {"symbol": "LITE"},
                    {"symbol": "AAOI"},
                ]
            }
        )

        items = fetch_stocktwits_items(["optical suppliers"], limit=5)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["source_name"], "stocktwits")
        self.assertEqual(items[0]["url"], "https://stocktwits.com/symbol/LITE")

    @patch("trade_social_tools.fetch_stocktwits_items")
    @patch("trade_social_tools.fetch_reddit_items")
    @patch("trade_social_tools.fetch_newsapi_items")
    @patch("trade_social_tools.fetch_gdelt_items")
    def test_fetch_trend_source_items_collects_sources_and_warnings(
        self,
        mock_gdelt,
        mock_newsapi,
        mock_reddit,
        mock_stocktwits,
    ):
        mock_gdelt.side_effect = Exception("429 rate limited")
        mock_newsapi.return_value = [
            {
                "source_name": "newsapi",
                "title": "Oil majors rally",
                "body_snippet": "XOM and CVX were mentioned.",
                "url": "https://example.com/oilmajors",
                "published_at": "2026-03-31T12:00:00Z",
                "author_or_source": "Reuters",
                "engagement_hint": None,
            }
        ]
        mock_reddit.return_value = []
        mock_stocktwits.return_value = []

        normalized_request = normalize_trend_scan_request(
            "iran war and oil prices",
            source_modes=["gdelt", "newsapi", "reddit", "stocktwits"],
            max_results=5,
        )

        with app.app_context():
            user = User.query.get(self.user_id)
            payload = fetch_trend_source_items(normalized_request, user)

        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(normalized_request["source_modes"][0], "newsapi")
        self.assertEqual(payload["sources_used"], ["newsapi"])
        self.assertTrue(any("gdelt fetch failed" in warning for warning in payload["warnings"]))
        self.assertEqual(len(payload["request_events"]), 1)
        self.assertEqual(payload["request_events"][0]["event_type"], "newsapi_request")
        self.assertEqual(payload["source_statuses"][0]["source_name"], "newsapi")

    def test_extract_trend_candidates_seeds_prompt_symbols_when_source_items_exist(self):
        items = [
            {
                "source_name": "newsapi",
                "title": "NVIDIA and Marvell partnership chatter grows",
                "body_snippet": "Discussion around a possible supplier relationship continues.",
                "url": "https://example.com/nvda-mrvl",
                "published_at": "2026-03-31T12:00:00Z",
                "author_or_source": "Reuters",
                "engagement_hint": None,
            }
        ]
        with app.app_context():
            candidate_map = extract_trend_candidates(items, prompt_symbols=["NVDA", "MRVL"])
        self.assertIn("NVDA", candidate_map)
        self.assertIn("MRVL", candidate_map)
        self.assertGreaterEqual(candidate_map["NVDA"]["mention_count"], 1)
        self.assertGreaterEqual(candidate_map["MRVL"]["mention_count"], 1)


if __name__ == "__main__":
    unittest.main()
