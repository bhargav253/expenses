#!/usr/bin/env python3

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

from ticker_ingestion import FinnhubClient

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


RUN_LIVE = os.environ.get("RUN_FINNHUB_LIVE_TESTS", "false").lower() == "true"
TEST_SYMBOL = os.environ.get("FINNHUB_TEST_SYMBOL", "AAPL").strip().upper()


@unittest.skipUnless(RUN_LIVE, "Set RUN_FINNHUB_LIVE_TESTS=true to run live Finnhub API checks")
class TestFinnhubLiveRequests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = FinnhubClient()

    def test_company_profile_request(self):
        payload = self.client.get_company_profile(TEST_SYMBOL)
        print(
            f"\n[company_profile] keys={sorted(payload.keys())} "
            f"name={payload.get('name')} exchange={payload.get('exchange')} "
            f"industry={payload.get('finnhubIndustry')}",
            flush=True,
        )
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload.get("ticker") == TEST_SYMBOL or payload.get("name"))

    def test_basic_financials_request(self):
        payload = self.client.get_basic_financials(TEST_SYMBOL)
        metric = payload.get("metric") or {}
        interesting_fields = {
            "marketCapitalization": metric.get("marketCapitalization"),
            "peNormalizedAnnual": metric.get("peNormalizedAnnual"),
            "peTTM": metric.get("peTTM"),
            "pegRatio": metric.get("pegRatio"),
            "totalRevenueAnnual": metric.get("totalRevenueAnnual"),
            "revenuePerShareTTM": metric.get("revenuePerShareTTM"),
            "salesPerShareTTM": metric.get("salesPerShareTTM"),
            "dividendYieldIndicatedAnnual": metric.get("dividendYieldIndicatedAnnual"),
            "shareOutstanding": metric.get("shareOutstanding"),
        }
        print(
            f"\n[basic_financials] metric_keys_sample={sorted(metric.keys())[:40]} "
            f"interesting_fields={interesting_fields}",
            flush=True,
        )
        self.assertIsInstance(payload, dict)
        self.assertIn("metric", payload)
        self.assertTrue(
            any(
                metric.get(key) is not None
                for key in (
                    "marketCapitalization",
                    "peNormalizedAnnual",
                    "peTTM",
                    "pegRatio",
                    "totalRevenueAnnual",
                    "revenuePerShareTTM",
                    "salesPerShareTTM",
                )
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
