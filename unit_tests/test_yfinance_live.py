#!/usr/bin/env python3

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

from ticker_ingestion import YFinanceBatchClient

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


RUN_LIVE = os.environ.get("RUN_YFINANCE_LIVE_TESTS", "false").lower() == "true"
TEST_SYMBOLS = [
    symbol.strip().upper()
    for symbol in os.environ.get("YFINANCE_TEST_SYMBOLS", "AAPL,GOOG,MSFT,NVDA,AMD").split(",")
    if symbol.strip()
]


@unittest.skipUnless(RUN_LIVE, "Set RUN_YFINANCE_LIVE_TESTS=true to run live yfinance batch checks")
class TestYFinanceLiveBatchRequests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = YFinanceBatchClient()

    def test_hourly_batch_request(self):
        payload = self.client.get_hourly_bars(TEST_SYMBOLS)
        print(f"\n[yfinance_batch] requested={TEST_SYMBOLS} returned={sorted(payload.keys())}", flush=True)
        for symbol in TEST_SYMBOLS:
            bars = payload.get(symbol) or []
            preview = bars[-1] if bars else None
            print(f"[yfinance_batch] symbol={symbol} bars={len(bars)} latest={preview}", flush=True)

        self.assertIsInstance(payload, dict)
        self.assertGreater(len(payload), 0)
        for symbol, bars in payload.items():
            self.assertIsInstance(bars, list)
            self.assertGreater(len(bars), 0)
            self.assertIn("timestamp", bars[-1])
            self.assertIn("close", bars[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
