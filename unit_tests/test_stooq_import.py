#!/usr/bin/env python3

import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import Asset, TickerDailyBar, TickerFetchState, TickerSnapshotLatest
from scripts.import_stooq_daily import run_import


class TestStooqImport(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.stooq_root = self.root / "data" / "daily" / "us" / "nasdaq stocks" / "1"
        self.stooq_root.mkdir(parents=True, exist_ok=True)
        self.symbols_file = self.root / "symbols.txt"
        self.missing_report = self.root / "missing.txt"

        with app.app_context():
            db.create_all()
            TickerDailyBar.query.delete(synchronize_session=False)
            TickerSnapshotLatest.query.delete(synchronize_session=False)
            TickerFetchState.query.delete(synchronize_session=False)
            Asset.query.filter(Asset.symbol.in_(["AAPL", "MSFT"])).delete(synchronize_session=False)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            TickerDailyBar.query.delete(synchronize_session=False)
            TickerSnapshotLatest.query.delete(synchronize_session=False)
            TickerFetchState.query.delete(synchronize_session=False)
            Asset.query.filter(Asset.symbol.in_(["AAPL", "MSFT"])).delete(synchronize_session=False)
            db.session.commit()
        self.tmpdir.cleanup()

    def test_import_only_adds_new_daily_rows_on_rerun(self):
        self.symbols_file.write_text("AAPL\nMSFT\n", encoding="utf-8")
        self._write_stooq_file(
            "aapl.us.txt",
            [
                "AAPL.US,D,20250303,000000,100,101,99,100.5,1000,0",
                "AAPL.US,D,20250304,000000,101,102,100,101.5,1100,0",
            ],
        )
        self._write_stooq_file(
            "msft.us.txt",
            [
                "MSFT.US,D,20250227,000000,200,202,199,201,900,0",
                "MSFT.US,D,20250305,000000,202,203,201,202.5,950,0",
            ],
        )

        with app.app_context():
            summary = run_import(
                stooq_root=self.root / "data" / "daily" / "us",
                symbols_file=self.symbols_file,
                cutoff_date=date(2025, 3, 1),
                missing_report=self.missing_report,
            )
            self.assertEqual(summary.symbols_total, 2)
            self.assertEqual(summary.symbols_missing_files, 0)
            self.assertEqual(summary.bars_inserted, 3)
            self.assertEqual(TickerDailyBar.query.count(), 3)

        self._write_stooq_file(
            "aapl.us.txt",
            [
                "AAPL.US,D,20250303,000000,100,101,99,100.5,1000,0",
                "AAPL.US,D,20250304,000000,101,102,100,101.5,1100,0",
                "AAPL.US,D,20250305,000000,102,103,101,102.5,1200,0",
            ],
        )
        self._write_stooq_file(
            "msft.us.txt",
            [
                "MSFT.US,D,20250227,000000,200,202,199,201,900,0",
                "MSFT.US,D,20250305,000000,202,203,201,202.5,950,0",
                "MSFT.US,D,20250306,000000,203,204,202,203.5,975,0",
            ],
        )

        with app.app_context():
            summary = run_import(
                stooq_root=self.root / "data" / "daily" / "us",
                symbols_file=self.symbols_file,
                cutoff_date=date(2025, 3, 1),
                missing_report=self.missing_report,
            )
            self.assertEqual(summary.bars_inserted, 2)
            self.assertEqual(TickerDailyBar.query.count(), 5)
            aapl = Asset.query.filter_by(symbol="AAPL").first()
            fetch_state = TickerFetchState.query.filter_by(asset_id=aapl.id).first()
            snapshot = TickerSnapshotLatest.query.filter_by(asset_id=aapl.id).first()
            self.assertEqual(fetch_state.last_daily_bar_date.isoformat(), "2025-03-05")
            self.assertFalse(fetch_state.is_backfill_pending)
            self.assertAlmostEqual(snapshot.last_price, 102.5, places=2)

    def _write_stooq_file(self, filename, rows):
        content = "\n".join(
            ["<TICKER>,<PER>,<DATE>,<TIME>,<OPEN>,<HIGH>,<LOW>,<CLOSE>,<VOL>,<OPENINT>", *rows]
        )
        (self.stooq_root / filename).write_text(content + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
