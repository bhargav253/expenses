#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app, db
from models import Asset, TickerDailyBar
from ticker_ingestion import get_or_create_fetch_state, refresh_ticker_snapshot_from_sources, utcnow


DEFAULT_SYMBOLS_FILE = Path("next_plan/screener/default_watchlist.txt")
DEFAULT_MISSING_REPORT = Path("next_plan/screener/stooq_missing_symbols.txt")
DEFAULT_CUTOFF_DATE = date(2025, 3, 1)


@dataclass
class ImportSummary:
    symbols_total: int = 0
    symbols_with_files: int = 0
    symbols_missing_files: int = 0
    assets_created: int = 0
    bars_inserted: int = 0
    bars_skipped_existing: int = 0


def load_symbols(symbols_file: Path) -> list[str]:
    symbols = []
    seen = set()
    for line in symbols_file.read_text(encoding="utf-8").splitlines():
        symbol = line.strip().upper()
        if not symbol or symbol.startswith("#") or symbol in seen:
            continue
        seen.add(symbol)
        symbols.append(symbol)
    return symbols


def symbol_variants(symbol: str) -> set[str]:
    symbol = symbol.upper()
    variants = {symbol}
    variants.add(symbol.replace(".", "-"))
    variants.add(symbol.replace("-", "."))
    variants.add(symbol.replace(".", "_"))
    variants.add(symbol.replace("-", "_"))
    return {value for value in variants if value}


def index_stooq_files(stooq_root: Path) -> dict[str, Path]:
    indexed = {}
    for file_path in stooq_root.rglob("*.us.txt"):
        base_symbol = file_path.name[:-7].upper()
        for variant in symbol_variants(base_symbol):
            indexed.setdefault(variant, file_path)
    return indexed


def resolve_stooq_file(symbol: str, file_index: dict[str, Path]) -> Path | None:
    for variant in symbol_variants(symbol):
        match = file_index.get(variant)
        if match is not None:
            return match
    return None


def ensure_asset(symbol: str) -> tuple[Asset, bool]:
    asset = Asset.query.filter_by(symbol=symbol).first()
    if asset is not None:
        return asset, False

    asset = Asset(
        symbol=symbol,
        asset_type="equity",
        status="active",
        is_active=True,
        added_source="seed",
    )
    db.session.add(asset)
    db.session.flush()
    return asset, True


def latest_daily_bar_date(asset_id: int) -> date | None:
    row = (
        TickerDailyBar.query.filter_by(asset_id=asset_id)
        .order_by(TickerDailyBar.bar_date.desc())
        .first()
    )
    return row.bar_date if row else None


def import_symbol_history(asset: Asset, stooq_file: Path, cutoff_date: date) -> tuple[int, int]:
    latest_loaded_date = latest_daily_bar_date(asset.id)
    effective_start = max(cutoff_date, latest_loaded_date + timedelta(days=1)) if latest_loaded_date else cutoff_date
    inserted = 0
    skipped_existing = 0

    with stooq_file.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if (row.get("<PER>") or "").strip().upper() != "D":
                continue
            raw_date = (row.get("<DATE>") or "").strip()
            if not raw_date:
                continue
            bar_date = datetime.strptime(raw_date, "%Y%m%d").date()
            if bar_date < effective_start:
                continue

            existing = TickerDailyBar.query.filter_by(asset_id=asset.id, bar_date=bar_date).first()
            if existing is not None:
                skipped_existing += 1
                continue

            db.session.add(
                TickerDailyBar(
                    asset_id=asset.id,
                    bar_date=bar_date,
                    open=_parse_float(row.get("<OPEN>")),
                    high=_parse_float(row.get("<HIGH>")),
                    low=_parse_float(row.get("<LOW>")),
                    close=_parse_float(row.get("<CLOSE>")),
                    volume=_parse_float(row.get("<VOL>")),
                    source="stooq",
                )
            )
            inserted += 1

    if inserted:
        db.session.flush()

    fetch_state = get_or_create_fetch_state(asset)
    latest_bar_date = latest_daily_bar_date(asset.id)
    fetch_state.last_daily_bar_date = latest_bar_date
    fetch_state.history_backfilled_at = utcnow() if latest_bar_date else fetch_state.history_backfilled_at
    fetch_state.is_backfill_pending = False
    fetch_state.updated_at = utcnow()
    refresh_ticker_snapshot_from_sources(asset)
    return inserted, skipped_existing


def write_missing_report(
    missing_symbols: list[str],
    report_path: Path,
    symbols_file: Path,
    stooq_root: Path,
    summary: ImportSummary,
):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Stooq daily import check against {symbols_file.as_posix()}",
        f"Source directory: {stooq_root}",
        f"Checked on: {date.today().isoformat()}",
        "",
        f"Universe size: {summary.symbols_total}",
        f"Missing from current Stooq dump: {len(missing_symbols)}",
        "",
    ]
    lines.extend(missing_symbols)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_float(value: str | None) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def run_import(
    *,
    stooq_root: Path,
    symbols_file: Path = DEFAULT_SYMBOLS_FILE,
    cutoff_date: date = DEFAULT_CUTOFF_DATE,
    missing_report: Path = DEFAULT_MISSING_REPORT,
) -> ImportSummary:
    symbols = load_symbols(symbols_file)
    file_index = index_stooq_files(stooq_root)
    missing_symbols = []
    summary = ImportSummary(symbols_total=len(symbols))

    for position, symbol in enumerate(symbols, start=1):
        stooq_file = resolve_stooq_file(symbol, file_index)
        if stooq_file is None:
            missing_symbols.append(symbol)
            summary.symbols_missing_files += 1
            print(f"[stooq_import] missing file symbol={symbol} progress={position}/{len(symbols)}", flush=True)
            continue

        summary.symbols_with_files += 1
        asset, created = ensure_asset(symbol)
        if created:
            summary.assets_created += 1
        inserted, skipped_existing = import_symbol_history(asset, stooq_file, cutoff_date)
        summary.bars_inserted += inserted
        summary.bars_skipped_existing += skipped_existing
        print(
            f"[stooq_import] symbol={symbol} progress={position}/{len(symbols)} inserted={inserted} skipped_existing={skipped_existing}",
            flush=True,
        )

    write_missing_report(missing_symbols, missing_report, symbols_file, stooq_root, summary)
    db.session.commit()
    return summary


def parse_args():
    parser = argparse.ArgumentParser(description="Import Stooq daily bars into the ticker universe.")
    parser.add_argument("--stooq-root", required=True, help="Path to the Stooq daily US directory.")
    parser.add_argument("--symbols-file", default=str(DEFAULT_SYMBOLS_FILE), help="Ticker universe file.")
    parser.add_argument("--cutoff-date", default=DEFAULT_CUTOFF_DATE.isoformat(), help="Only import bars on or after YYYY-MM-DD.")
    parser.add_argument("--missing-report", default=str(DEFAULT_MISSING_REPORT), help="Where to write unresolved Stooq symbols.")
    return parser.parse_args()


def main():
    args = parse_args()
    stooq_root = Path(args.stooq_root).expanduser().resolve()
    symbols_file = Path(args.symbols_file).expanduser().resolve()
    missing_report = Path(args.missing_report).expanduser().resolve()
    cutoff_date = datetime.strptime(args.cutoff_date, "%Y-%m-%d").date()

    if not stooq_root.exists():
        raise SystemExit(f"Stooq root not found: {stooq_root}")
    if not symbols_file.exists():
        raise SystemExit(f"Symbols file not found: {symbols_file}")

    with app.app_context():
        summary = run_import(
            stooq_root=stooq_root,
            symbols_file=symbols_file,
            cutoff_date=cutoff_date,
            missing_report=missing_report,
        )
        print(
            "[stooq_import] complete "
            f"symbols_total={summary.symbols_total} "
            f"symbols_with_files={summary.symbols_with_files} "
            f"symbols_missing_files={summary.symbols_missing_files} "
            f"assets_created={summary.assets_created} "
            f"bars_inserted={summary.bars_inserted} "
            f"bars_skipped_existing={summary.bars_skipped_existing}",
            flush=True,
        )


if __name__ == "__main__":
    main()
