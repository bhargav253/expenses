#!/usr/bin/env python3

from __future__ import annotations

import argparse
from typing import Iterable

from sqlalchemy import MetaData, create_engine, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine


GLOBAL_TICKER_TABLES = [
    "asset",
    "ticker_fetch_state",
    "ticker_daily_bar",
    "ticker_intraday_bar",
    "ticker_snapshot_latest",
    "ticker_fundamentals_latest",
    "market_snapshot",
    "fundamental_snapshot",
]

OPTIONAL_WORKSPACE_TABLES = [
    "watchlist",
    "screener_definition",
    "watchlist_item",
    "trade_idea",
    "trade_agent_run",
    "trade_agent_event",
    "trend_scan_run",
    "trend_scan_event",
]

DEFAULT_BATCH_SIZE = 5000


def reflect_tables(engine: Engine, table_names: Iterable[str]):
    metadata = MetaData()
    metadata.reflect(bind=engine, only=list(table_names))
    return metadata


def count_rows(source_engine: Engine, table):
    with source_engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(table)).scalar() or 0


def fetch_rows(source_engine: Engine, table, *, offset: int | None = None, limit: int | None = None):
    statement = select(table)
    primary_keys = [column for column in table.primary_key.columns]
    if primary_keys:
        statement = statement.order_by(*primary_keys)
    if offset is not None:
        statement = statement.offset(offset)
    if limit is not None:
        statement = statement.limit(limit)
    with source_engine.connect() as conn:
        return [dict(row) for row in conn.execute(statement).mappings().all()]


def upsert_postgres_rows(target_engine: Engine, table, rows: list[dict]):
    if not rows:
        return 0
    primary_keys = [column.name for column in table.primary_key.columns]
    update_columns = {
        column.name: getattr(pg_insert(table).excluded, column.name)
        for column in table.columns
        if column.name not in primary_keys
    }
    statement = pg_insert(table).values(rows)
    if primary_keys:
        statement = statement.on_conflict_do_update(
            index_elements=primary_keys,
            set_=update_columns,
        )
    with target_engine.begin() as conn:
        conn.execute(statement)
    return len(rows)


def reset_postgres_sequence(target_engine: Engine, table):
    primary_keys = [column for column in table.primary_key.columns]
    if len(primary_keys) != 1:
        return
    primary_key = primary_keys[0]
    if not getattr(primary_key.type, "python_type", None) is int:
        return

    with target_engine.begin() as conn:
        sequence_name = conn.execute(
            select(func.pg_get_serial_sequence(table.name, primary_key.name))
        ).scalar()
        if not sequence_name:
            return
        max_id = conn.execute(select(func.max(getattr(table.c, primary_key.name)))).scalar()
        if max_id is None:
            max_id = 1
        conn.execute(text("SELECT setval(:sequence_name, :value, true)"), {
            "sequence_name": sequence_name,
            "value": max_id,
        })


def ensure_tables_present(metadata: MetaData, table_names: list[str], label: str):
    missing = [table_name for table_name in table_names if table_name not in metadata.tables]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(f"Missing {label} tables: {joined}")


def main():
    parser = argparse.ArgumentParser(description="One-time investing-data migration from local SQLite to Postgres")
    parser.add_argument("--source-sqlite", required=True, help="Path to the source SQLite database file")
    parser.add_argument("--target-database-url", required=True, help="Target Postgres DATABASE_URL")
    parser.add_argument(
        "--tables",
        nargs="*",
        default=None,
        help="Override the tables to copy explicitly",
    )
    parser.add_argument(
        "--include-workspace-data",
        action="store_true",
        help="Also copy watchlists, trade ideas, and agent runs in addition to global ticker data",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Rows per batch for large table copies",
    )
    args = parser.parse_args()

    table_names = args.tables or list(GLOBAL_TICKER_TABLES)
    if args.include_workspace_data and args.tables is None:
        table_names.extend(OPTIONAL_WORKSPACE_TABLES)

    source_url = f"sqlite:///{args.source_sqlite}"
    target_url = args.target_database_url
    if target_url.startswith("postgres://"):
        target_url = target_url.replace("postgres://", "postgresql://", 1)

    source_engine = create_engine(source_url)
    target_engine = create_engine(target_url)

    source_metadata = reflect_tables(source_engine, table_names)
    target_metadata = reflect_tables(target_engine, table_names)
    ensure_tables_present(source_metadata, table_names, "source")
    ensure_tables_present(target_metadata, table_names, "target")

    print("[migrate_investing_data] starting copy")
    copied_counts = {}
    for table_name in table_names:
        source_table = source_metadata.tables[table_name]
        target_table = target_metadata.tables[table_name]
        total_rows = count_rows(source_engine, source_table)
        print(f"[migrate_investing_data] table={table_name} total_rows={total_rows}")
        copied_count = 0
        if total_rows == 0:
            reset_postgres_sequence(target_engine, target_table)
            copied_counts[table_name] = 0
            print(f"[migrate_investing_data] copied table={table_name} rows=0")
            continue

        for offset in range(0, total_rows, args.batch_size):
            rows = fetch_rows(source_engine, source_table, offset=offset, limit=args.batch_size)
            batch_count = upsert_postgres_rows(target_engine, target_table, rows)
            copied_count += batch_count
            batch_end = min(offset + batch_count, total_rows)
            print(
                f"[migrate_investing_data] table={table_name} batch_rows={batch_count} progress={batch_end}/{total_rows}"
            )
        reset_postgres_sequence(target_engine, target_table)
        copied_counts[table_name] = copied_count
        print(f"[migrate_investing_data] copied table={table_name} rows={copied_count}")

    total_rows = sum(copied_counts.values())
    print(f"[migrate_investing_data] complete tables={len(copied_counts)} rows={total_rows}")


if __name__ == "__main__":
    main()
