import os
import argparse
import json

from app import app, init_db
from ticker_ingestion import TickerIngestionWorker, get_worker_status_summary


def main():
    parser = argparse.ArgumentParser(description="Run or inspect the ticker ingestion worker")
    parser.add_argument("--once", action="store_true", help="Run one ingestion cycle and exit")
    parser.add_argument("--status", action="store_true", help="Print worker/database status and exit")
    args = parser.parse_args()

    run_once = args.once or os.environ.get("TICKER_WORKER_ONCE", "false").lower() == "true"
    print_status = args.status
    sleep_seconds = int(os.environ.get("TICKER_WORKER_SLEEP_SECONDS", "10"))

    with app.app_context():
        init_db()
        if print_status:
            print(json.dumps(get_worker_status_summary(), indent=2))
            return
        worker = TickerIngestionWorker()
        if run_once:
            processed = worker.run_once()
            print(f"ticker_worker processed={processed}")
            return
        worker.run_forever(sleep_seconds=sleep_seconds)


if __name__ == "__main__":
    main()
