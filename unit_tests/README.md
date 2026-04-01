Unit test rule:

- Never point tests at the real application database.
- Any test that imports `app` must set `DATABASE_URL` / `SQLALCHEMY_DATABASE_URI` to a dedicated test SQLite file before importing `app`.
- Use [test_bootstrap.py](/media/poseidon/HDD1/projects/Expenses/unit_tests/test_bootstrap.py) for that setup.

Reason:

- Several tests delete rows from ticker and investing tables during setup/teardown.
- If those tests bind to `sqlite:///expenses.db`, they will destroy real cached market data.
