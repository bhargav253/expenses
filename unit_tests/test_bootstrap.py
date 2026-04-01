#!/usr/bin/env python3

import os
from pathlib import Path


def configure_test_db(module_name: str) -> str:
    safe_name = module_name.replace(".py", "").replace("/", "_").replace("\\", "_")
    db_path = Path("/tmp") / f"{safe_name}.sqlite"
    uri = f"sqlite:///{db_path.as_posix()}"
    os.environ["DATABASE_URL"] = uri
    os.environ["SQLALCHEMY_DATABASE_URI"] = uri
    os.environ["FLASK_ENV"] = "development"
    os.environ["TESTING"] = "true"
    return uri
