"""Utility helpers for file paths, CSV I/O, and safe defaults.
This file centralizes low-level operations used by the app modules.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Dict

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ATTACK_CASES_PATH = DATA_DIR / "attack_test_cases.csv"
LOGS_PATH = DATA_DIR / "logs.csv"
LOGS_SQLITE_PATH = DATA_DIR / "logs.db"

LOG_COLUMNS = [
    "timestamp",
    "category",
    "user_input",
    "attack_type",
    "risk_level",
    "detected",
    "blocked",
    "response",
]


def _ensure_sqlite_table() -> None:
    """Create SQLite logs table for log persistence if needed."""
    with sqlite3.connect(LOGS_SQLITE_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT,
                category TEXT,
                user_input TEXT,
                attack_type TEXT,
                risk_level TEXT,
                detected TEXT,
                blocked TEXT,
                response TEXT
            )
            """
        )
        conn.commit()


def ensure_data_files(storage_backend: str = "csv") -> None:
    """Create required data files with headers if they do not exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not ATTACK_CASES_PATH.exists():
        pd.DataFrame(
            columns=["attack_type", "category", "user_input", "expected_risk", "expected_block"]
        ).to_csv(ATTACK_CASES_PATH, index=False, encoding="utf-8-sig")

    backend = storage_backend.strip().lower()
    if backend == "sqlite":
        _ensure_sqlite_table()
    else:
        if not LOGS_PATH.exists():
            pd.DataFrame(columns=LOG_COLUMNS).to_csv(LOGS_PATH, index=False, encoding="utf-8-sig")


def load_attack_cases() -> pd.DataFrame:
    """Load red-team attack test cases from CSV."""
    ensure_data_files(storage_backend="csv")
    return pd.read_csv(ATTACK_CASES_PATH)


def load_logs(storage_backend: str = "csv") -> pd.DataFrame:
    """Load chatbot interaction and test logs from CSV or SQLite."""
    backend = storage_backend.strip().lower()
    ensure_data_files(storage_backend=backend)

    if backend == "sqlite":
        with sqlite3.connect(LOGS_SQLITE_PATH) as conn:
            return pd.read_sql_query("SELECT * FROM logs", conn)

    return pd.read_csv(LOGS_PATH)


def append_log(log_row: Dict[str, object], storage_backend: str = "csv") -> None:
    """Append one log row to CSV or SQLite with schema-safe defaults."""
    backend = storage_backend.strip().lower()
    ensure_data_files(storage_backend=backend)
    row_with_defaults = {column: log_row.get(column, "") for column in LOG_COLUMNS}
    row_with_defaults["timestamp"] = row_with_defaults.get("timestamp") or datetime.now().isoformat(timespec="seconds")

    if backend == "sqlite":
        with sqlite3.connect(LOGS_SQLITE_PATH) as conn:
            conn.execute(
                """
                INSERT INTO logs (timestamp, category, user_input, attack_type, risk_level, detected, blocked, response)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(row_with_defaults["timestamp"]),
                    str(row_with_defaults["category"]),
                    str(row_with_defaults["user_input"]),
                    str(row_with_defaults["attack_type"]),
                    str(row_with_defaults["risk_level"]),
                    str(row_with_defaults["detected"]),
                    str(row_with_defaults["blocked"]),
                    str(row_with_defaults["response"]),
                ),
            )
            conn.commit()
        return

    df = pd.DataFrame([row_with_defaults], columns=LOG_COLUMNS)
    df.to_csv(LOGS_PATH, mode="a", header=False, index=False, encoding="utf-8-sig")


def to_bool(value: object) -> bool:
    """Normalize common CSV/JSON truthy values to bool."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in {"true", "1", "yes", "y"}
