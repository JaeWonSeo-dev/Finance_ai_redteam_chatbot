"""Utility helpers for file paths, CSV I/O, and safe defaults.
This file centralizes low-level operations used by the app modules.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ATTACK_CASES_PATH = DATA_DIR / "attack_test_cases.csv"
LOGS_PATH = DATA_DIR / "logs.csv"

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


def ensure_data_files() -> None:
    """Create required data files with headers if they do not exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not ATTACK_CASES_PATH.exists():
        pd.DataFrame(
            columns=["attack_type", "category", "user_input", "expected_risk", "expected_block"]
        ).to_csv(ATTACK_CASES_PATH, index=False, encoding="utf-8-sig")

    if not LOGS_PATH.exists():
        pd.DataFrame(columns=LOG_COLUMNS).to_csv(LOGS_PATH, index=False, encoding="utf-8-sig")


def load_attack_cases() -> pd.DataFrame:
    """Load red-team attack test cases from CSV."""
    ensure_data_files()
    return pd.read_csv(ATTACK_CASES_PATH)


def load_logs() -> pd.DataFrame:
    """Load chatbot interaction and test logs from CSV."""
    ensure_data_files()
    return pd.read_csv(LOGS_PATH)


def append_log(log_row: Dict[str, object]) -> None:
    """Append one log row to logs.csv with schema-safe defaults."""
    ensure_data_files()
    row_with_defaults = {column: log_row.get(column, "") for column in LOG_COLUMNS}
    row_with_defaults["timestamp"] = row_with_defaults.get("timestamp") or datetime.now().isoformat(timespec="seconds")

    df = pd.DataFrame([row_with_defaults], columns=LOG_COLUMNS)
    df.to_csv(LOGS_PATH, mode="a", header=False, index=False, encoding="utf-8-sig")


def to_bool(value: object) -> bool:
    """Normalize common CSV/JSON truthy values to bool."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in {"true", "1", "yes", "y"}
