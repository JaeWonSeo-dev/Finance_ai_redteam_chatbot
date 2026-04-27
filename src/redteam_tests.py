"""Red-team test runner for attack scenarios and result logging.
This module executes CSV test cases against the chatbot and stores outputs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

import pandas as pd

from src.chatbot import FinanceChatbot
from src.utils import append_log, load_attack_cases, save_redteam_results, to_bool


def run_redteam_tests(chatbot: FinanceChatbot, storage_backend: str = "csv") -> pd.DataFrame:
    """Run all attack test cases and return result dataframe."""
    cases = load_attack_cases()
    run_id = datetime.now().strftime("%Y%m%d%H%M%S")
    results: List[Dict[str, object]] = []

    for _, row in cases.iterrows():
        category = str(row.get("category", "security")).strip().lower()
        user_input = str(row.get("user_input", "")).strip()
        attack_type_expected = str(row.get("attack_type", "Unknown"))
        expected_risk = str(row.get("expected_risk", "low")).strip().lower()
        expected_block = to_bool(row.get("expected_block", False))

        output = chatbot.ask(user_input=user_input, category=category)

        result = {
            "run_id": run_id,
            "attack_type_expected": attack_type_expected,
            "category": category,
            "user_input": user_input,
            "expected_risk": expected_risk,
            "expected_block": expected_block,
            "detected_attack_type": output.get("attack_type", "None"),
            "risk_level": output.get("risk_level", "low"),
            "detected": bool(output.get("detected", False)),
            "blocked": bool(output.get("blocked", False)),
            "response": output.get("response", ""),
        }

        result["risk_match"] = result["risk_level"] == result["expected_risk"]
        result["block_match"] = result["blocked"] == result["expected_block"]
        result["test_passed"] = bool(result["risk_match"] and result["block_match"])

        append_log(
            {
                "category": category,
                "user_input": user_input,
                "attack_type": result["detected_attack_type"],
                "risk_level": result["risk_level"],
                "detected": result["detected"],
                "blocked": result["blocked"],
                "response": result["response"],
            },
            storage_backend=storage_backend,
        )

        results.append(result)

    results_df = pd.DataFrame(results)
    save_redteam_results(results_df)
    return results_df


def build_dashboard_metrics(logs_df: pd.DataFrame) -> Dict[str, object]:
    """Build aggregate metrics for the admin dashboard."""
    if logs_df.empty:
        return {
            "total_cases": 0,
            "detected_attacks": 0,
            "blocked_requests": 0,
            "by_attack_type": pd.DataFrame(columns=["attack_type", "count"]),
            "by_risk_level": pd.DataFrame(columns=["risk_level", "count"]),
            "failed_cases": pd.DataFrame(),
        }

    total_cases = len(logs_df)
    detected_attacks = int(logs_df["detected"].astype(str).str.lower().isin(["true", "1"]).sum())
    blocked_requests = int(logs_df["blocked"].astype(str).str.lower().isin(["true", "1"]).sum())

    by_attack_type = (
        logs_df.assign(attack_type=logs_df["attack_type"].fillna("None").replace("", "None"))
        .groupby("attack_type", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
    )

    by_risk_level = (
        logs_df.assign(risk_level=logs_df["risk_level"].fillna("unknown").replace("", "unknown"))
        .groupby("risk_level", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
    )

    failed_cases = logs_df[
        (logs_df["risk_level"].fillna("low") == "high") &
        (~logs_df["blocked"].astype(str).str.lower().isin(["true", "1"]))
    ]

    return {
        "total_cases": total_cases,
        "detected_attacks": detected_attacks,
        "blocked_requests": blocked_requests,
        "by_attack_type": by_attack_type,
        "by_risk_level": by_risk_level,
        "failed_cases": failed_cases,
    }
