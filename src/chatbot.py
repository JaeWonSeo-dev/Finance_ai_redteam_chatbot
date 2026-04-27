"""Finance chatbot engine with mock/API modes and policy-aware responses.
This module coordinates security filtering, response generation, and post-processing.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from typing import Dict

from src.security_filter import (
    detect_risk,
    enforce_investment_safety,
    mask_sensitive_output,
    refusal_message,
)


CATEGORY_GUIDANCE = {
    "deposit": "예금은 금리, 우대조건, 만기, 중도해지 패널티를 함께 비교해야 합니다.",
    "loan": "대출은 금리 유형(고정/변동), DSR, 상환 방식, 중도상환수수료를 확인하세요.",
    "investment": "투자상품은 위험등급, 수수료, 분산투자 여부, 투자기간을 먼저 점검하세요.",
    "account": "계좌 관련 문의는 본인 인증과 이상거래 탐지 절차를 우선 확인해야 합니다.",
    "security": "보안 안내는 피싱/스미싱 예방, OTP 보호, 비밀번호 관리가 핵심입니다.",
}


class FinanceChatbot:
    """Simple financial assistant prototype for security red-team evaluation."""

    def __init__(self, llm_mode: str = "mock") -> None:
        self.llm_mode = llm_mode

    def ask(self, user_input: str, category: str) -> Dict[str, object]:
        """Process one question through risk filter, response generation, and output policy."""
        detection = detect_risk(user_input)

        if detection.blocked:
            response = refusal_message()
            return {
                "response": response,
                "attack_type": ", ".join(detection.attack_types) if detection.attack_types else "None",
                "risk_level": detection.risk_level,
                "detected": detection.detected,
                "blocked": detection.blocked,
                "reasons": detection.reasons,
                "detection": asdict(detection),
            }

        raw_response = self._generate_response(user_input=user_input, category=category)
        safe_response = enforce_investment_safety(mask_sensitive_output(raw_response))

        return {
            "response": safe_response,
            "attack_type": ", ".join(detection.attack_types) if detection.attack_types else "None",
            "risk_level": detection.risk_level,
            "detected": detection.detected,
            "blocked": detection.blocked,
            "reasons": detection.reasons,
            "detection": asdict(detection),
        }

    def _generate_response(self, user_input: str, category: str) -> str:
        """Generate response by selected backend mode."""
        if self.llm_mode == "api":
            return self._api_response(user_input, category)
        return self._mock_response(user_input, category)

    def _mock_response(self, user_input: str, category: str) -> str:
        """Rule-based mock LLM response for local testing without API keys."""
        guidance = CATEGORY_GUIDANCE.get(category, "금융 상담은 상품 특성과 위험요인을 함께 확인하는 것이 중요합니다.")
        return (
            f"[Mock LLM 응답]\n"
            f"질문 요약: {user_input}\n"
            f"상담 카테고리: {category}\n"
            f"안내: {guidance}\n"
            "추가 확인: 본인 상황(목표 기간, 위험 성향, 수수료)을 알려주시면 더 구체적으로 설명할 수 있습니다."
        )

    def _api_response(self, user_input: str, category: str) -> str:
        """Placeholder API mode. Kept simple for portfolio/demo usage."""
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return (
                "[API 모드 안내] OPENAI_API_KEY가 설정되지 않아 Mock 응답으로 대체합니다.\n"
                + self._mock_response(user_input, category)
            )

        # In a real deployment, call the LLM provider here.
        # For a portfolio-safe sample, we keep deterministic fallback behavior.
        return (
            "[API 모드 샘플 응답]\n"
            "실제 배포 시 이 영역에 LLM API 호출을 연결하세요.\n"
            + self._mock_response(user_input, category)
        )
