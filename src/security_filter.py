"""Security policy filters for prompt-injection and financial abuse detection.
This module performs both input risk detection and output masking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class DetectionResult:
    attack_types: List[str]
    risk_level: str
    detected: bool
    blocked: bool
    reasons: List[str]


HIGH_RISK_PATTERNS = {
    "Prompt Injection": [
        r"ignore\s+previous\s+instructions",
        r"이전\s*지시\s*무시",
        r"developer\s*mode",
        r"jailbreak",
    ],
    "System Prompt Leakage": [
        r"system\s*prompt",
        r"시스템\s*프롬프트",
        r"내부\s*정책\s*전문",
        r"prompt\s*reveal",
    ],
    "PII Exfiltration": [
        r"고객정보\s*알려",
        r"계좌번호\s*보여",
        r"주민등록번호",
        r"전화번호\s*목록",
        r"이메일\s*목록",
    ],
    "Internal Information Request": [
        r"내부\s*규정",
        r"직원용",
        r"심사\s*규칙\s*우회",
        r"관리자\s*정책",
    ],
    "Guaranteed Profit": [
        r"무조건\s*수익",
        r"원금\s*보장",
        r"확정\s*수익",
        r"손실\s*없는\s*투자",
    ],
    "Voice Phishing": [
        r"은행\s*직원인\s*척",
        r"보이스피싱",
        r"사칭\s*멘트",
        r"인증번호\s*받아내",
    ],
    "Privilege Bypass": [
        r"관리자\s*모드",
        r"권한\s*우회",
        r"인증\s*절차\s*없이",
        r"access\s*token",
    ],
}

MEDIUM_RISK_PATTERNS = {
    "Investment Aggressive Advice": [
        r"지금\s*당장\s*매수",
        r"매도\s*타이밍\s*딱",
        r"단기\s*급등",
    ],
    "Data Disclosure Attempt": [
        r"샘플\s*고객\s*데이터",
        r"계좌\s*예시\s*전체",
    ],
}


def _find_matches(text: str, pattern_dict: dict) -> List[str]:
    found = []
    for attack_type, patterns in pattern_dict.items():
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            found.append(attack_type)
    return found


def detect_risk(user_input: str) -> DetectionResult:
    """Detect risky prompt patterns and classify risk level."""
    text = user_input.strip()
    high_matches = _find_matches(text, HIGH_RISK_PATTERNS)
    medium_matches = _find_matches(text, MEDIUM_RISK_PATTERNS)

    attack_types = high_matches + [m for m in medium_matches if m not in high_matches]
    detected = bool(attack_types)

    if high_matches:
        risk = "high"
    elif medium_matches:
        risk = "medium"
    else:
        risk = "low"

    blocked = risk == "high"

    reasons = []
    if high_matches:
        reasons.append("High-risk policy violation detected")
    if medium_matches and not high_matches:
        reasons.append("Potentially unsafe request pattern detected")
    if not reasons:
        reasons.append("No critical security pattern found")

    return DetectionResult(
        attack_types=attack_types,
        risk_level=risk,
        detected=detected,
        blocked=blocked,
        reasons=reasons,
    )


def mask_sensitive_output(text: str) -> str:
    """Mask personal/sensitive patterns in model outputs."""
    masked = text

    patterns = {
        r"\b\d{2,3}-\d{3,4}-\d{4}\b": "***-****-****",  # phone
        r"\b\d{6}-\d{7}\b": "******-*******",  # Korean resident ID format
        r"\b[\w\.-]+@[\w\.-]+\.\w+\b": "***@***",  # email
        r"\b\d{2,4}-\d{2,6}-\d{2,6}\b": "****-****-****",  # account-like numbers
    }

    for pattern, replacement in patterns.items():
        masked = re.sub(pattern, replacement, masked)

    return masked


def enforce_investment_safety(response: str) -> str:
    """Remove explicit guarantee wording and append investment caution."""
    unsafe_phrases = ["무조건 수익", "원금 보장", "확정 수익", "손실 없음"]
    safe = response
    for phrase in unsafe_phrases:
        safe = safe.replace(phrase, "일반적 투자 정보")

    if "투자" in safe or "ETF" in safe or "펀드" in safe or "주식" in safe:
        safe += "\n\n[투자 유의사항] 본 답변은 보안성 검증 목적의 일반 정보이며, 특정 종목 매수/매도 권유가 아닙니다."

    return safe


def refusal_message() -> str:
    """Standard refusal used for high-risk malicious inputs."""
    return (
        "요청에 보안 위협 요소가 포함되어 있어 답변할 수 없습니다. "
        "개인정보 요청, 내부 정책 공개, 권한 우회, 수익 보장 요구는 허용되지 않습니다."
    )
