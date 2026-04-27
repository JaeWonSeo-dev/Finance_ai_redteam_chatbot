"""Markdown report generator for portfolio-ready experiment summaries.
This module turns logs and metrics into a reusable report text.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.redteam_tests import build_dashboard_metrics


def _safe_rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def generate_markdown_report(logs_df: pd.DataFrame) -> str:
    """Generate markdown summary text for portfolio submission."""
    metrics = build_dashboard_metrics(logs_df)

    total_cases = int(metrics["total_cases"])
    detected_attacks = int(metrics["detected_attacks"])
    blocked_requests = int(metrics["blocked_requests"])
    detection_rate = _safe_rate(detected_attacks, total_cases)
    block_rate = _safe_rate(blocked_requests, total_cases)

    by_attack_type = metrics["by_attack_type"]
    by_risk_level = metrics["by_risk_level"]
    failed_cases = metrics["failed_cases"]

    attack_table = by_attack_type.to_markdown(index=False) if not by_attack_type.empty else "No data"
    risk_table = by_risk_level.to_markdown(index=False) if not by_risk_level.empty else "No data"

    if failed_cases.empty:
        failed_text = "탐지 실패 사례가 없거나 아직 데이터가 충분하지 않습니다."
    else:
        failed_text = failed_cases[["timestamp", "category", "user_input", "risk_level", "blocked"]].head(10).to_markdown(index=False)

    markdown = f"""# 금융 생성형 AI 상담 서비스 보안 포트폴리오 보고서

## 1. 프로젝트 개요
본 프로젝트는 금융 상담 챗봇에 대해 프롬프트 인젝션 및 보안 위협 시나리오를 체계적으로 점검하고,
입력/출력 정책 기반 방어 체계를 설계하는 것을 목표로 하였습니다.

## 2. 금융권 생성형 AI 서비스의 보안 리스크
- Prompt Injection으로 인한 정책 우회
- 시스템 프롬프트 및 내부 정책 노출
- 개인정보(계좌정보, 연락처 등) 유출 위험
- 투자 수익 보장형 허위 조언 생성 위험
- 보이스피싱 유도형 악성 요청 대응 실패 가능성

## 3. 공격 시나리오 정의
- Prompt Injection
- System Prompt Leakage
- 개인정보 유출 유도
- 금융 내부정보 요청
- 투자 수익 보장 유도
- 보이스피싱성 요청
- 권한 우회 요청

## 4. 보안 필터 설계
- 입력 검증: 위험 키워드/패턴 탐지 및 위험도 분류(low/medium/high)
- 출력 검증: 계좌번호/주민등록번호/전화번호/이메일 패턴 마스킹
- 투자 조언 제한: 수익 보장/원금 보장 표현 제거 및 유의사항 추가
- 내부 정책 보호: 시스템 프롬프트/내부 규정 요청 시 거절 응답
- 로그 기록: 질문, 공격유형, 위험도, 차단 여부, 응답 저장

## 5. 실험 방법
- CSV 기반 공격 테스트 케이스를 자동 실행
- 각 케이스별 탐지 여부, 위험도, 차단 여부, 응답 결과 저장
- 누적 로그 기준으로 탐지율 및 차단율 집계

## 6. 실험 결과
- 전체 테스트 케이스 수: {total_cases}
- 탐지된 공격 수: {detected_attacks}
- 차단된 요청 수: {blocked_requests}
- 탐지율: {detection_rate:.1f}%
- 차단율: {block_rate:.1f}%

### 공격 유형별 결과
{attack_table}

### 위험도별 분포
{risk_table}

## 7. 탐지 실패 사례 분석
{failed_text}

## 8. 개선 방향
- 문맥 기반 탐지(임베딩/분류 모델) 추가로 우회 표현 탐지 강화
- 허용 정책(allow list)과 금지 정책(deny list)의 이중 정책 엔진 구성
- 실제 LLM API 연동 후 모델별 취약점 비교(A/B 테스트)
- 정적 룰 기반 + LLM self-check 기반 하이브리드 가드레일 적용

## 9. 지원 직무와의 연관성
본 프로젝트는 금융권/증권사 AI 서비스 기획, 정보보호, 리스크 관리 직무와 직접 연계됩니다.
특히 공격 시나리오 설계, 통제 정책 수립, 로그 기반 성능 검증 경험을 통해
생성형 AI 거버넌스 및 보안성 평가 역량을 증명할 수 있습니다.
"""
    return markdown


def save_markdown_report(markdown_text: str, output_path: Path) -> None:
    """Persist report markdown to docs folder."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown_text, encoding="utf-8")
