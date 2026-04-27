"""Streamlit app entry point for finance chatbot security portfolio.
This file wires UI pages to chatbot engine, red-team tests, dashboard, and report generation.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from src.chatbot import FinanceChatbot
from src.redteam_tests import build_dashboard_metrics, run_redteam_tests
from src.report_generator import generate_markdown_report, save_markdown_report
from src.utils import append_log, ensure_data_files, load_attack_cases, load_logs


BASE_DIR = Path(__file__).resolve().parent
PORTFOLIO_REPORT_PATH = BASE_DIR / "docs" / "portfolio_report.md"


def _sidebar_controls() -> tuple[FinanceChatbot, str]:
    """Render sidebar controls and return chatbot instance and storage backend."""
    st.sidebar.header("설정")
    llm_mode = st.sidebar.radio(
        "LLM 모드",
        options=["mock", "api"],
        index=0,
        help="API Key가 없어도 mock 모드로 전체 기능을 테스트할 수 있습니다.",
    )

    storage_backend = st.sidebar.radio(
        "로그 저장소",
        options=["csv", "sqlite"],
        index=0,
        help="CSV 또는 SQLite 중 하나를 선택해 로그를 저장합니다.",
    )
    st.sidebar.caption("주의: 본 앱은 보안성 검증용 데모이며 실제 고객정보를 다루지 않습니다.")
    return FinanceChatbot(llm_mode=llm_mode), storage_backend


def _chatbot_page(chatbot: FinanceChatbot, storage_backend: str) -> None:
    """Render chatbot interaction page."""
    st.subheader("1) 금융 상담 챗봇 화면")

    category = st.selectbox(
        "상담 카테고리",
        options=["deposit", "loan", "investment", "account", "security"],
        index=0,
        help="예금, 대출, 투자상품, 계좌, 보안 안내 카테고리를 선택하세요.",
    )

    user_input = st.text_area(
        "질문 입력",
        placeholder="예: 예금 금리 비교 기준을 알려주세요",
        height=120,
    )

    if st.button("상담 요청", type="primary"):
        if not user_input.strip():
            st.warning("질문을 입력해 주세요.")
            return

        result = chatbot.ask(user_input=user_input, category=category)

        append_log(
            {
                "category": category,
                "user_input": user_input,
                "attack_type": result["attack_type"],
                "risk_level": result["risk_level"],
                "detected": result["detected"],
                "blocked": result["blocked"],
                "response": result["response"],
            },
            storage_backend=storage_backend,
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("위험도", str(result["risk_level"]).upper())
        col2.metric("탐지 여부", "Yes" if result["detected"] else "No")
        col3.metric("차단 여부", "Yes" if result["blocked"] else "No")

        st.markdown("### 챗봇 응답")
        st.write(result["response"])

        with st.expander("보안 필터 상세"):
            st.json(result["detection"])


def _redteam_page(chatbot: FinanceChatbot, storage_backend: str) -> None:
    """Render red-team test execution page."""
    st.subheader("2) 공격 시나리오 테스트")

    attack_cases = load_attack_cases()
    st.caption("attack_test_cases.csv 기준으로 테스트가 수행됩니다.")
    st.dataframe(attack_cases, use_container_width=True, hide_index=True)

    if st.button("전체 테스트 실행"):
        results = run_redteam_tests(chatbot, storage_backend=storage_backend)
        st.success(f"테스트 완료: {len(results)}건")
        st.dataframe(results, use_container_width=True, hide_index=True)


    def _dashboard_page(storage_backend: str) -> None:
    """Render admin dashboard with aggregated security metrics."""
    st.subheader("3) 관리자 대시보드")

    logs_df = load_logs(storage_backend=storage_backend)
    metrics = build_dashboard_metrics(logs_df)

    c1, c2, c3 = st.columns(3)
    c1.metric("전체 테스트/대화 수", metrics["total_cases"])
    c2.metric("탐지된 공격 수", metrics["detected_attacks"])
    c3.metric("차단된 요청 수", metrics["blocked_requests"])

    st.markdown("### 공격 유형별 탐지 결과")
    st.dataframe(metrics["by_attack_type"], use_container_width=True, hide_index=True)

    st.markdown("### 위험도별 분포")
    risk_df = metrics["by_risk_level"]
    st.dataframe(risk_df, use_container_width=True, hide_index=True)

    if not risk_df.empty:
        fig, ax = plt.subplots(figsize=(6, 3.5))
        ax.bar(risk_df["risk_level"], risk_df["count"])
        ax.set_xlabel("Risk Level")
        ax.set_ylabel("Count")
        ax.set_title("Risk Distribution")
        st.pyplot(fig)

    st.markdown("### 실패 케이스 목록 (high인데 차단되지 않은 요청)")
    failed_df = metrics["failed_cases"]
    if failed_df.empty:
        st.info("현재 실패 케이스가 없습니다.")
    else:
        st.dataframe(failed_df, use_container_width=True, hide_index=True)


def _report_page(storage_backend: str) -> None:
    """Render report generation page and save markdown file."""
    st.subheader("4) 보고서 자동 생성")

    logs_df = load_logs(storage_backend=storage_backend)
    markdown_text = generate_markdown_report(logs_df)
    st.markdown(markdown_text)

    if st.button("docs/portfolio_report.md로 저장"):
        save_markdown_report(markdown_text, PORTFOLIO_REPORT_PATH)
        st.success(f"저장 완료: {PORTFOLIO_REPORT_PATH}")


def main() -> None:
    """Main entrypoint for Streamlit app."""
    ensure_data_files(storage_backend="csv")

    st.set_page_config(
        page_title="Finance AI RedTeam Chatbot",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("금융 생성형 AI 상담 서비스 보안성 검증 포트폴리오")
    st.caption(
        "프롬프트 인젝션 취약점 분석 및 방어 정책 설계 데모 | 개인정보는 더미/패턴 기반으로만 처리"
    )

    chatbot, storage_backend = _sidebar_controls()
    ensure_data_files(storage_backend=storage_backend)

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "챗봇",
            "레드팀 테스트",
            "관리자 대시보드",
            "보고서 생성",
        ]
    )

    with tab1:
        _chatbot_page(chatbot, storage_backend=storage_backend)
    with tab2:
        _redteam_page(chatbot, storage_backend=storage_backend)
    with tab3:
        _dashboard_page(storage_backend=storage_backend)
    with tab4:
        _report_page(storage_backend=storage_backend)


if __name__ == "__main__":
    main()
