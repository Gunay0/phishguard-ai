import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
from phishguard.analyzer import analyze_message

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishGuard AI")
st.write("AI-Powered Phishing Detection System")
st.divider()

st.subheader("Choose Your Plan")
country = st.selectbox(
    "Select your country:",
    ["Azerbaijan", "Other countries"]
)
plan = st.radio(
    "Select a plan:",
    ["Free", "Pro"]
)

if plan == "Free":
    st.success("Free Plan - Basic phishing analysis")
else:
    if country == "Azerbaijan":
        st.info("Pro Plan - 9.90 AZN / 20 AI analyses")
    else:
        st.info("Pro Plan - 5.99 USD / 20 AI analyses")
    st.warning("Pro payments are not active yet.")

message = st.text_area(
    "Enter a suspicious message:",
    height=180,
    placeholder="Paste an email or SMS here..."
)

if st.button("Analyze Message", disabled=(plan == "Pro")):
    if not message.strip():
        st.warning("Please enter a message.")
    else:
        result = analyze_message(message)

        st.subheader("Analysis Results")
        st.write("**Risk Level:**", result.final_risk.value)
        st.write("**Language:**", result.language.value)
        st.write("**Detected Indicators:**", len(result.indicators))
        st.write("**Suspicious URL Findings:**", len(result.url_findings))

        for indicator in result.indicators:
            st.warning(f"{indicator.title}: {indicator.explanation}")

        for finding in result.url_findings:
            st.warning(f"{finding.rule_id}: {finding.explanation}")

        st.info("AI analysis is not enabled yet. Results are rule-based.")
