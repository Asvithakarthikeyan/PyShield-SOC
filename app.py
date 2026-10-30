
import sqlite3
from pathlib import Path
from io import StringIO

import streamlit as st
import pandas as pd
import plotly.express as px


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "logs" / "pyshield.db"

st.set_page_config(
    page_title="PyShield SOC",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PyShield SOC")
st.caption("Live Security Operations Center | Network Monitoring")


def load_events():

    if not DB_PATH.exists():
        return pd.DataFrame()

    connection = sqlite3.connect(DB_PATH)

    try:
        data = pd.read_sql_query(
            "SELECT * FROM security_events ORDER BY id DESC",
            connection
        )
    finally:
        connection.close()

    return data


severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)


@st.fragment(run_every=5)
def live_dashboard():

    events = load_events()

    st.caption("Dashboard updates automatically every 5 seconds.")

    if events.empty:
        total = critical = high = medium = low = 0
    else:
        total = len(events)
        critical = len(events[events["severity"] == "CRITICAL"])
        high = len(events[events["severity"] == "HIGH"])
        medium = len(events[events["severity"] == "MEDIUM"])
        low = len(events[events["severity"] == "LOW"])

    st.subheader("Security Overview")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Events", total)
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("Medium", medium)
    col5.metric("Low", low)

    st.divider()

    st.subheader("Live Network Packet Feed")

    if not events.empty:

        packets = events[
            events["signature"].str.contains(
                "network packet",
                case=False,
                na=False
            )
        ]

        st.metric("Captured Packets", len(packets))

        if not packets.empty:
            st.dataframe(
                packets.head(20),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Waiting for network packets...")

    st.divider()

    st.subheader("Threat Distribution")

    if not events.empty:

        chart_data = (
            events["severity"]
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Count")
        )

        fig = px.pie(
            chart_data,
            names="Severity",
            values="Count",
            hole=0.45
        )

        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    st.subheader("Security Event Monitoring")

    if not events.empty:

        filtered = events[
            events["severity"].isin(severity_filter)
        ]

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("Waiting for security events...")

    st.divider()

    st.subheader("Security Report")

    if not events.empty:

        report = StringIO()
        events.to_csv(report, index=False)

        st.download_button(
            "Download Security Report",
            data=report.getvalue(),
            file_name="pyshield_security_report.csv",
            mime="text/csv"
        )


live_dashboard()
