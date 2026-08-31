from __future__ import annotations

import io
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st

from bitcoin_investigator.pipeline import build_pipeline

matplotlib.use("Agg")


st.set_page_config(page_title="Bitcoin Investigation Dashboard", layout="wide")

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "outputs"


@st.cache_data
def load_alerts() -> list[dict]:
    alerts_path = OUTPUT_DIR / "alerts.json"
    if alerts_path.exists():
        with alerts_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    results = build_pipeline(PROJECT_ROOT, data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
    return results["alerts"]


@st.cache_data
def load_summary() -> dict:
    summary_path = OUTPUT_DIR / "summary.json"
    if summary_path.exists():
        with summary_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    results = build_pipeline(PROJECT_ROOT, data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
    return results["summary"]


@st.cache_data
def load_dataset() -> list[dict]:
    dataset_path = DATA_DIR / "synthetic_bitcoin_metadata.json"
    if not dataset_path.exists():
        build_pipeline(PROJECT_ROOT, data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
    with dataset_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_wallet_context(records: list[dict]) -> dict[str, dict]:
    wallet_meta: dict[str, dict] = defaultdict(dict)
    wallet_to_ips: dict[str, set[str]] = defaultdict(set)
    wallet_to_countries: dict[str, set[str]] = defaultdict(set)
    wallet_to_txids: dict[str, set[str]] = defaultdict(set)
    wallet_to_flow: dict[str, dict[str, float]] = defaultdict(lambda: {"inflow": 0.0, "outflow": 0.0})

    for record in records:
        txid = str(record.get("txid", "unknown"))
        src_ip = str(record.get("src_ip", "unknown"))
        dst_ip = str(record.get("dst_ip", "unknown"))
        country = str(record.get("geo_country", "Unknown"))

        for wallet in record.get("input_addresses", []):
            wallet_to_ips[wallet].update({src_ip, dst_ip})
            wallet_to_countries[wallet].add(country)
            wallet_to_txids[wallet].add(txid)
            wallet_to_flow[wallet]["inflow"] += float(sum(record.get("input_amounts", [0.0]) or [0.0]))

        for wallet in record.get("output_addresses", []):
            wallet_to_ips[wallet].update({src_ip, dst_ip})
            wallet_to_countries[wallet].add(country)
            wallet_to_txids[wallet].add(txid)
            wallet_to_flow[wallet]["outflow"] += float(sum(record.get("output_amounts", [0.0]) or [0.0]))

    for wallet, ips in wallet_to_ips.items():
        wallet_meta[wallet] = {
            "ips": sorted(ips),
            "countries": sorted(wallet_to_countries.get(wallet, set())),
            "txids": sorted(wallet_to_txids.get(wallet, set())),
            "inflow": round(wallet_to_flow[wallet].get("inflow", 0.0), 2),
            "outflow": round(wallet_to_flow[wallet].get("outflow", 0.0), 2),
        }
    return wallet_meta


def render_graph_for_wallets(wallets: list[str], records: list[dict]) -> bytes:
    graph = nx.Graph()
    selected = set(wallets)

    for record in records:
        txid = str(record.get("txid", "unknown"))
        src_ip = str(record.get("src_ip", "unknown"))
        dst_ip = str(record.get("dst_ip", "unknown"))
        addresses = list(record.get("input_addresses", [])) + list(record.get("output_addresses", []))
        if not selected.intersection(addresses):
            continue

        graph.add_node(txid, kind="transaction")
        graph.add_node(src_ip, kind="ip")
        graph.add_node(dst_ip, kind="ip")
        graph.add_edge(src_ip, txid)
        graph.add_edge(txid, dst_ip)

        for wallet in addresses:
            graph.add_node(wallet, kind="wallet")
            graph.add_edge(wallet, txid)

    if graph.number_of_nodes() == 0:
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.text(0.5, 0.5, "No linked graph for the selected lead set", ha="center", va="center")
        ax.axis("off")
        buffer = io.BytesIO()
        fig.savefig(buffer, format="png", bbox_inches="tight")
        buffer.seek(0)
        plt.close(fig)
        return buffer.getvalue()

    pos = nx.spring_layout(graph, seed=42)
    fig, ax = plt.subplots(figsize=(10, 7))
    nx.draw_networkx(
        graph,
        pos,
        with_labels=True,
        node_size=600,
        font_size=8,
        node_color=["#f59e0b" if graph.nodes[n].get("kind") == "wallet" else "#60a5fa" if graph.nodes[n].get("kind") == "ip" else "#34d399" for n in graph.nodes()],
        edge_color="#d1d5db",
        alpha=0.9,
        ax=ax,
    )
    ax.set_axis_off()
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", bbox_inches="tight")
    buffer.seek(0)
    plt.close(fig)
    return buffer.getvalue()


st.title("Bitcoin Investigation Dashboard")
st.caption("Offline anomaly detection for Bitcoin transaction and network metadata")

with st.sidebar:
    st.header("Controls")
    if st.button("Run pipeline"):
        build_pipeline(PROJECT_ROOT, data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
    st.caption("Generates or refreshes the synthetic dataset and investigative alerts.")

    st.divider()
    st.caption("Project outputs are written to the local data and outputs folders.")

alerts = load_alerts()
summary = load_summary()
records = load_dataset()
wallet_meta = build_wallet_context(records)

if not alerts:
    st.warning("No alerts found. Run the pipeline to generate a dataset and alerts.")
    st.stop()

lead_rows = []
for alert in alerts:
    wallet = alert["entity_id"]
    context = wallet_meta.get(wallet, {})
    lead_rows.append(
        {
            "entity_id": wallet,
            "risk_score": alert["risk_score"],
            "confidence": alert["confidence"],
            "countries": ", ".join(context.get("countries", [])) or "Unknown",
            "ips": ", ".join(context.get("ips", [])) or "Unknown",
            "tx_count": len(context.get("txids", [])),
            "outflow": context.get("outflow", 0.0),
            "inflow": context.get("inflow", 0.0),
            "reasons": " | ".join(alert["reasons"]),
        }
    )
lead_df = pd.DataFrame(lead_rows)

col1, col2, col3 = st.columns(3)
col1.metric("Alert count", len(lead_df))
col2.metric("Top risk score", round(float(lead_df["risk_score"].max()), 3))
col3.metric("High priority", ", ".join(summary.get("high_priority_alerts", [])[:3]))

st.subheader("Lead filters")
filter_col1, filter_col2, filter_col3 = st.columns(3)
with filter_col1:
    risk_min = st.slider("Minimum risk", 0.0, 1.0, 0.0, 0.01)
with filter_col2:
    countries = sorted({item for row in lead_df["countries"].tolist() for item in (row.split(", ") if row and row != "Unknown" else [])})
    selected_countries = st.multiselect("Country", countries, default=[])
with filter_col3:
    ips = sorted({ip for row in lead_df["ips"].tolist() for ip in (row.split(", ") if row and row != "Unknown" else [])})
    selected_ips = st.multiselect("IP", ips, default=[])

filtered = lead_df.copy()
if risk_min > 0:
    filtered = filtered[filtered["risk_score"] >= risk_min]
if selected_countries:
    filtered = filtered[filtered["countries"].apply(lambda value: any(country in value for country in selected_countries))]
if selected_ips:
    filtered = filtered[filtered["ips"].apply(lambda value: any(ip in value for ip in selected_ips))]

st.subheader("Prioritized investigative leads")
if filtered.empty:
    st.warning("No alerts match the selected filters.")
    st.stop()

st.dataframe(filtered, use_container_width=True)

csv_data = filtered.to_csv(index=False).encode("utf-8")
st.download_button(
    "Download filtered CSV",
    data=csv_data,
    file_name="bitcoin_alerts.csv",
    mime="text/csv",
)

selected_wallet = st.selectbox("Select lead for drill-down", filtered["entity_id"].tolist(), index=0)
selected_alert = next((alert for alert in alerts if alert["entity_id"] == selected_wallet), alerts[0])
selected_context = wallet_meta.get(selected_wallet, {})

st.subheader("Lead drill-down")
lead_col1, lead_col2 = st.columns([1.25, 1.75])
with lead_col1:
    st.markdown("### Wallet summary")
    st.metric("Risk score", round(float(selected_alert["risk_score"]), 3))
    st.metric("Confidence", round(float(selected_alert["confidence"]), 3))
    st.metric("Observed transactions", len(selected_context.get("txids", [])))
    st.metric("Countries", ", ".join(selected_context.get("countries", [])) or "Unknown")
    st.metric("IPs", ", ".join(selected_context.get("ips", [])) or "Unknown")
with lead_col2:
    st.markdown("### Why this wallet was flagged")
    for reason in selected_alert["reasons"]:
        st.markdown(f"- {reason}")
    st.markdown("### Evidence")
    st.json({
        "tx_count": len(selected_context.get("txids", [])),
        "countries": selected_context.get("countries", []),
        "ips": selected_context.get("ips", []),
        "inflow": selected_context.get("inflow", 0.0),
        "outflow": selected_context.get("outflow", 0.0),
        "neighbors": selected_alert.get("evidence", {}).get("neighbors", []),
    })

st.subheader("Graph / network view")
selected_wallets = filtered["entity_id"].tolist()[:10]
graph_bytes = render_graph_for_wallets(selected_wallets, records)
st.image(graph_bytes, use_container_width=True, channels="RGB")

st.subheader("Alert feed")
for alert in filtered.to_dict("records"):
    wallet = alert["entity_id"]
    with st.expander(f"{wallet} — risk {alert['risk_score']}"):
        st.write(alert["reasons"])
        st.write(f"Countries: {alert['countries']}")
        st.write(f"IPs: {alert['ips']}")
