from __future__ import annotations

import csv
import json
import random
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd
from jinja2 import Template


def _normalize_address_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def _normalize_amount_list(value: Any) -> list[float]:
    if value is None:
        return []
    if isinstance(value, list):
        try:
            return [float(v) for v in value]
        except (TypeError, ValueError):
            return []
    if isinstance(value, str):
        try:
            return [float(value)]
        except ValueError:
            return []
    try:
        return [float(value)]
    except (TypeError, ValueError):
        return []


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def generate_synthetic_dataset(data_dir: Path | str) -> Path:
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)

    suspicious_ips = [
        ("10.10.20.11", 8333, "US"),
        ("10.10.20.12", 8333, "US"),
        ("10.10.20.13", 8333, "DE"),
        ("10.10.20.14", 8333, "NL"),
        ("10.10.20.15", 8333, "DE"),
    ]
    normal_ips = [
        ("192.168.1.10", 8333, "US"),
        ("192.168.1.11", 8333, "GB"),
        ("192.168.1.12", 8333, "FR"),
        ("192.168.1.13", 8333, "JP"),
        ("192.168.1.14", 8333, "AU"),
    ]

    suspicious_wallets = [
        "bc1q7p9gk5vhy9nrx0lk2m6n6d3u2q4v9x4m9s0wq3",
        "bc1q9m5nt3gzg9k7h9xv5u9p3zq3c2v8k7k0m9uhk",
        "bc1q5xv6t4d8p2k1j7n8u9n4w6r2z5m3v9y0f7a9q",
        "bc1q2m7u7h4p9j1l6n3x8z4r2v6h9t1q4k7c5m9s",
    ]
    normal_wallets = [
        "bc1qf9e9h0g5p2x4m8v2j5z4y8n1r3u7l6k9s2wq",
        "bc1qv1n5d7m3x8q6k0c2p4y9u7l5r3m8w1n6k9x3",
        "bc1qx2p6d9n1w7c5z3k9m8u2r4v7l1y6j0t5h9n3",
        "bc1q3t5n7w9x1c2p8v6m4r0k7h5y9n3l8q2u4m7w",
    ]

    records: list[dict[str, Any]] = []
    for i in range(120):
        suspicious = i < 70
        if suspicious:
            src_ip, src_port, src_country = suspicious_ips[i % len(suspicious_ips)]
            dst_ip, dst_port, dst_country = suspicious_ips[(i + 1) % len(suspicious_ips)]
            wallet_in = suspicious_wallets[i % len(suspicious_wallets)]
            wallet_out = suspicious_wallets[(i + 2) % len(suspicious_wallets)]
            amount = round(100 + rng.random() * 3500 + i * 7.5, 2)
            fee = round((rng.random() * 0.15) + 0.02, 4)
            txid = f"{i:08x}a{rng.randint(1000, 9999)}b{rng.randint(1000, 9999)}"
            output_addresses = [wallet_out, normal_wallets[(i + 3) % len(normal_wallets)]]
            output_amounts = [round(amount * 0.78, 2), round(amount * 0.22, 2)]
            input_addresses = [wallet_in]
            input_amounts = [amount + fee]
            script_type = "P2SH-P2WPKH"
        else:
            src_ip, src_port, src_country = normal_ips[i % len(normal_ips)]
            dst_ip, dst_port, dst_country = normal_ips[(i + 2) % len(normal_ips)]
            wallet_in = normal_wallets[i % len(normal_wallets)]
            wallet_out = normal_wallets[(i + 1) % len(normal_wallets)]
            amount = round(20 + rng.random() * 1200, 2)
            fee = round((rng.random() * 0.08) + 0.01, 4)
            txid = f"{i:05x}c{rng.randint(100, 999)}d{rng.randint(100, 999)}"
            if i % 7 == 0:
                output_addresses = [wallet_out, suspicious_wallets[(i + 1) % len(suspicious_wallets)]]
                output_amounts = [round(amount * 0.8, 2), round(amount * 0.2, 2)]
            else:
                output_addresses = [wallet_out]
                output_amounts = [amount]
            input_addresses = [wallet_in]
            input_amounts = [amount + fee]
            script_type = "P2PKH"

        records.append(
            {
                "timestamp": f"2026-08-01T{(i % 24):02d}:{(i * 7) % 60:02d}:00Z",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "txid": txid,
                "input_addresses": input_addresses,
                "output_addresses": output_addresses,
                "input_amounts": input_amounts,
                "output_amounts": output_amounts,
                "fee": fee,
                "script_type": script_type,
                "geo_country": src_country,
                "asn": f"AS{1000 + i % 50}",
            }
        )

    dataset_path = data_dir / "synthetic_bitcoin_metadata.json"
    dataset_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return dataset_path


def _read_json_dataset(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        return list(payload.get("records", payload.get("transactions", [])))
    return list(payload)


def _read_csv_dataset(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def _read_xml_dataset(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    root = tree.getroot()
    records: list[dict[str, Any]] = []
    for record in root.findall("record"):
        row: dict[str, Any] = {}
        for field in record:
            row[field.tag] = field.text
        records.append(row)
    return records


def load_dataset(dataset_dir: Path | str) -> pd.DataFrame:
    dataset_dir = Path(dataset_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(dataset_dir.iterdir())
    if not files:
        dataset_path = generate_synthetic_dataset(dataset_dir)
        files = [dataset_path]

    rows: list[dict[str, Any]] = []
    for file_path in files:
        if file_path.is_dir():
            continue
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            rows.extend(_read_json_dataset(file_path))
        elif suffix == ".csv":
            rows.extend(_read_csv_dataset(file_path))
        elif suffix == ".xml":
            rows.extend(_read_xml_dataset(file_path))

    if not rows:
        raise ValueError(f"No metadata records found in {dataset_dir}")

    frame = pd.DataFrame.from_records(rows)
    frame["timestamp"] = pd.to_datetime(frame.get("timestamp", pd.Series(["1970-01-01"] * len(frame))), errors="coerce")
    frame["fee"] = frame.get("fee", pd.Series([0.0] * len(frame))).apply(_safe_float)
    frame["src_port"] = frame.get("src_port", pd.Series([0] * len(frame))).apply(lambda value: int(value or 0))
    frame["dst_port"] = frame.get("dst_port", pd.Series([0] * len(frame))).apply(lambda value: int(value or 0))
    frame["geo_country"] = frame.get("geo_country", pd.Series(["Unknown"] * len(frame))).fillna("Unknown")
    frame["asn"] = frame.get("asn", pd.Series(["Unknown"] * len(frame))).fillna("Unknown")
    return frame


def build_graph(df: pd.DataFrame) -> nx.Graph:
    graph = nx.Graph()
    for _, row in df.iterrows():
        txid = str(row.get("txid", "unknown"))
        source_ip = str(row.get("src_ip", "unknown"))
        target_ip = str(row.get("dst_ip", "unknown"))

        graph.add_node(source_ip, kind="ip")
        graph.add_node(target_ip, kind="ip")
        graph.add_node(txid, kind="transaction")
        graph.add_edge(source_ip, txid, relation="observed_in")
        graph.add_edge(txid, target_ip, relation="observed_in")

        input_addrs = _normalize_address_list(row.get("input_addresses", []))
        output_addrs = _normalize_address_list(row.get("output_addresses", []))
        for addr in input_addrs:
            graph.add_node(addr, kind="wallet")
            graph.add_edge(addr, txid, relation="input")
        for addr in output_addrs:
            graph.add_node(addr, kind="wallet")
            graph.add_edge(addr, txid, relation="output")
        for addr in input_addrs + output_addrs:
            graph.add_edge(source_ip, addr, relation="related")
            graph.add_edge(target_ip, addr, relation="related")
    return graph


def _build_wallet_features(df: pd.DataFrame) -> pd.DataFrame:
    wallet_stats: dict[str, dict[str, Any]] = defaultdict(dict)
    wallet_tx_count: dict[str, int] = defaultdict(int)
    wallet_ips: dict[str, set[str]] = defaultdict(set)
    wallet_country_hits: dict[str, int] = defaultdict(int)
    wallet_total_outflow: dict[str, float] = defaultdict(float)
    wallet_total_inflow: dict[str, float] = defaultdict(float)

    for _, row in df.iterrows():
        input_addrs = _normalize_address_list(row.get("input_addresses", []))
        output_addrs = _normalize_address_list(row.get("output_addresses", []))
        src_ip = str(row.get("src_ip", "unknown"))
        dst_ip = str(row.get("dst_ip", "unknown"))
        country = str(row.get("geo_country", "Unknown"))

        for addr in input_addrs:
            wallet_tx_count[addr] += 1
            wallet_ips[addr].add(src_ip)
            wallet_ips[addr].add(dst_ip)
            total = sum(_normalize_amount_list(row.get("input_amounts", [])) or [0.0])
            wallet_total_inflow[addr] += total
            wallet_country_hits[addr] += 1 if country in {"US", "DE", "NL"} else 0

        for addr in output_addrs:
            wallet_tx_count[addr] += 1
            wallet_ips[addr].add(src_ip)
            wallet_ips[addr].add(dst_ip)
            outputs = _normalize_amount_list(row.get("output_amounts", []))
            if outputs:
                wallet_total_outflow[addr] += sum(outputs)
            wallet_country_hits[addr] += 1 if country in {"US", "DE", "NL"} else 0

    for wallet, tx_count in wallet_tx_count.items():
        inflow = wallet_total_inflow.get(wallet, 0.0)
        outflow = wallet_total_outflow.get(wallet, 0.0)
        wallet_stats[wallet] = {
            "wallet": wallet,
            "tx_count": tx_count,
            "inflow": inflow,
            "outflow": outflow,
            "net_flow": outflow - inflow,
            "unique_ips": len(wallet_ips.get(wallet, set())),
            "suspicious_country_ratio": wallet_country_hits.get(wallet, 0) / max(tx_count, 1),
            "avg_tx_value": (inflow + outflow) / max(tx_count, 1),
        }

    feature_table = pd.DataFrame.from_records(list(wallet_stats.values()))
    feature_table["tx_count"] = feature_table["tx_count"].fillna(0)
    feature_table["inflow"] = feature_table["inflow"].fillna(0)
    feature_table["outflow"] = feature_table["outflow"].fillna(0)
    feature_table["net_flow"] = feature_table["net_flow"].fillna(0)
    feature_table["unique_ips"] = feature_table["unique_ips"].fillna(0)
    feature_table["suspicious_country_ratio"] = feature_table["suspicious_country_ratio"].fillna(0)
    feature_table["avg_tx_value"] = feature_table["avg_tx_value"].fillna(0)
    feature_table["activity_score"] = feature_table["tx_count"] * (1 + feature_table["unique_ips"] / 10)
    return feature_table


def detect_alerts(df: pd.DataFrame, graph: nx.Graph) -> list[dict[str, Any]]:
    feature_table = _build_wallet_features(df)
    if feature_table.empty:
        return []

    feature_matrix = feature_table[
        [
            "tx_count",
            "inflow",
            "outflow",
            "net_flow",
            "unique_ips",
            "suspicious_country_ratio",
            "avg_tx_value",
            "activity_score",
        ]
    ].fillna(0).astype(float).to_numpy()

    means = feature_matrix.mean(axis=0)
    stds = feature_matrix.std(axis=0)
    stds = np.where(stds == 0, 1.0, stds)
    z_scores = (feature_matrix - means) / stds

    weighted_scores = (
        z_scores[:, 0] * 0.8
        + z_scores[:, 1] * 0.6
        + z_scores[:, 2] * 1.8
        + z_scores[:, 3] * 0.5
        + z_scores[:, 4] * 1.2
        + z_scores[:, 5] * 1.6
        + z_scores[:, 6] * 0.9
        + z_scores[:, 7] * 0.7
    )
    weighted_scores = np.nan_to_num(weighted_scores, nan=0.0, posinf=0.0, neginf=0.0)
    normalized = (weighted_scores - weighted_scores.min()) / (weighted_scores.max() - weighted_scores.min() + 1e-8)

    alerts: list[dict[str, Any]] = []
    for idx, row in feature_table.iterrows():
        wallet = row["wallet"]
        risk_base = float(normalized[idx])
        heuristic = 0.0
        if row["unique_ips"] >= 4:
            heuristic += 0.15
        if row["suspicious_country_ratio"] >= 0.5:
            heuristic += 0.2
        if row["tx_count"] >= 8:
            heuristic += 0.15
        if row["outflow"] >= 2000:
            heuristic += 0.2
        risk_score = min(1.0, 0.7 * risk_base + 0.3 * heuristic)
        if risk_score < 0.55:
            continue

        reasons: list[str] = []
        if row["unique_ips"] >= 4:
            reasons.append("High IP diversity suggests input-output mixing across multiple peers.")
        if row["suspicious_country_ratio"] >= 0.5:
            reasons.append("The wallet repeatedly appears in high-risk geographic routing clusters.")
        if row["tx_count"] >= 8:
            reasons.append("Transaction frequency is elevated relative to ordinary wallets in the synthetic sample.")
        if row["outflow"] >= 2000:
            reasons.append("Large outbound value movement is consistent with a cash-out or laundering pattern.")
        if not reasons:
            reasons.append("Model identified the wallet as behaviorally anomalous relative to the rest of the dataset.")

        alerts.append(
            {
                "entity_type": "wallet",
                "entity_id": wallet,
                "risk_score": round(float(risk_score), 3),
                "confidence": round(min(0.99, 0.55 + risk_score / 2), 3),
                "reasons": reasons,
                "evidence": {
                    "tx_count": int(row["tx_count"]),
                    "unique_ips": int(row["unique_ips"]),
                    "outflow": round(float(row["outflow"]), 2),
                    "inflow": round(float(row["inflow"]), 2),
                    "suspicious_country_ratio": round(float(row["suspicious_country_ratio"]), 3),
                    "neighbors": list(graph.neighbors(wallet))[:10] if graph.has_node(wallet) else [],
                },
            }
        )

    alerts.sort(key=lambda item: item["risk_score"], reverse=True)
    return alerts


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _render_dashboard(alerts: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    template = Template(
        """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Bitcoin Investigation Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; background: #111827; color: #e5e7eb; margin: 0; padding: 24px; }
                h1, h2 { color: #f9fafb; }
                .summary { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
                .card { background: #1f2937; padding: 14px 18px; border-radius: 8px; min-width: 150px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border-bottom: 1px solid #374151; padding: 10px; text-align: left; }
                th { background: #0f172a; }
                .badge { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #f59e0b; color: #111827; font-weight: bold; }
                .reason { color: #cbd5e1; }
            </style>
        </head>
        <body>
            <h1>Bitcoin Investigation Dashboard</h1>
            <div class="summary">
                <div class="card"><strong>Alert count</strong><br>{{ summary.alert_count }}</div>
                <div class="card"><strong>Top score</strong><br>{{ summary.top_risk_score }}</div>
                <div class="card"><strong>High priority</strong><br>{{ summary.high_priority_alerts | join(', ') }}</div>
            </div>
            <h2>Prioritized Leads</h2>
            <table>
                <thead>
                    <tr>
                        <th>Entity</th>
                        <th>Risk</th>
                        <th>Confidence</th>
                        <th>Evidence</th>
                        <th>Why It Was Flagged</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in alerts %}
                    <tr>
                        <td>{{ alert.entity_id }}</td>
                        <td><span class="badge">{{ alert.risk_score }}</span></td>
                        <td>{{ alert.confidence }}</td>
                        <td>Tx: {{ alert.evidence.tx_count }} | IPs: {{ alert.evidence.unique_ips }} | Out: ${{ alert.evidence.outflow }}</td>
                        <td class="reason">{% for reason in alert.reasons %}{{ reason }}<br>{% endfor %}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </body>
        </html>
        """
    )
    return template.render(alerts=alerts, summary=summary)


def build_pipeline(project_root: Path | str, data_dir: Path | str | None = None, output_dir: Path | str | None = None) -> dict[str, Any]:
    project_root = Path(project_root)
    data_dir = Path(data_dir) if data_dir is not None else project_root / "data"
    output_dir = Path(output_dir) if output_dir is not None else project_root / "outputs"

    data_dir.mkdir(parents=True, exist_ok=True)

    dataset_path = next((candidate for candidate in sorted(data_dir.iterdir()) if candidate.is_file()), None)
    if dataset_path is None:
        dataset_path = generate_synthetic_dataset(data_dir)

    df = load_dataset(data_dir)
    graph = build_graph(df)
    alerts = detect_alerts(df, graph)

    summary = {
        "dataset": str(dataset_path),
        "alert_count": len(alerts),
        "top_risk_score": round(max((alert["risk_score"] for alert in alerts), default=0.0), 3),
        "high_priority_alerts": [alert["entity_id"] for alert in alerts[:5]],
    }

    _write_json(output_dir / "alerts.json", alerts)
    _write_json(output_dir / "summary.json", summary)
    (output_dir / "dashboard.html").write_text(_render_dashboard(alerts, summary), encoding="utf-8")

    return {"dataset_path": str(dataset_path), "alerts": alerts, "summary": summary}


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[2]
    results = build_pipeline(project_root)
    print(f"Generated {len(results['alerts'])} alerts from {results['dataset_path']}")
    print(json.dumps(results["summary"], indent=2))
