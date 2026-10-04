# Bitcoin Investigation Prototype

This project is an offline Bitcoin analytics prototype designed to ingest synthetic transaction/network metadata, correlate wallet and IP activity, and surface prioritized investigative leads from an unsupervised anomaly model.

## Features

- Synthetic JSON metadata generation that resembles Bitcoin peer-to-peer and transaction fields.
- Data ingestion for JSON, CSV, and XML sources.
- Graph construction linking source/destination IPs, transactions, and wallet addresses.
- Wallet-level anomaly scoring using a deterministic, unsupervised statistical model built from wallet activity features.
- Explainable alert generation with ranked risk and supporting evidence.
- HTML dashboard summarizing the highest-risk wallets and reasons for flagging.

## Run

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m bitcoin_investigator.pipeline
```

## Streamlit frontend

```bash
$Env:PYTHONPATH = "$PWD\src"
streamlit run ".\streamlit_app.py"
```

The frontend lets you launch the pipeline, inspect ranked alerts, and review the supporting evidence for each flagged wallet.

## Outputs

- data/synthetic_bitcoin_metadata.json
- outputs/alerts.json
- outputs/summary.json
- outputs/dashboard.html
