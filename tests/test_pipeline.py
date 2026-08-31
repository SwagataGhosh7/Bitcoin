import json
from pathlib import Path

from bitcoin_investigator import build_pipeline


def test_pipeline_generates_alerts_and_outputs(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"
    output_dir = tmp_path / "outputs"

    results = build_pipeline(project_root, data_dir=data_dir, output_dir=output_dir)

    assert "alerts" in results
    assert len(results["alerts"]) > 0
    assert any(alert["risk_score"] >= 0.6 for alert in results["alerts"])
    assert output_dir.joinpath("alerts.json").exists()
    assert output_dir.joinpath("summary.json").exists()
    assert output_dir.joinpath("dashboard.html").exists()
