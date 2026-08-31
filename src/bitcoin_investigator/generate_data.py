from __future__ import annotations

from pathlib import Path

from .pipeline import generate_synthetic_dataset


if __name__ == "__main__":
    dataset_path = generate_synthetic_dataset(Path(__file__).resolve().parents[2] / "data")
    print(f"Generated synthetic dataset: {dataset_path}")
