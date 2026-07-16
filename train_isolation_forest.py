"""Train SentinelShield's unsupervised Wi-Fi anomaly detector.

Usage: python train_isolation_forest.py [historical_csv]
"""
import sys
import pandas as pd

from ai_models.isolation_forest_detector import IsolationForestDetector

dataset = sys.argv[1] if len(sys.argv) > 1 else "wifi_dataset.csv"
data = pd.read_csv(dataset, on_bad_lines="skip")
detector = IsolationForestDetector().train(data)
path = detector.save()
print(f"Trained Isolation Forest on {len(data)} historical rows using {detector.feature_names}.")
print(f"Saved model to {path}")
