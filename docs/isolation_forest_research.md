# Isolation Forest Anomaly Detection

## Research novelty

SentinelShield combines supervised classification with unsupervised anomaly detection. Random Forest and K-Nearest Neighbors learn from labelled examples of legitimate and malicious Wi-Fi networks. They are effective for attack patterns represented in the training set, but both depend on similarity to known examples. An Evil Twin, rogue access point, or signal behaviour that has not appeared in that data can therefore be difficult to classify reliably.

Isolation Forest addresses that gap. It repeatedly partitions the feature space using random split points. Observations requiring fewer partitions to isolate are rare relative to the learned normal Wi-Fi baseline and receive an anomaly prediction. The approach is unsupervised: training uses normal historical network behaviour rather than requiring labels for every future attack.

The detector uses whichever of the following project features are available: RSSI, signal variance, channel, encryption type, AP density, MAC similarity, BSSID reputation, threat score, SSID length, hidden-SSID flag, and temporal signal fluctuation. Missing values are median-filled for numeric features; encryption is safely encoded using the persisted training category map. This permits the same model bundle to be applied to real-time scan records even when optional telemetry is unavailable.

During scanning, SentinelShield combines Random Forest, KNN, Isolation Forest, and explainable rule-based evidence. Default weights are RF 0.35, KNN 0.25, Isolation Forest 0.25, and rule score 0.15; deployments may change them in `config/detection_weights.json`. Anomaly results include a normalized anomaly score, a `NORMAL`/`ANOMALY` decision, and confidence. Every anomaly is logged and persisted to SQLite for trend analysis.

This hybrid design has a cybersecurity benefit beyond a single classifier: supervised models identify known Evil Twin signatures, while Isolation Forest identifies zero-day configurations and unusual radio behaviour. It gives analysts a defensible research contribution for rogue access-point detection: known-pattern classification and baseline-deviation detection operate independently, then contribute transparently to a single risk score.

## Operating the detector

Train or refresh the detector from the project root:

```powershell
python train_isolation_forest.py wifi_dataset.csv
```

This writes the model and feature-preprocessing metadata to `models/isolation_forest.pkl`. The background scanner loads it lazily once per process, so model loading does not block every Wi-Fi scan. The Dashboard's **AI Detection**, **Home**, and **Anomaly Analysis** pages display its state and persisted results.
