"""Persisted, schema-tolerant Isolation Forest detector for Wi-Fi networks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Mapping

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

LOGGER = logging.getLogger(__name__)
DEFAULT_MODEL_PATH = Path("models/isolation_forest.pkl")


class IsolationForestDetector:
    """Detect Wi-Fi behaviour that differs from the learned normal baseline.

    The saved bundle contains the model and preprocessing metadata, so the
    model can safely be reloaded once and used by the real-time scan worker.
    """

    FEATURE_ALIASES = {
        "rssi": ("RSSI", "Signal", "Signal_Strength", "signal_strength"),
        "signal_variance": ("Signal_Var", "Signal_Variance", "signal_variance"),
        "channel": ("Channel", "channel"),
        "encryption_type": ("Security", "Encryption", "security", "encryption"),
        "ap_density": ("AP_Count", "AP_Density", "ap_count", "ap_density"),
        "mac_similarity": ("MAC_Similarity", "mac_similarity"),
        "bssid_reputation_score": ("BSSID_Reputation", "BSSID_Reputation_Score", "bssid_reputation_score"),
        "threat_score": ("Threat_Score", "Risk_Score", "threat_score"),
        "ssid_length": ("SSID_Length", "ssid_length"),
        "hidden_ssid_flag": ("Hidden_SSID_Flag", "Hidden_SSID", "hidden_ssid_flag"),
        "temporal_signal_fluctuation": ("Temporal_Signal_Fluctuation", "Signal_Fluctuation", "Signal_Var", "temporal_signal_fluctuation"),
    }
    CATEGORICAL = {"encryption_type"}

    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self.model: IsolationForest | None = None
        self.feature_names: list[str] = []
        self.fill_values: dict[str, float] = {}
        self.category_maps: dict[str, dict[str, int]] = {}

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def _value(self, record: Mapping[str, Any], feature: str) -> Any:
        for key in self.FEATURE_ALIASES[feature]:
            if key in record and record[key] is not None:
                return record[key]
        if feature == "ssid_length":
            return len(str(record.get("SSID") or record.get("ssid") or ""))
        if feature == "hidden_ssid_flag":
            return int(not str(record.get("SSID") or record.get("ssid") or "").strip())
        return None

    def _available_features(self, records: Iterable[Mapping[str, Any]]) -> list[str]:
        rows = list(records)
        return [name for name in self.FEATURE_ALIASES if any(self._value(row, name) is not None for row in rows)]

    @staticmethod
    def _numeric(value: Any) -> float:
        try:
            result = float(value)
            return result if np.isfinite(result) else np.nan
        except (TypeError, ValueError):
            return np.nan

    def _matrix(self, records: Iterable[Mapping[str, Any]], fitting: bool = False) -> np.ndarray:
        rows = list(records)
        values: dict[str, list[float]] = {}
        for feature in self.feature_names:
            raw = [self._value(row, feature) for row in rows]
            if feature in self.CATEGORICAL:
                if fitting:
                    categories = sorted({str(value).upper() for value in raw if value is not None})
                    self.category_maps[feature] = {category: index for index, category in enumerate(categories)}
                mapping = self.category_maps.get(feature, {})
                values[feature] = [float(mapping.get(str(value).upper(), -1)) if value is not None else np.nan for value in raw]
            else:
                values[feature] = [self._numeric(value) for value in raw]
            if fitting:
                valid = np.asarray(values[feature], dtype=float)
                self.fill_values[feature] = float(np.nanmedian(valid)) if np.isfinite(valid).any() else 0.0
        return np.column_stack([
            np.nan_to_num(np.asarray(values[feature], dtype=float), nan=self.fill_values.get(feature, 0.0))
            for feature in self.feature_names
        ])

    def train(self, historical_data: pd.DataFrame | Iterable[Mapping[str, Any]]) -> "IsolationForestDetector":
        records = historical_data.to_dict("records") if isinstance(historical_data, pd.DataFrame) else list(historical_data)
        if not records:
            raise ValueError("Historical data is empty; Isolation Forest cannot be trained.")
        # Only explicitly legitimate records define the normal baseline.
        normal = [row for row in records if str(row.get("Label", row.get("label", "Legit"))).strip().lower() in {"legit", "normal", "safe"}]
        normal = normal or records
        self.feature_names = self._available_features(normal)
        if not self.feature_names:
            raise ValueError("No supported anomaly-detection features were found.")
        matrix = self._matrix(normal, fitting=True)
        if len(matrix) < 2:
            raise ValueError("At least two normal records are required to train Isolation Forest.")
        self.model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        self.model.fit(matrix)
        return self

    def save(self) -> Path:
        if self.model is None:
            raise RuntimeError("Train or load a model before saving it.")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "feature_names": self.feature_names, "fill_values": self.fill_values, "category_maps": self.category_maps}, self.model_path)
        return self.model_path

    def load(self) -> bool:
        if not self.model_path.exists():
            return False
        try:
            bundle = joblib.load(self.model_path)
            self.model = bundle["model"]
            self.feature_names = list(bundle["feature_names"])
            self.fill_values = dict(bundle["fill_values"])
            self.category_maps = dict(bundle["category_maps"])
            return True
        except (OSError, KeyError, TypeError, ValueError) as exc:
            LOGGER.warning("Isolation Forest model could not be loaded: %s", exc)
            return False

    def predict(self, record: Mapping[str, Any]) -> dict[str, float | str]:
        if self.model is None:
            raise RuntimeError("Isolation Forest is not loaded. Train and save it first.")
        matrix = self._matrix([record])
        prediction = int(self.model.predict(matrix)[0])
        # sklearn: larger decision values are more normal.  Convert that to an
        # intuitive 0..1 anomaly score; prediction still preserves +/-1 logic.
        raw = float(-self.model.decision_function(matrix)[0])
        anomaly_score = float(np.clip(0.5 + raw, 0.0, 1.0))
        confidence = float(np.clip(abs(raw) * 2.0, 0.0, 1.0))
        return {"anomaly_score": round(anomaly_score, 4), "prediction": "ANOMALY" if prediction == -1 else "NORMAL", "confidence": round(confidence, 4)}
