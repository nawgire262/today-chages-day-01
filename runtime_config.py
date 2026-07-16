"""Small, dependency-free runtime configuration loader for SentinelShield."""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
CONFIG_PATH = Path("config/runtime_settings.json")

DEFAULTS: dict[str, Any] = {
    "adaptive_thresholds": {
        "warmup_samples": 15,
        "ewma_alpha": 0.12,
        "min_std": 4.0,
        "multipliers": {"critical": 2.0, "high": 1.15, "medium": 0.35},
        "bands": {"critical": [55.0, 95.0], "high": [35.0, 80.0], "medium": [15.0, 60.0]},
    },
    "notifications": {"cooldown_seconds": 120},
}


def _merge(defaults: dict[str, Any], provided: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(defaults)
    for key, value in provided.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        elif key in result:
            result[key] = value
    return result


def load_runtime_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load known keys only, retaining safe defaults on invalid configuration."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("configuration root must be an object")
        merged = _merge(DEFAULTS, loaded)
        adaptive = merged["adaptive_thresholds"]
        adaptive["warmup_samples"] = max(1, int(adaptive["warmup_samples"]))
        adaptive["ewma_alpha"] = min(1.0, max(0.001, float(adaptive["ewma_alpha"])))
        adaptive["min_std"] = max(0.1, float(adaptive["min_std"]))
        for name in ("critical", "high", "medium"):
            adaptive["multipliers"][name] = float(adaptive["multipliers"][name])
            band = adaptive["bands"][name]
            if not isinstance(band, list) or len(band) != 2:
                raise ValueError(f"adaptive threshold band '{name}' must contain two values")
            adaptive["bands"][name] = sorted(float(value) for value in band)
        merged["notifications"]["cooldown_seconds"] = max(0, int(merged["notifications"]["cooldown_seconds"]))
        return merged
    except FileNotFoundError:
        return deepcopy(DEFAULTS)
    except (KeyError, OSError, TypeError, json.JSONDecodeError, ValueError) as exc:
        LOGGER.warning("Invalid runtime configuration; using safe defaults: %s", exc)
        return deepcopy(DEFAULTS)
