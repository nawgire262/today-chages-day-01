"""
adaptive_thresholds.py
=======================
Implements the "Adaptive Detection Thresholds" add-on.

PROBLEM THIS FIXES
-------------------
Previously, background_scanner.py (and main.py) classified every network
using hard-coded risk cut points:

    if threat_score >= 75: "CRITICAL"
    elif threat_score >= 50: "HIGH"
    elif threat_score >= 30: "MEDIUM"
    else: "SAFE"

Those numbers were picked once, by hand, and never change - regardless of
whether the deployment is a quiet home network (where a score of 40 would
be genuinely unusual) or a busy office/campus with dozens of overlapping
APs (where 40 is business as usual and would flood the analyst with
false "MEDIUM/HIGH" alerts).

WHAT THIS MODULE DOES INSTEAD
------------------------------
`AdaptiveThresholdEngine` learns the statistical baseline of risk scores
that a *specific* deployment normally produces, using an Exponentially
Weighted Moving Average (EWMA) of the mean and variance of every risk
score the scanner has ever seen. EWMA is used (rather than storing the
full history) so the engine adapts to a changing RF environment over
time and stays cheap enough to update on every scan cycle.

CRITICAL / HIGH / MEDIUM cut points are then re-derived every scan as:

    cut_point(level) = baseline_mean + k(level) * baseline_std

so a deployment that is normally noisy needs a proportionally bigger
deviation from its own baseline before something is flagged, and a
deployment that is normally quiet is flagged much sooner. Cut points
are still clamped to a sane [min, max] band (BAND below) so the system
never collapses to "everything is CRITICAL" or "nothing is ever
CRITICAL" in a pathological environment.

Until enough scans have been observed (WARMUP_SAMPLES), the engine
falls back to the original fixed 75/50/30 thresholds, so a fresh
install behaves exactly as before and only starts adapting once it has
real data to adapt from.

State (sample count, running mean, running variance) is persisted to a
small JSON file so the learned baseline survives dashboard restarts,
the same way alert_history.csv / current_scan.csv persist other scan
state.
"""

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_STATE_PATH = Path("adaptive_threshold_state.json")

# Original hard-coded thresholds - used as a safe fallback during warm-up
# and if the persisted state ever becomes unreadable/corrupted.
FALLBACK_THRESHOLDS = {"critical": 75.0, "high": 50.0, "medium": 30.0}

WARMUP_SAMPLES = 15      # scans needed before the engine starts adapting
EWMA_ALPHA = 0.12        # smoothing factor for the running mean/variance
                         # (smaller = slower/steadier adaptation)
MIN_STD = 4.0            # floor on the learned std-dev so thresholds
                         # never collapse on top of each other in an
                         # extremely stable environment

# Standard-deviation multipliers used to derive each cut point from the
# learned baseline. Roughly tuned so that, on a "typical" environment,
# the adaptive cut points land close to the original 75/50/30 values.
K_CRITICAL = 2.0
K_HIGH = 1.15
K_MEDIUM = 0.35

# Absolute safety rails: no matter how the baseline drifts, cut points
# are always clamped inside these ranges.
BAND = {
    "critical": (55.0, 95.0),
    "high": (35.0, 80.0),
    "medium": (15.0, 60.0),
}


@dataclass
class ThresholdState:
    count: int = 0
    mean: float = 0.0
    var: float = 0.0  # EWMA variance estimate


class AdaptiveThresholdEngine:
    """Learns a per-deployment risk-score baseline and derives adaptive
    CRITICAL / HIGH / MEDIUM cut points from it, instead of relying on
    fixed constants."""

    def __init__(self, state_path=DEFAULT_STATE_PATH, alpha: float = EWMA_ALPHA):
        self.state_path = Path(state_path)
        self.alpha = alpha
        self.state = self._load_state()

    # ---------------------------------------------------------- persistence
    def _load_state(self) -> ThresholdState:
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text())
                return ThresholdState(
                    count=int(data.get("count", 0)),
                    mean=float(data.get("mean", 0.0)),
                    var=float(data.get("var", 0.0)),
                )
            except Exception:
                pass
        return ThresholdState()

    def _save_state(self):
        try:
            self.state_path.write_text(json.dumps(asdict(self.state)))
        except Exception:
            pass  # persistence is best-effort; never break a scan over it

    def reset(self):
        """Wipe the learned baseline and go back to fixed fallback
        thresholds. Exposed for a 'reset adaptive baseline' control in
        Settings."""
        self.state = ThresholdState()
        self._save_state()

    # ------------------------------------------------------------ updating
    def update(self, risk_scores):
        """Feed this scan cycle's risk/threat scores into the running
        baseline. Call once per scan pass, after scoring every network."""
        for score in risk_scores:
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue
            self.state.count += 1
            if self.state.count == 1:
                self.state.mean = score
                self.state.var = 0.0
            else:
                delta = score - self.state.mean
                self.state.mean += self.alpha * delta
                self.state.var = (1 - self.alpha) * (self.state.var + self.alpha * delta * delta)
        self._save_state()

    # --------------------------------------------------------- computation
    def get_thresholds(self):
        """Return (thresholds_dict, mode) where mode is 'warming_up' or
        'adaptive'."""
        if self.state.count < WARMUP_SAMPLES:
            return dict(FALLBACK_THRESHOLDS), "warming_up"

        std = max(math.sqrt(max(self.state.var, 0.0)), MIN_STD)
        mean = self.state.mean

        raw = {
            "critical": mean + K_CRITICAL * std,
            "high": mean + K_HIGH * std,
            "medium": mean + K_MEDIUM * std,
        }

        clamped = {
            level: min(max(value, BAND[level][0]), BAND[level][1])
            for level, value in raw.items()
        }

        # Enforce critical > high > medium even after independent clamping.
        clamped["high"] = min(clamped["high"], clamped["critical"] - 1)
        clamped["medium"] = min(clamped["medium"], clamped["high"] - 1)

        return clamped, "adaptive"

    def classify(self, score):
        """Classify a single risk score using the current adaptive (or
        fallback) thresholds. Returns (threat_level, thresholds, mode)."""
        thresholds, mode = self.get_thresholds()
        score = float(score)
        if score >= thresholds["critical"]:
            level = "CRITICAL"
        elif score >= thresholds["high"]:
            level = "HIGH"
        elif score >= thresholds["medium"]:
            level = "MEDIUM"
        else:
            level = "SAFE"
        return level, thresholds, mode

    def summary(self):
        """Small dict suitable for showing in the dashboard (e.g. an
        'Adaptive Thresholds' panel) so the analyst can see the learned
        baseline and how many scans it is based on."""
        thresholds, mode = self.get_thresholds()
        std = math.sqrt(max(self.state.var, 0.0)) if self.state.count else 0.0
        return {
            "mode": mode,
            "samples_seen": self.state.count,
            "warmup_samples": WARMUP_SAMPLES,
            "baseline_mean": round(self.state.mean, 2),
            "baseline_std": round(std, 2),
            "thresholds": {k: round(v, 1) for k, v in thresholds.items()},
        }


if __name__ == "__main__":
    import random

    engine = AdaptiveThresholdEngine(state_path=Path("_demo_adaptive_state.json"))
    engine.reset()

    print("Simulating a 'noisy office' environment (scores cluster ~45-65)...\n")
    for i in range(30):
        batch = [random.gauss(52, 9) for _ in range(6)]
        engine.update(batch)
        thresholds, mode = engine.get_thresholds()
        if i % 5 == 0 or i == 29:
            print(f"scan {i+1:2d} | mode={mode:10s} | thresholds={thresholds}")

    print("\nFinal summary:", engine.summary())
    Path("_demo_adaptive_state.json").unlink(missing_ok=True)
