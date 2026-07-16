"""
rssi_raim.py
<<<<<<< HEAD
=============
"AP Distance-Consistency Engine" — integrates the core logic of three
research papers into one feature for SentinelShield.

PAPER 1 — Ahmad, N.M. et al. (2014), "A RSSI-based rogue access point
    detection framework for Wi-Fi hotspots," IEEE ISTT.
    Core idea we reuse: client-centric detection using nothing but RSSI
    values the client itself collects over repeated scans — no dedicated
    sensors, no infrastructure changes. This module runs entirely on the
    scanning device, exactly like main.py already does.

PAPER 2 — "Time of Flight and Fingerprinting Based Methods for Wireless
    Rogue Device Detection" (Montclair State University thesis).
    Core idea we reuse: raw RSSI alone is a weak feature; the RSSI-to-
    DISTANCE relationship (via a path-loss model) is what actually lets
    you tell devices apart, and a Random Forest classifier gave the best
    results of the models tested. We (a) convert every RSSI reading to an
    estimated distance instead of comparing raw dBm values, and (b) feed
    that estimated distance into the project's existing Random Forest /
    hybrid stack (train_model.py / main.py) as an extra feature signal.

PAPER 3 — Liu, W. & Papadimitratos, P. (2024/2025), "Position-based Rogue
    Access Point Detection," arXiv:2406.01927.
    Core idea we reuse: generate different SUBSETS of APs, fuse a
    position/state estimate from each subset, and flag whichever AP's
    inclusion/exclusion causes estimates to disagree beyond a 3-sigma
    threshold (adapted from RAIM in GNSS spoofing detection). We don't
    have a pre-surveyed fingerprint database or true 3-D AP positions, so
    we run the same subset-generation + Gaussian-fusion + deviation-
    threshold + voting-exclusion logic (their Eq. 4–8) in 1-D DISTANCE
    space instead of full (x, y, z) position space, using each BSSID's
    own path-loss-model distance estimate as the state to cross-validate.
    This is the natural adaptation for a single client with no pre-built
    radio map — exactly the "client/user can independently detect rogue
    APs" use case the paper calls out as a goal.

Nothing here needs new hardware, a server, or a pre-surveyed database —
only the RSSI samples main.py is already collecting.
"""

import math
from itertools import combinations

import numpy as np

# ---------------------------------------------------------------------
# PAPER 2: log-distance path-loss model
# ---------------------------------------------------------------------
# RSSI(d) = TX_POWER_AT_1M - 10 * PATH_LOSS_EXPONENT * log10(d)
#  => d = 10 ** ((TX_POWER_AT_1M - RSSI) / (10 * PATH_LOSS_EXPONENT))
TX_POWER_AT_1M = -40.0     # dBm: typical AP transmit strength at 1 meter
PATH_LOSS_EXPONENT = 3.0   # ~2 free space ... ~4 indoor w/ walls; 3.0 = indoor default


def rssi_to_distance(rssi, tx_power=TX_POWER_AT_1M, n=PATH_LOSS_EXPONENT):
    """Convert one RSSI reading (dBm) into an estimated distance (meters).

    Replaces the project's old fixed rule ("avg_signal > -35 => suspicious")
    with a physically grounded estimate, per the Montclair thesis finding
    that the RSSI-DISTANCE relationship, not raw RSSI, is the reliable
    signal for telling devices/APs apart.
    """
    return 10 ** ((tx_power - rssi) / (10 * n))


def distance_uncertainty(rssi_samples, tx_power=TX_POWER_AT_1M, n=PATH_LOSS_EXPONENT,
                          relative_model_uncertainty=0.4):
    """Turn the spread (std dev) of repeated RSSI samples for one BSSID
    into an uncertainty on its distance estimate, by propagating the RSSI
    std dev through the path-loss model's derivative. Noisier RSSI history
    -> less confidence in that BSSID's distance estimate -> lower voting
    weight in the fusion step below.

    Path-loss-model distance estimates are inherently noisy even for
    perfectly legitimate APs (the Montclair thesis found the RSSI-distance
    relationship is *not* perfectly consistent, and Liu et al. cite this as
    a known weakness of pure RSSI-clustering methods). So on top of the
    RSSI-sample spread, we add a distance-proportional "model uncertainty"
    floor (~40% of the estimated distance by default) so that ordinary
    physical separation between legitimately co-located APs (different
    radio bands, mesh nodes, repeaters) isn't mistaken for an inconsistency.
    """
    d = rssi_to_distance(float(np.mean(rssi_samples)), tx_power, n)
    model_floor = relative_model_uncertainty * d

    if len(rssi_samples) < 2:
        return max(model_floor, 0.25)

    rssi_std = float(np.std(rssi_samples))
    # d(distance)/d(RSSI) = -ln(10)/(10n) * distance  (derivative of the model above)
    slope = (math.log(10) / (10 * n)) * d
    sampling_uncertainty = rssi_std * slope

    return max(sampling_uncertainty, model_floor, 0.25)


# ---------------------------------------------------------------------
# PAPER 1: client-centric per-BSSID temporal RSSI profile
# ---------------------------------------------------------------------
def rssi_profile(rssi_samples):
    """Summarize one BSSID's repeated-scan RSSI history (mean/std/range).
    This is the 'client-only, no dedicated sensors' RSSI-over-time signal
    from Ahmad et al. — built from the same repeated scans main.py already
    performs (its existing 5-pass scan loop)."""
    arr = np.asarray(rssi_samples, dtype=float)
    return {
        "mean": float(arr.mean()),
        "std": float(arr.std()) if len(arr) > 1 else 0.0,
        "range": float(arr.max() - arr.min()) if len(arr) > 1 else 0.0,
    }


def is_temporally_unstable(rssi_samples, std_threshold=8.0, range_threshold=15.0):
    """Flag a BSSID whose RSSI bounces around abnormally across the
    repeated scans taken within one ~10-second window — e.g. an attacker
    actively adjusting transmit power to compete for client association,
    or a spoofed/replayed signal (Liu et al.'s "attack (ii)": RSSIs
    replaced by random values in a range). Legitimate, stationary APs
    typically vary by only 1-3 dB scan-to-scan; the thresholds here are
    set well above that normal noise floor.

    This complements the distance-consistency check above: RAIM-style
    voting catches an AP that's in the *wrong physical place* relative to
    its peers, while this catches an AP whose own signal simply isn't
    physically plausible/stable over time — two different attack
    signatures, matching the different attack types Liu et al. test
    against (steady additive offset vs. randomized replacement values).
    """
    profile = rssi_profile(rssi_samples)
    return profile["std"] > std_threshold or profile["range"] > range_threshold


# ---------------------------------------------------------------------
# PAPER 3: subset-generation + Gaussian-fusion + RAIM-style voting
# ---------------------------------------------------------------------
def raim_consistency_check(bssid_rssi_histories, n_sigma=3.0, max_subsets_per_bssid=15, seed=42):
    """
    Adapts the Gaussian-mixture RAIM scheme from Liu & Papadimitratos
    (2024/2025) to a single-SSID, no-fingerprint-database setting.

    For every BSSID broadcasting a given SSID, we build many different
    subsets of the OTHER BSSIDs, fuse an uncertainty-weighted distance
    estimate from each subset, and check whether the candidate BSSID's own
    distance estimate deviates from that fused value by more than an
    adaptive 3-sigma threshold. If more subsets say "inconsistent" than
    "consistent" (majority vote, Eq. 8 in the paper), the BSSID is flagged
    as a rogue-AP candidate.

    Parameters
    ----------
    bssid_rssi_histories : dict[str, list[float]]
        BSSID -> list of RSSI samples collected across repeated scans
        (needs >= 2 BSSIDs for the same SSID to have anything to cross-
        validate against — matches the paper's requirement of "redundant"
        AP measurements).

    Returns
    -------
    dict[str, dict] — per-BSSID:
        distance, uncertainty, deviation, rogue_votes, benign_votes, flagged
    """
    bssids = list(bssid_rssi_histories.keys())
    n = len(bssids)

    distances, uncertainties = {}, {}
    for b in bssids:
        samples = bssid_rssi_histories[b]
        distances[b] = rssi_to_distance(float(np.mean(samples)))
        uncertainties[b] = distance_uncertainty(samples)

    if n < 2:
        # No redundancy -> nothing to cross-validate (same limitation the
        # paper has: RAIM needs multiple independent measurements).
        return {
            b: {
                "distance": round(distances[b], 2),
                "uncertainty": round(uncertainties[b], 2),
                "deviation": 0.0,
                "rogue_votes": 0,
                "benign_votes": 0,
                "flagged": False,
            }
            for b in bssids
        }

    rng = np.random.default_rng(seed)
    results = {}

    for b in bssids:
        others = [x for x in bssids if x != b]

        # ---- 4.1 Subset generation: varying sizes, from the OTHER BSSIDs ----
        subset_pool = []
        for size in range(1, len(others) + 1):
            subset_pool.extend(combinations(others, size))

        # ---- 4.1.1 Sampling strategy: cap subset explosion for many APs ----
        if len(subset_pool) > max_subsets_per_bssid:
            idx = rng.choice(len(subset_pool), size=max_subsets_per_bssid, replace=False)
            subset_pool = [subset_pool[i] for i in idx]

        rogue_votes = benign_votes = 0
        devs = []

        for subset in subset_pool:
            # ---- 4.2 Eq. 4: uncertainty-weighted fusion ----
            weights = np.array([1.0 / uncertainties[x] ** 2 for x in subset])
            subset_d = np.array([distances[x] for x in subset])
            fused = float(np.sum(subset_d * weights) / np.sum(weights))

            # Fused uncertainty of the subset's combined estimate (standard
            # inverse-variance weighting), then combined with the
            # candidate's own uncertainty to get the expected spread under
            # the null hypothesis ("b is just another legitimate AP at its
            # own distance"). This replaces trying to estimate a 3-sigma
            # threshold from only 1-3 raw points per subset (unstable with
            # so few BSSIDs) with a standard propagated-uncertainty check.
            fused_uncertainty = float(np.sqrt(1.0 / np.sum(weights)))
            combined_uncertainty = math.sqrt(uncertainties[b] ** 2 + fused_uncertainty ** 2)
            thresh = max(n_sigma * combined_uncertainty, 1.0)

            dev = abs(distances[b] - fused)
            devs.append(dev)

            if dev > thresh:
                rogue_votes += 1
            else:
                benign_votes += 1

        results[b] = {
            "distance": round(distances[b], 2),
            "uncertainty": round(uncertainties[b], 2),
            "deviation": round(float(np.mean(devs)), 2) if devs else 0.0,
            "rogue_votes": rogue_votes,
            "benign_votes": benign_votes,
            # ---- 4.2.1 Eq. 8: majority-vote exclusion rule ----
            "flagged": rogue_votes > benign_votes,
        }

    return results
=======

RAIM-inspired WiFi signal validation utilities
for SentinelShield.

Provides:
1. RSSI -> Distance estimation
2. Temporal RSSI stability detection
3. RAIM-style consistency check
"""

import math
import statistics


# -------------------------------------------------
# RSSI TO DISTANCE
# -------------------------------------------------

def rssi_to_distance(rssi, tx_power=-40, path_loss_exponent=2.4):
    """
    Estimate distance from RSSI using
    the log-distance path loss model.

    Parameters
    ----------
    rssi : int
        Received Signal Strength (dBm)

    tx_power : int
        Expected RSSI at 1 meter

    path_loss_exponent : float
        Indoor propagation factor

    Returns
    -------
    float
        Estimated distance (meters)
    """

    try:
        distance = 10 ** ((tx_power - rssi) /
                          (10 * path_loss_exponent))
        return round(distance, 2)

    except Exception:
        return 0.0


# -------------------------------------------------
# TEMPORAL STABILITY
# -------------------------------------------------

def is_temporally_unstable(history,
                           std_threshold=8,
                           range_threshold=15):
    """
    Determine whether RSSI is unstable
    over repeated scans.
    """

    if history is None:
        return False

    if len(history) < 3:
        return False

    try:

        signal_range = max(history) - min(history)

        std = statistics.stdev(history)

        if signal_range > range_threshold:
            return True

        if std > std_threshold:
            return True

        return False

    except Exception:
        return False


# -------------------------------------------------
# RAIM CONSISTENCY CHECK
# -------------------------------------------------

def raim_consistency_check(per_bssid_histories):
    """
    Compare all BSSIDs broadcasting
    the same SSID.

    Returns dictionary:

    {
        bssid:{
            flagged,
            distance,
            rogue_votes,
            benign_votes
        }
    }
    """

    results = {}

    if not per_bssid_histories:
        return results

    distances = {}

    for bssid, history in per_bssid_histories.items():

        if len(history) == 0:
            continue

        avg = sum(history) / len(history)

        distances[bssid] = rssi_to_distance(avg)

    if len(distances) == 0:
        return results

    median_distance = statistics.median(
        distances.values()
    )

    for bssid, distance in distances.items():

        difference = abs(distance - median_distance)

        flagged = difference > 6

        results[bssid] = {

            "flagged": flagged,

            "distance": round(distance, 2),

            "rogue_votes": 1 if flagged else 0,

            "benign_votes": 0 if flagged else 1

        }

    return results


# -------------------------------------------------
# OPTIONAL HELPERS
# -------------------------------------------------

def calculate_signal_variance(history):
    """
    Return RSSI variance.
    """

    if len(history) < 2:
        return 0

    return round(statistics.variance(history), 2)


def calculate_signal_std(history):
    """
    Return RSSI standard deviation.
    """

    if len(history) < 2:
        return 0

    return round(statistics.stdev(history), 2)


def signal_quality(rssi):
    """
    Human readable signal quality.
    """

    if rssi >= -50:
        return "Excellent"

    if rssi >= -60:
        return "Very Good"

    if rssi >= -70:
        return "Good"

    if rssi >= -80:
        return "Fair"

    return "Poor"


# -------------------------------------------------
# TEST
# -------------------------------------------------

if __name__ == "__main__":

    history = [-45, -47, -46, -44, -60]

    print("Distance:",
          rssi_to_distance(-45))

    print("Unstable:",
          is_temporally_unstable(history))

    sample = {

        "AA:BB:CC:11": [-44, -45, -46],

        "AA:BB:CC:22": [-46, -45, -47],

        "AA:BB:CC:33": [-72, -74, -73]

    }

    print(raim_consistency_check(sample))
>>>>>>> 0d1f8da (Updated SentinelShield project)
