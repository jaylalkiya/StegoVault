"""Steganalysis - detecting whether an image likely hides LSB data.

This is the *defensive* side of the project. An analyst who intercepts an image
wants to know: does this innocent-looking picture secretly carry data?

Primary detector: RS Analysis (Fridrich, Goljan & Du, 2001)
----------------------------------------------------------
RS analysis is the standard, reliable way to detect LSB embedding. It groups
neighbouring pixels and measures how "smooth" they are, then flips LSBs and
measures again. In a natural image, flipping LSBs disturbs the smoothness in a
predictable, lopsided way. Random LSB data (like encrypted secrets) pushes those
measurements together. From the gap, RS *estimates the embedding rate p* - the
fraction of the LSB plane that carries hidden data.

    clean photo   -> p ~ 0.00 - 0.05   (low score)
    fully embedded -> p ~ 0.90 - 1.00   (high score)

Unlike the older global chi-square test, RS analysis does NOT flag ordinary
photos as suspicious, which fixes the false-positive problem.

We also report two supporting signals for the analysis log:
    * marker check - definitive if it is a StegoVault image.
    * LSB ratio    - how close the 0/1 balance is to a suspicious 50/50.
"""

from __future__ import annotations

import numpy as np
from PIL import Image

from .embed import MAGIC, HEADER_LEN

# RS mask: which pixels in each group of 4 get their LSB flipped.
_MASK = np.array([0, 1, 1, 0], dtype=bool)


def _load_rgb(image_path: str) -> np.ndarray:
    return np.array(Image.open(image_path).convert("RGB"), dtype=np.uint8)


def _has_marker(flat: np.ndarray) -> bool:
    """True if StegoVault's MAGIC marker sits in the first LSBs."""
    if flat.size < len(MAGIC) * 8:
        return False
    bits = flat[:len(MAGIC) * 8] & 1
    return np.packbits(bits).tobytes() == MAGIC


def _lsb_ratio(flat: np.ndarray) -> float:
    """Fraction of least-significant bits that are 1 (natural ~0.42-0.48)."""
    return float(np.mean(flat & 1))


# --- RS analysis ------------------------------------------------------------
def _discrimination(groups: np.ndarray) -> np.ndarray:
    """Smoothness of each group = sum of |neighbour differences|."""
    return np.abs(np.diff(groups, axis=-1)).sum(axis=-1)


def _flip(groups: np.ndarray, negative: bool) -> np.ndarray:
    """Apply the flipping function on the masked pixels of each group.

    F1 (positive) : x -> x XOR 1      (0<->1, 2<->3, ...)
    F-1 (negative): x -> ((x+1) XOR 1) - 1   (-1<->0, 1<->2, ...)
    """
    out = groups.copy()
    sel = out[..., _MASK]
    if negative:
        out[..., _MASK] = ((sel + 1) ^ 1) - 1
    else:
        out[..., _MASK] = sel ^ 1
    return out


def _rs_counts(groups: np.ndarray):
    """Return (R, S) for positive and negative masks in one pass."""
    f0 = _discrimination(groups)
    fp = _discrimination(_flip(groups, negative=False))
    fn = _discrimination(_flip(groups, negative=True))
    R_p = int(np.sum(fp > f0)); S_p = int(np.sum(fp < f0))
    R_n = int(np.sum(fn > f0)); S_n = int(np.sum(fn < f0))
    return R_p, S_p, R_n, S_n


def _rs_estimate_channel(chan: np.ndarray) -> float:
    """Estimate the LSB embedding rate p in [0, 1] for one colour channel."""
    chan = chan.astype(np.int16)
    h, w = chan.shape
    w4 = (w // 4) * 4
    if w4 < 4:
        return 0.0
    groups = chan[:, :w4].reshape(h, -1, 4)

    # Measurements on the image as-is.
    R_p, S_p, R_n, S_n = _rs_counts(groups)
    # Measurements after flipping ALL LSBs (the other end of the RS curve).
    R_p1, S_p1, R_n1, S_n1 = _rs_counts(groups ^ 1)

    d0 = R_p - S_p
    d1 = R_p1 - S_p1
    dm0 = R_n - S_n
    dm1 = R_n1 - S_n1

    # Solve the RS quadratic  a*x^2 + b*x + c = 0  for the curve crossing.
    a = 2 * (d1 + d0)
    b = dm0 - dm1 - d1 - 3 * d0
    c = d0 - dm0

    if a == 0:
        if b == 0:
            return 0.0
        x = -c / b
    else:
        disc = b * b - 4 * a * c
        if disc < 0:
            return 0.0
        root = np.sqrt(disc)
        x1 = (-b + root) / (2 * a)
        x2 = (-b - root) / (2 * a)
        x = x1 if abs(x1) < abs(x2) else x2

    denom = x - 0.5
    if denom == 0:
        return 0.0
    p = x / denom
    return float(np.clip(p, 0.0, 1.0))


def rs_embedding_rate(arr: np.ndarray) -> float:
    """Average RS embedding-rate estimate across the R, G, B channels."""
    ps = [_rs_estimate_channel(arr[:, :, c]) for c in range(arr.shape[2])]
    return float(np.mean(ps))


def analyze(image_path: str) -> dict:
    """Run all detectors and return a structured verdict.

    Returns a dict with:
        marker        : bool  - StegoVault payload definitely present
        lsb_ratio     : float
        rs_rate       : float - RS estimated embedding rate [0..1]
        score         : int   - overall suspicion 0..100
        verdict       : str   - human summary
        notes         : list[str]
    """
    arr = _load_rgb(image_path)
    flat = arr.reshape(-1)

    marker = _has_marker(flat)
    ratio = _lsb_ratio(flat)
    rs_rate = rs_embedding_rate(arr)

    notes: list[str] = []

    if marker:
        length = int.from_bytes(
            np.packbits(flat[len(MAGIC) * 8:HEADER_LEN * 8] & 1).tobytes(), "big")
        notes.append(f"StegoVault marker found - payload is ~{length} bytes.")
        score = 100
    else:
        # RS embedding rate is the main signal (0..1 -> 0..100).
        score = int(round(100 * rs_rate))

        if rs_rate > 0.6:
            notes.append(f"RS analysis estimates a high embedding rate (~{rs_rate*100:.0f}%).")
        elif rs_rate > 0.25:
            notes.append(f"RS analysis estimates a moderate embedding rate (~{rs_rate*100:.0f}%).")
        else:
            notes.append(f"RS analysis estimates almost no embedding (~{rs_rate*100:.0f}%).")

        if abs(ratio - 0.5) < 0.01:
            notes.append("LSB 0/1 ratio is close to 50/50 (consistent with random data).")
        else:
            notes.append("LSB ratio is within the normal range for photos.")

    if score >= 80:
        verdict = "HIGH likelihood of hidden data"
    elif score >= 40:
        verdict = "POSSIBLE hidden data - inconclusive"
    else:
        verdict = "LOW likelihood - probably a clean image"

    return {
        "marker": marker,
        "lsb_ratio": ratio,
        "rs_rate": rs_rate,
        "score": score,
        "verdict": verdict,
        "notes": notes,
    }
