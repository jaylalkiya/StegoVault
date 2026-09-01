"""Headless test of the StegoVault engine (no GUI).

Run:  python selftest.py
It creates a test image, hides an encrypted message, extracts it back,
checks wrong-password/tamper protection, and runs the detector on both a
clean and a stego image.
"""

import os
import tempfile

import numpy as np
from PIL import Image

from stego import crypto, embed, detect


def make_natural_image(path, w=256, h=256, seed=7):
    """A smooth gradient + mild noise - resembles a real photo's LSB stats."""
    rng = np.random.default_rng(seed)
    xs = np.linspace(0, 255, w, dtype=np.float64)
    ys = np.linspace(0, 255, h, dtype=np.float64)
    base = (xs[None, :] * 0.5 + ys[:, None] * 0.5)
    arr = np.stack([base, base * 0.8 + 20, base * 0.6 + 40], axis=-1)
    arr += rng.normal(0, 3, arr.shape)          # gentle sensor-like noise
    arr = np.clip(arr, 0, 255).astype(np.uint8)
    Image.fromarray(arr, "RGB").save(path)


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


def main():
    tmp = tempfile.mkdtemp(prefix="stego_")
    clean = os.path.join(tmp, "clean.png")
    stego = os.path.join(tmp, "stego.png")
    make_natural_image(clean)

    secret = "Attack at dawn. Coordinates 27.1751 N, 78.0421 E. -- agent 42".encode()
    password = "correct horse battery staple"

    print("1) Round-trip encrypt -> hide -> extract -> decrypt")
    blob = crypto.encrypt(secret, password)
    embed.embed(clean, blob, stego)
    recovered = crypto.decrypt(embed.extract(stego), password)
    check("recovered message matches original", recovered == secret)

    print("2) Capacity reporting")
    cap = embed.capacity_bytes(clean)
    check("capacity is positive and sane", cap > 1000)
    print(f"       capacity of 256x256 image: {cap} bytes")

    print("3) Wrong password is rejected")
    try:
        crypto.decrypt(embed.extract(stego), "wrong password")
        check("wrong password should have raised", False)
    except crypto.DecryptionError:
        check("wrong password raises DecryptionError", True)

    print("4) Tamper protection (flip a pixel bit)")
    arr = np.array(Image.open(stego).convert("RGB"))
    # Corrupt an LSB in the CIPHERTEXT region (past the 8-byte header, which
    # lives in the first ~21 pixels). Pixel (0,100) is well inside the payload,
    # so GCM's authentication tag should reject it on decrypt.
    arr[0, 100, 0] ^= 1
    tampered = os.path.join(tmp, "tampered.png")
    Image.fromarray(arr, "RGB").save(tampered)
    try:
        crypto.decrypt(embed.extract(tampered), password)
        check("tampering should have raised", False)
    except (crypto.DecryptionError, embed.NoHiddenDataError):
        check("tampering is detected and rejected", True)

    print("5) Extract on a clean image reports 'no data'")
    try:
        embed.extract(clean)
        check("clean image should raise NoHiddenDataError", False)
    except embed.NoHiddenDataError:
        check("clean image correctly reports no hidden data", True)

    print("6) Steganalysis: clean vs stego (fill image to stress the detector)")
    big_secret = os.urandom(cap - 100)          # nearly fill the image
    embed.embed(clean, crypto.encrypt(big_secret, password), stego)
    clean_r = detect.analyze(clean)
    stego_r = detect.analyze(stego)
    print(f"       clean  -> score {clean_r['score']:>3}  rs={clean_r['rs_rate']:.3f}  ({clean_r['verdict']})")
    print(f"       stego  -> score {stego_r['score']:>3}  rs={stego_r['rs_rate']:.3f}  ({stego_r['verdict']})")
    check("stego marker detected", stego_r["marker"] is True)
    check("clean image is NOT flagged high (score < 40)", clean_r["score"] < 40)
    check("stego scores higher than clean", stego_r["score"] > clean_r["score"])

    print("7) Foreign-tool check: RS detects a marker-free 50%-embedded image")
    # Mimic a DIFFERENT stego tool (no StegoVault marker) at a realistic 50%
    # embedding rate. RS analysis alone must flag it, with no marker to rely on.
    arr = np.array(Image.open(clean).convert("RGB"))
    marker_free = os.path.join(tmp, "marker_free.png")
    rng2 = np.random.default_rng(1)
    flat = arr.reshape(-1)
    n = flat.size // 2
    idx = rng2.choice(flat.size, n, replace=False)
    flat[idx] = (flat[idx] & 0xFE) | rng2.integers(0, 2, n, dtype=np.uint8)
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(marker_free)
    mf = detect.analyze(marker_free)
    natural = detect.analyze(clean)
    print(f"       natural (clean) -> rs={natural['rs_rate']:.3f}  score {natural['score']:>3}")
    print(f"       foreign 50%     -> rs={mf['rs_rate']:.3f}  score {mf['score']:>3}")
    check("clean image stays low (score < 40)", natural["score"] < 40)
    check("foreign 50% embed is flagged (score >= 40)", mf["score"] >= 40)

    print("\nAll checks passed. Engine is working correctly.")
    print(f"(test files in {tmp})")


if __name__ == "__main__":
    main()
