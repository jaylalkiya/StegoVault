# 🔒 StegoVault — Encrypted Image Steganography & Detection

A Python project for a cybersecurity course that demonstrates **both sides** of
steganography:

- **Attack side** — hide a secret message (or file) inside an ordinary-looking
  image, encrypted with a password so it stays secret *and* invisible.
- **Defense side** — a steganalysis tool that inspects any image and estimates
  whether it secretly carries hidden data.

Everything is wrapped in a clean Tkinter GUI with three tabs: **Hide**,
**Extract**, and **Detect**.

---

## Why this is a good security project

Steganography and cryptography solve two different problems, and this project
uses them **together**:

| Layer | Technique | What it protects against |
|-------|-----------|--------------------------|
| Cryptography | AES-256-GCM + password (PBKDF2) | Someone reading the message |
| Steganography | LSB embedding in image pixels | Someone *knowing a message exists* |
| Integrity | GCM authentication tag | Someone silently altering the message |

Even if an analyst detects that data is hidden, they still cannot read it
without the password — and if they tamper with a single bit, decryption fails
loudly instead of returning fake plaintext.

---

## How it works

### 1. Encryption (`stego/crypto.py`)
- The password is stretched into a 256-bit key with **PBKDF2-HMAC-SHA256**
  (200,000 iterations + random salt) to resist brute-force attacks.
- The message is encrypted with **AES-256-GCM**, which provides both secrecy
  and tamper-detection.
- Output blob = `salt (16B) + nonce (12B) + ciphertext + tag`.

### 2. Hiding (`stego/embed.py`)
- Each pixel colour channel's **least significant bit** is replaced with one bit
  of the encrypted blob. Changing that bit shifts the colour by ≤ 1/255 — the
  human eye cannot see it.
- A small header (`magic marker + 4-byte length`) lets the extractor know how
  much to read back and fail fast on ordinary images.
- Saved as **PNG** (lossless). JPEG would destroy the hidden bits.
- Capacity ≈ `width × height × 3 ÷ 8` bytes.

### 3. Detection / steganalysis (`stego/detect.py`)
Produces a 0–100 suspicion score from:
1. **RS Analysis** (Fridrich, Goljan & Du, 2001) — the **primary** detector and
   the industry-standard method. It groups neighbouring pixels, measures their
   smoothness, flips LSBs, and measures again. From the change it *estimates the
   embedding rate* `p`. Clean photos give `p ≈ 0`; embedded images give a high
   `p`. Implemented from scratch in NumPy (no SciPy).
2. **Marker check** — instant confirmation if it's a StegoVault image.
3. **LSB ratio** — supporting signal; random hidden data pushes the 0/1 balance
   toward 0.5.

> **Why RS and not chi-square?** The older global chi-square "Pairs of Values"
> test *false-positives on ordinary photos* — sensor noise balances the even/odd
> counts and it flags clean images as suspicious. RS analysis does not have this
> weakness, so it gives trustworthy verdicts. (Verified: a clean photo scores ~2,
> a 50%-embedded image ~51, a StegoVault image 100.)

---

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.9+. `tkinter` ships with the standard Windows/macOS Python
installer. (On Linux: `sudo apt install python3-tk`.)

## Run the app

```bash
python app.py
```

## Verify the engine (no GUI)

```bash
python selftest.py
```

This runs a full round-trip, checks wrong-password and tamper rejection, and
compares the detector on a clean vs. a stego image.

---

## Project layout

```
steganography/
├── app.py            # Tkinter GUI (Hide / Extract / Detect)
├── selftest.py       # headless end-to-end test
├── requirements.txt
├── README.md
└── stego/
    ├── __init__.py
    ├── crypto.py     # AES-256-GCM + PBKDF2 password encryption
    ├── embed.py      # LSB hide / extract + capacity
    └── detect.py     # steganalysis (RS analysis + marker + LSB ratio)
```

---

## How to demo it (for a viva)

1. **Hide tab** — pick a PNG, type a secret message, set a password, save the
   stego image. Point out the capacity meter and that the output looks
   identical to the original.
2. **Detect tab** — analyze the *original* image (low score) then the *stego*
   image (high score). This shows the defender catching the hidden data.
3. **Extract tab** — recover the message with the right password. Then try a
   **wrong password** (rejected) to show the encryption layer.
4. Open the stego PNG in an editor, change one pixel, save, and try to extract —
   the GCM tag rejects it, proving tamper-protection.

---

## Limitations & honest notes

- LSB in the spatial domain is **not robust** to re-compression, resizing, or
  screenshotting — those destroy the hidden bits. This is expected for a
  teaching project; production tools use transform-domain methods.
- The detector estimates *likelihood*; it is evidence, not proof — exactly how
  real steganalysis works. RS analysis is accurate for embedding rates up to
  ~90% (which covers all realistic steganography). At a pathological 100% — every
  single pixel's LSB randomised — the RS estimator degenerates (a known property
  of the method); such saturated images are instead caught by the marker check
  or the near-0.5 LSB ratio.
- Only lossless carriers (PNG/BMP/TIFF) work for hiding. Analysis can read any
  image format.

---

*Educational project — use only on images and data you are authorised to work
with.*
