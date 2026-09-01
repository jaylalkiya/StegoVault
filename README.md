<div align="center">

```
 ███████ ████████ ███████  ██████   ██████
 ██         ██    ██      ██       ██    ██
 ███████    ██    █████   ██   ███ ██    ██
      ██    ██    ██      ██    ██ ██    ██
 ███████    ██    ███████  ██████   ██████   V A U L T
```

**`[ encrypted image steganography + steganalysis ]`**

*Hide a message so it cannot be read — and so nobody knows it is there.*
*Then build the tool that catches you doing it.*

![python](https://img.shields.io/badge/python-3.9%2B-0a0f0a?style=flat-square&labelColor=050805&color=00ff41)
![crypto](https://img.shields.io/badge/crypto-AES--256--GCM-0a0f0a?style=flat-square&labelColor=050805&color=00ff41)
![kdf](https://img.shields.io/badge/KDF-PBKDF2%20200k-0a0f0a?style=flat-square&labelColor=050805&color=00ff41)
![detector](https://img.shields.io/badge/steganalysis-RS%20analysis-0a0f0a?style=flat-square&labelColor=050805&color=ffb000)
![tests](https://img.shields.io/badge/selftest-7%2F7%20passing-0a0f0a?style=flat-square&labelColor=050805&color=00ff41)

</div>

---

## `>` the demo

Two images. One of them is carrying **114 KB of AES-256-GCM ciphertext**.

![carrier vs stego vs amplified difference](docs/comparison.png)

Panel 3 is the absolute pixel difference, amplified ×255. Every lit pixel is a
single bit that moved — a colour shift of **1/255**, well under the threshold
where a human eye or a JPEG-grade compressor would ever notice.

Your eye cannot separate panels 1 and 2. **Panel 3 is why steganalysis exists.**

---

## `>` what this is

Most steganography projects stop at *hiding*. This one implements the
**attacker and the analyst**, because a covert channel you cannot detect is only
half of the security story.

| | module | does |
|---|---|---|
| 🔴 | **`[ HIDE ]`** | encrypt a message or file under a passphrase, then bury the ciphertext one bit at a time in the pixels of an ordinary PNG |
| 🟢 | **`[ EXTRACT ]`** | pull it back out — wrong passphrase or a single altered bit is *refused*, not silently mangled |
| 🟡 | **`[ DETECT ]`** | steganalysis: score any image 0–100 on whether it secretly carries data, including images made by **other** tools |

Three layers, three different attacks defeated:

```
┌─ layer ────────────┬─ technique ───────────────┬─ stops an adversary from ────┐
│ cryptography       │ AES-256-GCM               │ reading the message          │
│ steganography      │ LSB embedding             │ knowing a message exists     │
│ integrity          │ GCM authentication tag    │ silently altering it         │
└────────────────────┴───────────────────────────┴──────────────────────────────┘
```

Even an analyst who *detects* the payload still faces AES-256. And if they flip
one bit to corrupt it, decryption fails loudly instead of returning plausible
garbage.

---

## `>` screenshots

<table>
<tr>
<td width="50%">

**`[ HIDE ]`** — live capacity meter, text or file payload

![hide tab](docs/shot_hide.png)

</td>
<td width="50%">

**`[ EXTRACT ]`** — payload recovered, tamper-checked

![extract tab](docs/shot_extract.png)

</td>
</tr>
<tr>
<td width="50%">

**`[ DETECT ]`** — clean image, correctly cleared

![detect clean](docs/shot_detect_clean.png)

</td>
<td width="50%">

**`[ DETECT ]`** — the same photo, now carrying 114 KB

![detect stego](docs/shot_detect_stego.png)

</td>
</tr>
</table>

---

## `>` how the payload is built

The secret never touches the image until it is already ciphertext.

```
  plaintext                                   ┌── random, per message ──┐
      │                                       │                         │
      ▼                                       ▼                         ▼
  passphrase ──► PBKDF2-HMAC-SHA256 ──► key   salt(16B)             nonce(12B)
                 200,000 iterations      │
                                         ▼
                              AES-256-GCM encrypt
                                         │
                                         ▼
        blob =  salt(16) │ nonce(12) │ ciphertext │ GCM tag(16)
                                         │
                                         ▼
        pixels = MAGIC "SVLT"(4) │ length(4) │ blob   ← 1 bit per colour channel
```

**Why each piece is there:**

- **PBKDF2, 200k iterations** — a passphrase is not a key. Stretching it makes
  each brute-force guess ~200,000× more expensive.
- **Random 16-byte salt** — two people picking the same passphrase still derive
  completely different keys, which kills precomputed rainbow tables.
- **GCM tag** — authenticated encryption. Tampering is *detected*, not decrypted.
- **`SVLT` magic + length header** — lets extraction fail fast on an ordinary
  image instead of returning 100 KB of noise.

Capacity is `width × height × 3 ÷ 8` bytes — a 12 MP photo hides about **4.5 MB**.

---

## `>` the detector

This is the part most projects skip. `stego/detect.py` implements
**RS Analysis** (Fridrich, Goljan & Du, 2001) from scratch in NumPy — no SciPy,
no ML, no black box.

RS groups neighbouring pixels and measures their *smoothness*, flips LSBs
according to a mask, and measures again. Natural images react to that flip in a
predictable, lopsided way; random data does not. Solving the resulting quadratic
recovers `p` — an **estimate of what fraction of the LSB plane is carrying data**.

```
  clean photograph      p ≈ 0.00 – 0.05      →  score 0–5     LOW
  moderate embed        p ≈ 0.50             →  score ~50     POSSIBLE
  saturated carrier     p ≈ 0.83 – 1.00      →  score 83–100  HIGH
```

Measured, reproducible — every row below comes out of `selftest.py`:

| target | RS rate | score | verdict |
|---|---|---|---|
| natural photo, untouched | `0.002` | **0** | LOW — probably clean |
| StegoVault, 127-byte message | `0.003` | **100** | HIGH *(caught by marker)* |
| StegoVault, 88% of capacity | `0.830` | **100** | HIGH *(caught by RS alone)* |
| **foreign tool, no marker, 50% embed** | `0.509` | **51** | POSSIBLE — inconclusive |

That last row is the one that matters. The image carries **no `SVLT` marker** —
it mimics a completely different stego tool — and RS still flags it purely on
statistics. The detector is not just recognising its own output.

> **Why RS instead of the classic chi-square test?**
> The older global chi-square "Pairs of Values" test *false-positives on
> ordinary photographs* — sensor noise naturally balances the even/odd counts,
> so clean images get flagged as suspicious. A detector that cries wolf on real
> photos is useless to an analyst. RS analysis does not have that weakness.

---

## `>` run it

```bash
git clone https://github.com/jaylalkiya/StegoVault.git
cd StegoVault
pip install -r requirements.txt
python app.py
```

Python 3.9+. `tkinter` ships with the standard Windows/macOS installer
(Linux: `sudo apt install python3-tk`).

**60-second demo.** Two images ship with the repo — a clean carrier and one
that is already loaded, so you can point the detector at something on your very
first run:

```
[ DETECT ]   scan docs/sample_carrier.png  →   0/100   LOW
             scan docs/stego_filled.png    → 100/100   HIGH
             open both. they look identical.

[ HIDE ]     carrier → docs/sample_carrier.png, type a message,
             set a passphrase, ENCRYPT & EMBED → save as mine.png

[ EXTRACT ]  open mine.png with the passphrase → your message returns
             now try a WRONG passphrase        → refused, not garbage
```

---

## `>` verify the engine

No GUI, no clicking — the whole thing is provable from the terminal:

```bash
python selftest.py
```

```
1) Round-trip encrypt -> hide -> extract -> decrypt
  [PASS] recovered message matches original
2) Capacity reporting
  [PASS] capacity is positive and sane
       capacity of 256x256 image: 24568 bytes
3) Wrong password is rejected
  [PASS] wrong password raises DecryptionError
4) Tamper protection (flip a pixel bit)
  [PASS] tampering is detected and rejected
5) Extract on a clean image reports 'no data'
  [PASS] clean image correctly reports no hidden data
6) Steganalysis: clean vs stego (fill image to stress the detector)
       clean  -> score   2  rs=0.025  (LOW likelihood - probably a clean image)
       stego  -> score 100  rs=0.622  (HIGH likelihood of hidden data)
  [PASS] stego marker detected
  [PASS] clean image is NOT flagged high (score < 40)
  [PASS] stego scores higher than clean
7) Foreign-tool check: RS detects a marker-free 50%-embedded image
       natural (clean) -> rs=0.025  score   2
       foreign 50%     -> rs=0.509  score  51
  [PASS] clean image stays low (score < 40)
  [PASS] foreign 50% embed is flagged (score >= 40)

All checks passed. Engine is working correctly.
```

Check 4 is the interesting one: it flips **a single bit** inside the ciphertext
region of a stego image, and the GCM tag catches it.

---

## `>` build a standalone .exe

```bash
pip install pyinstaller
pyinstaller StegoVault.spec
```

Produces `dist/StegoVault.exe` — no Python needed on the target machine. The
spec bundles the icon and excludes unused libraries to keep the binary lean.

---

## `>` layout

```
StegoVault/
├── app.py              # Tkinter GUI — three tabs, threaded so the UI never blocks
├── selftest.py         # headless end-to-end proof, 7 checks
├── StegoVault.spec     # PyInstaller build recipe
├── stego/
│   ├── crypto.py       # AES-256-GCM + PBKDF2 — 82 lines, no custom crypto
│   ├── embed.py        # LSB hide / extract / capacity, vectorised in NumPy
│   └── detect.py       # RS analysis + marker + LSB ratio → 0-100 score
├── assets/             # application icon
└── docs/               # sample carrier + screenshots
```

Every cryptographic primitive comes from the audited `cryptography` library.
**No hand-rolled crypto** — only the steganography and steganalysis are
implemented here, which is exactly where the interesting work is.

---

## `>` limits — read this part

Honest engineering beats overselling:

- **LSB is fragile by design.** Re-compress to JPEG, resize, or screenshot the
  stego image and the payload is gone. This is inherent to spatial-domain LSB;
  production tools embed in the DCT/DWT domain to survive it.
- **The detector reports likelihood, not proof.** A score is evidence for an
  analyst, the same way real steganalysis works — not a courtroom verdict.
- **RS degenerates at exactly 100% embedding.** A known property of the
  estimator: when *every* LSB is randomised there is no clean baseline left to
  measure against. Such saturated images get caught by the marker check and the
  near-0.500 LSB ratio instead.
- **A PyInstaller .exe is not protection.** Frozen bytecode can be decompiled.
  It is packaging convenience, nothing more.
- **Only lossless carriers** (PNG / BMP / TIFF) can hide data. Any format can be
  *analysed*.

---

## `>` reference

- J. Fridrich, M. Goljan, R. Du — *Reliable Detection of LSB Steganography in
  Color and Grayscale Images*, ACM Multimedia 2001. (The RS method in `detect.py`.)
- NIST SP 800-38D — Galois/Counter Mode.
- RFC 8018 — PBKDF2.

---

<div align="center">

`root@stegovault:~#` **built for learning offensive and defensive technique.**
**use only on images and data you are authorised to touch.**

</div>
