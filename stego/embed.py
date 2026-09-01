"""Least-Significant-Bit (LSB) steganography for images.

Idea
----
Every pixel colour channel is a byte, e.g. red = 10110110. Flipping the last
(least significant) bit changes the colour by at most 1/255 - invisible to the
eye. So we can store one secret bit in each channel's last bit.

We embed the payload as a bit stream across the R, G, B channels of every
pixel. A small header tells the extractor how many bytes to read back.

Payload layout written into the pixels:

    +---------+---------+-----------------+
    | MAGIC   | length  |  data bytes     |
    | 4 bytes | 4 bytes |  <length> bytes |
    +---------+---------+-----------------+

MAGIC lets us fail fast when an image contains no StegoVault payload.
The image is saved as PNG (lossless) - JPEG would destroy the hidden bits.
"""

from __future__ import annotations

import numpy as np
from PIL import Image

MAGIC = b"SVLT"          # 4-byte marker identifying our payloads
HEADER_LEN = len(MAGIC) + 4   # magic + 4-byte big-endian length


class CapacityError(Exception):
    """Raised when the message is too large for the chosen image."""


class NoHiddenDataError(Exception):
    """Raised when an image contains no StegoVault payload."""


def _load_rgb(image_path: str) -> np.ndarray:
    """Load an image as an (H, W, 3) uint8 array, dropping any alpha channel."""
    img = Image.open(image_path).convert("RGB")
    return np.array(img, dtype=np.uint8)


def capacity_bytes(image_path: str) -> int:
    """How many *payload* bytes this image can hold (excluding our header)."""
    arr = _load_rgb(image_path)
    total_bits = arr.size            # 1 usable bit per channel value
    return total_bits // 8 - HEADER_LEN


def _bytes_to_bits(data: bytes) -> np.ndarray:
    """Expand bytes into a flat array of bits (MSB first)."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def embed(image_path: str, payload: bytes, out_path: str) -> None:
    """Hide ``payload`` inside the image and save the result to ``out_path``."""
    arr = _load_rgb(image_path)
    flat = arr.reshape(-1)           # 1-D view of every channel value

    header = MAGIC + len(payload).to_bytes(4, "big")
    full = header + payload
    bits = _bytes_to_bits(full)

    if bits.size > flat.size:
        need = bits.size // 8
        have = flat.size // 8
        raise CapacityError(
            f"Message needs {need} bytes but image only holds {have} bytes. "
            "Use a larger image or a shorter message."
        )

    # Clear the last bit of the first len(bits) channels, then set our bits.
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits.astype(np.uint8)

    out = flat.reshape(arr.shape)
    Image.fromarray(out, "RGB").save(out_path, format="PNG")


def extract(image_path: str) -> bytes:
    """Recover a payload previously stored by :func:`embed`."""
    arr = _load_rgb(image_path)
    flat = arr.reshape(-1)

    # Read the header first so we know how many data bits to pull.
    header_bits = flat[:HEADER_LEN * 8] & 1
    header = np.packbits(header_bits).tobytes()

    if header[:len(MAGIC)] != MAGIC:
        raise NoHiddenDataError(
            "No StegoVault message found in this image "
            "(missing marker - it may be an ordinary image)."
        )

    length = int.from_bytes(header[len(MAGIC):HEADER_LEN], "big")
    total_bits = (HEADER_LEN + length) * 8
    if total_bits > flat.size:
        raise NoHiddenDataError("Hidden length is corrupt or image was altered.")

    data_bits = flat[HEADER_LEN * 8:total_bits] & 1
    return np.packbits(data_bits).tobytes()
