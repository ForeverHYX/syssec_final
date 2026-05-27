"""Small binary-analysis helpers."""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import re


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def sha256_hex(data: bytes) -> str:
    """Return a stable SHA-256 digest for report evidence."""

    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Compute byte-level Shannon entropy."""

    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract ASCII printable strings from arbitrary binary data."""

    if min_length < 1:
        raise ValueError("min_length must be positive")
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode("ascii") + rb",}")
    strings: list[str] = []
    for match in pattern.finditer(data):
        strings.append(match.group(0).decode("ascii", errors="ignore"))
    return strings

