"""
guard/checks/normalize.py  --  turn a string into the form we actually check.

Why: attackers hide "../" from naive filters by encoding it (%2e%2e%2f), double-encoding it
(%252e%252e%252f), or using look-alike Unicode characters (fullwidth dots and slashes).
The rule from the brief is: normalize FIRST, then validate the normalized value.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

# How many decode rounds we try before giving up. Real input never needs more than 1-2.
MAX_ROUNDS = 5


@dataclass(frozen=True)
class Normalized:
    value: str                 # the fully decoded + normalized string (null bytes removed)
    decode_layers: int         # how many times %xx decoding changed the string
    flags: tuple[str, ...]     # signals seen: "null_byte", "unicode_changed", "decode_limit_reached"


def normalize_text(raw: str) -> Normalized:
    """
    Repeat until the string stops changing:
      1. URL-decode (%2e -> .)            -> counts as one "encoding layer"
      2. drop null bytes (flag them)      -> "file.txt\\x00.png" tricks
      3. Unicode NFKC (fullwidth . -> .)  -> look-alike characters
    More than one layer of encoding is almost never legitimate, so we report the count and let
    the caller decide (the path check blocks above a configurable limit).
    """
    flags: set[str] = set()
    value = raw
    layers = 0
    for _ in range(MAX_ROUNDS):
        step = unquote(value)
        decoded = step != value
        if "\x00" in step:
            flags.add("null_byte")
            step = step.replace("\x00", "")
        nfkc = unicodedata.normalize("NFKC", step)
        if nfkc != step:
            flags.add("unicode_changed")
        if nfkc == value:          # nothing changed this round -> stable, stop
            break
        if decoded:
            layers += 1
        value = nfkc
    else:                          # loop never stabilised: suspicious, tell the caller
        flags.add("decode_limit_reached")
    if "\x00" in raw:
        flags.add("null_byte")
    return Normalized(value.replace("\x00", ""), layers, tuple(sorted(flags)))
