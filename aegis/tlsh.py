"""TLSH (Trend Micro Locality Sensitive Hash), T1 variant.

A faithful pure-Python port of the reference algorithm
(128 buckets, 1-byte checksum, 5-byte sliding window), built
directly from the reference implementation's published source:
the Pearson permutation table, the six salted trigram mappings,
the quartile code construction, the topval length table, and the
totalDiff distance with its length and q-ratio multipliers.
Apache-2.0 / BSD licensed upstream; this port keeps the same
constants so digests are comparable in structure and distance
semantics.

Verification status, stated plainly: the bucket semantics
(256 counters, first 128 effective) were cross-checked against
two independent implementations, the reference C++ and the Go
port, which agree with each other on every constant used here,
including the Q-ratio nibble order once the reference's
nibble-swap serialisation is accounted for. The length table is
cross-checked in tests against the closed-form formula the
reference replaced it with, digests are property-tested
(deterministic, self-distance zero, near files closer than far
files, parse round-trips), and one regression known-answer
digest from this implementation is pinned in the tests. A
byte-exact digest comparison against the reference binary on
its published test corpus remains the one open item and is
labelled as such wherever it matters.
"""
from __future__ import annotations

import bisect
import math
from collections import deque

MIN_LENGTH = 50
BUCKETS = 256        # counters: the full Pearson output range
EFF_BUCKETS = 128    # only the first 128 feed quartiles and code
CODE_SIZE = 32

V_TABLE = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
]

TOPVAL = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656,
    854, 1110, 1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088,
    5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998, 13198,
    14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121,
    34233, 37656, 41422, 45564, 50121, 55133, 60646, 66711, 73382,
    80721, 88793, 97672, 107439, 118183, 130002, 143002, 157302,
    173032, 190335, 209369, 230306, 253337, 278670, 306538, 337191,
    370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800,
    795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534,
    1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836,
    3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905,
    5883796, 6472176, 7119394, 7831333, 8614467, 9475909, 10423501,
    11465851, 12612437, 13873681, 15261050, 16787154, 18465870,
    20312458, 22343706, 24578077, 27035886, 29739474, 32713425,
    35984770, 39583245, 43541573, 47895730, 52685306, 57953837,
    63749221, 70124148, 77136564, 84850228, 93335252, 102668779,
    112935659, 124229227, 136652151, 150317384, 165349128, 181884040,
    200072456, 220079703, 242087671, 266296456, 292926096, 322218735,
    354440623, 389884688, 428873168, 471760495, 518936559, 570830240,
    627913311, 690704607, 759775136, 835752671, 919327967, 1011260767,
    1112386880, 1223623232, 1345985727, 1480584256, 1628642751,
    1791507135, 1970657856, 2167723648, 2384496256, 2622945920,
    2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
]

# (salt, index of second byte, index of third byte) into the
# 5-byte window counted from the OLDEST byte (0) to newest (4);
# the first byte is always the newest (4). From the reference
# update loop for a 5-byte window.
_TRIGRAMS = [(49, 3, 2), (12, 3, 1), (178, 2, 1),
             (166, 2, 0), (84, 3, 0), (230, 1, 0)]


def _fbm(salt: int, i: int, j: int, k: int) -> int:
    return V_TABLE[V_TABLE[V_TABLE[salt ^ i] ^ j] ^ k]


def _l_capturing(length: int) -> int:
    idx = bisect.bisect_left(TOPVAL, length)
    return min(idx, 255)


def l_capturing_formula(length: int) -> int:
    """The closed form the reference's table replaced; used in
    tests to cross-validate the embedded table."""
    if length <= 656:
        i = math.floor(math.log(length) / 0.4054651)
    elif length <= 3199:
        i = math.floor(math.log(length) / 0.26236426 - 8.72777)
    else:
        i = math.floor(math.log(length) / 0.095310180 - 62.5472)
    return i & 0xFF


def _swap_byte(b: int) -> int:
    return ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)


def tlsh_digest(data: bytes) -> str | None:
    if len(data) < MIN_LENGTH:
        return None
    buckets = [0] * BUCKETS
    checksum = 0
    window: deque[int] = deque(maxlen=5)
    for byte in data:
        window.append(byte)
        if len(window) < 5:
            continue
        w = list(window)  # oldest .. newest
        checksum = _fbm(1, w[4], w[3], checksum)
        for salt, a, b in _TRIGRAMS:
            buckets[_fbm(salt, w[4], w[a], w[b])] += 1
    effective = buckets[:EFF_BUCKETS]  # reference behaviour, cross-
    # checked against the reference C++ and the Go port: counters
    # 128..255 are maintained but never read downstream
    ordered = sorted(effective)
    q1, q2, q3 = ordered[31], ordered[63], ordered[95]
    if q3 == 0:
        return None
    if sum(1 for v in effective if v > 0) <= 4 * CODE_SIZE // 2:
        return None
    code = bytearray()
    for i in range(CODE_SIZE):
        h = 0
        for j in range(4):
            k = effective[4 * i + j]
            if k > q3:
                h += 3 << (j * 2)
            elif k > q2:
                h += 2 << (j * 2)
            elif k > q1:
                h += 1 << (j * 2)
        code.append(h)
    lvalue = _l_capturing(len(data))
    q1ratio = (q1 * 100 // q3) % 16
    q2ratio = (q2 * 100 // q3) % 16
    qbyte = q1ratio | (q2ratio << 4)
    raw = bytes([_swap_byte(checksum), _swap_byte(lvalue),
                 _swap_byte(qbyte)]) + bytes(reversed(code))
    return "T1" + raw.hex().upper()


def _parse(digest: str) -> tuple[int, int, int, int, bytes]:
    s = digest.strip()
    if s.startswith("T1"):
        s = s[2:]
    raw = bytes.fromhex(s)
    if len(raw) != 35:
        raise ValueError("bad TLSH digest length")
    checksum = _swap_byte(raw[0])
    lvalue = _swap_byte(raw[1])
    qbyte = _swap_byte(raw[2])
    code = bytes(reversed(raw[3:]))
    return checksum, lvalue, qbyte & 0xF, qbyte >> 4, code


def _mod_diff(x: int, y: int, r: int) -> int:
    if y > x:
        dl, dr = y - x, x + r - y
    else:
        dl, dr = x - y, y + r - x
    return dr if dl > dr else dl


def _pair_cost(a: int, b: int) -> int:
    d = abs(a - b)
    return 0 if d == 0 else 1 if d == 1 else 2 if d == 2 else 6


def _byte_diff(x: int, y: int) -> int:
    total = 0
    for shift in (6, 4, 2, 0):
        total += _pair_cost((x >> shift) & 3, (y >> shift) & 3)
    return total


def tlsh_distance(a: str, b: str, include_length: bool = True) -> int:
    ca, la, q1a, q2a, codea = _parse(a)
    cb, lb, q1b, q2b, codeb = _parse(b)
    diff = 0
    if include_length:
        ld = _mod_diff(la, lb, 256)
        diff += 0 if ld == 0 else 1 if ld == 1 else ld * 12
    for qa, qb in ((q1a, q1b), (q2a, q2b)):
        qd = _mod_diff(qa, qb, 16)
        diff += qd if qd <= 1 else (qd - 1) * 12
    if ca != cb:
        diff += 1
    diff += sum(_byte_diff(x, y) for x, y in zip(codea, codeb))
    return diff
