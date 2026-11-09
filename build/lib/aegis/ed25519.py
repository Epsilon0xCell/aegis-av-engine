"""Pure-Python Ed25519 (RFC 8032), for rule-pack signing.

The standard library has no Ed25519, and this project is
dependency-free by design, so the primitive is implemented here
from the RFC 8032 reference algorithm and verified against the
RFC 8032 test vectors in the test suite. It signs rule-pack
manifests only: a handful of verifications per pack load, where
pure Python speed is irrelevant. It is NOT a general-purpose
crypto library and must not be reused for high-volume signing.
"""
from __future__ import annotations

import hashlib

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)
_IDENTITY = (0, 1)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    t = _D * x1 * x2 * y1 * y2 % _Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _Q - 2, _Q)
    return x3 % _Q, y3 % _Q


def _scalarmult(P, e: int):
    if e == 0:
        return _IDENTITY
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def publickey(seed32: bytes) -> bytes:
    h = _sha512(seed32)
    a = 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


def _hint(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little")


def signature(message: bytes, seed32: bytes, pk: bytes) -> bytes:
    h = _sha512(seed32)
    a = 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))
    r = _hint(h[32:64] + message) % _L
    R = _scalarmult(_B, r)
    S = (r + _hint(_encodepoint(R) + pk + message) * a) % _L
    return _encodepoint(R) + _encodeint(S)


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes) -> tuple[int, int]:
    bits = [(s[i // 8] >> (i % 8)) & 1 for i in range(256)]
    y = sum(2 ** i * bits[i] for i in range(255))
    x = _xrecover(y)
    if x & 1 != bits[255]:
        x = _Q - x
    return x, y


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def checkvalid(sig: bytes, message: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
    except Exception:
        return False
    if not _isoncurve(R) or not _isoncurve(A):
        return False
    S = _decodeint(sig[32:])
    if S >= _L:
        return False
    h = _hint(sig[:32] + pk + message) % _L
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
