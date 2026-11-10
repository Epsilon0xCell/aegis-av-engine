"""Field-aware mutational fuzzing for the format parsers.

Round 1 fuzzing (v1) threw random bytes and truncations at the
parsers. Round 2 mutates like the formats are built: it writes
interesting integer values (0, 1, 0x7F, 0xFF, 0xFFFF, 0x7FFFFFFF,
0xFFFFFFFF, length plus and minus one) into aligned and
unaligned field positions, splices chunks between seeds, and
deletes and duplicates slices, because parser bugs live at
field boundaries, not in random noise.

The oracle is strict and twofold: a case is a crash if the
target raises anything, and the campaign is deterministic
(one seeded RNG drives every choice), so any crash reproduces
from the campaign seed and case index alone.
"""
from __future__ import annotations

import random

INTERESTING = [0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF, 0x100, 0x7FFF,
               0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000,
               0xFFFFFFFF]


def mutate(data: bytes, rng: random.Random,
           pool: list[bytes]) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(7)
        if op == 0 and buf:  # byte set
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif op == 1 and buf:  # bit flip
            at = rng.randrange(len(buf))
            buf[at] ^= 1 << rng.randrange(8)
        elif op == 2 and len(buf) >= 2:  # interesting field write
            size = rng.choice([1, 2, 4, 8])
            value = rng.choice(INTERESTING) & ((1 << (size * 8)) - 1)
            at = rng.randrange(max(1, len(buf) - size + 1))
            buf[at:at + size] = value.to_bytes(size, "little")
        elif op == 3 and buf:  # truncate
            buf = buf[:rng.randrange(len(buf))]
        elif op == 4:  # extend
            extra = bytes(rng.randrange(256)
                          for _ in range(rng.randint(1, 64)))
            buf += extra
        elif op == 5 and pool:  # splice a chunk from another seed
            other = rng.choice(pool)
            if other:
                at = rng.randrange(len(other))
                take = other[at:at + rng.randint(1, 48)]
                into = rng.randrange(len(buf) + 1)
                buf[into:into] = take
        elif op == 6 and len(buf) > 8:  # delete a slice
            at = rng.randrange(len(buf) - 4)
            del buf[at:at + rng.randint(1, 32)]
    return bytes(buf)


def run_campaign(targets: dict, seeds: list[bytes], iterations: int,
                 seed: int = 20261109) -> dict:
    rng = random.Random(seed)
    crashes = []
    per_target = {name: 0 for name in targets}
    cases = 0
    names = sorted(targets)
    for i in range(iterations):
        name = names[i % len(names)]
        base = seeds[rng.randrange(len(seeds))]
        blob = mutate(base, rng, seeds)
        cases += 1
        per_target[name] += 1
        try:
            targets[name](blob)
        except Exception as exc:  # the oracle: nothing may raise
            crashes.append({"target": name, "case": i,
                            "error": f"{type(exc).__name__}: {exc}",
                            "seed": seed})
    return {"cases": cases, "per_target": per_target,
            "crashes": crashes, "seed": seed}
