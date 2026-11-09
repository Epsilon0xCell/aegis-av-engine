# Aegis AV Engine

**Version 1.0.0.** What grew since 0.1.0, each subsystem tested
and documented: safe container scanning under one shared budget,
deep PE/ELF/Mach-O parsers, a rule language with hex patterns and
condition ASTs plus a pack linter with per-rule fixtures, signed
rule packs (pure-Python Ed25519 verified against the RFC 8032
vectors) with rollback protection, a loopback daemon API and a
notify-only watch mode (user-space: scanning and notification,
never blocking), an explainable integer scoring module that is
off by default and capped at suspicious, Navigator/STIX/SARIF
exports, a sealed hold-out protocol with its first result
published verbatim in BENCHMARK.md (including the miss), and a
5-run median/IQR release benchmark. 37 tests, three-OS CI.

An open, cross-platform antivirus scanning and analysis engine for
education and research, by Gavin Blacklock (Epsilon0xCell).

EDUCATIONAL AND DEFENSIVE USE ONLY. Read DISCLAIMER.md and
RESPONSIBLE_USE.md. Template disclaimers, not legal advice.

## What Aegis is

A layered scanning engine in pure Python (standard library only),
running identically on Windows, macOS and Linux:

- bloom-filtered exact hash reputation and a verdict cache
- an Aho-Corasick multi-pattern string engine
- PE, ELF and Mach-O format identification and static features
- a transparent heuristic scorecard: named, weighted, inspectable
  evidence for every point of every score
- a fuzzy digest for near-duplicate matching
- an ATT&CK behavioural telemetry correlator
- quarantine and restore with receipts
- a benchmark harness that labels every number with its corpus

## What Aegis competes on, honestly

Commercial engines (Bitdefender, Kaspersky, Microsoft Defender,
Malwarebytes) detect real malware at 99.6 to 99.98 percent in
independent lab tests, powered by global telemetry and machine
learning at a scale no solo project replicates, and this README
will not pretend otherwise. Aegis competes on the axes a focused
open engine can measure and win, and only those, under the binding
protocol in BENCHMARK.md: offline determinism, throughput on a
defined corpus, 100 percent evidence-backed explainable verdicts,
false-positive control on a published clean corpus, identical
verdicts across the three operating systems, and zero telemetry.

## Corpora: no real malware

Detection numbers here come from a generated clean corpus and
synthetic, inert malicious-pattern fixtures created for this
project, plus the EICAR test file. There is no real malware in
this repository, in its tests, or in its history.

## Quick start

    pip install -e ".[dev]"
    aegis demo
    aegis scan path/to/file-or-folder
    pytest -q

`aegis demo` generates the corpora and prints a labelled benchmark
report; `aegis benchmark` also writes benchmarks/results_local.json.

## Author

Gavin Blacklock (Epsilon0xCell). A solo public project: design,
engine, rules, benchmarks and documentation.
