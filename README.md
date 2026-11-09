# Aegis AV Engine

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
