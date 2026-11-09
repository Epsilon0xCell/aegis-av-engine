# Changelog

## [3.0.0] - 2026-11-09

### Added
- Measurement integrity pack: corpus property registry (the v2
  generator bug as a regression test), pack mutation score 1.0
  over non-equivalent mutants, prevalence-adjusted reporting,
  per-stage engine profiling.
- CFB/OLE2 parser and MS-OVBA macro inventory with source
  recovery; PDF structural triage (hex-escaped names, object
  streams, action inventory); PE delay imports, debug/PDB,
  TLS callbacks; .NET metadata triage (ECMA-335); Authenticode
  signer identity extraction.
- YARA-subset importer with whole-rule loud rejection;
  per-rule false-positive budgets enforced in CI.
- PrefixSpan mining (candidates only, type-separated from
  detection), TUF-lite signed pack updates, witness
  cosignatures, CycloneDX SBOM from the release zip,
  convenience frozen binaries (spec + workflow, smoke-tested).

### Changed
- TLSH is computed lazily (non-clean verdicts or on demand);
  measured at 2.3 ms per file standalone, it was over half the
  scan. 10k-corpus parallel throughput rose from 310 to 1,861
  files per second with identical fixture accounting.

### Hold-out (three sealed families, each scored once)
- Families A, B, C: TP 4, FP 0, FN 1, TN 6 each. Every miss is
  the high-entropy fixture: the standing boundary that unknown
  formats are not convicted on entropy alone, unchanged.

All notable changes to Aegis AV Engine. Versions follow
Semantic Versioning; the rule pack and feature set carry their
own version strings inside verdicts.

## [2.0.0] - 2026-11-09

### Added
- Loaded versus residual views, segmented entropy, and a
  dilution heuristic that flags padding attacks on the entropy
  average; streaming scan core with chunk-size equivalence
  tests.
- Section hashes, imphash, a cross-checked pure-Python TLSH,
  and a persistent SQLite verdict cache with a composite key
  that cannot serve stale verdicts.
- Conformal calibration for the scoring module with an ABSTAIN
  band (ambiguous versus novel), risk-coverage reporting, and a
  structural calibration corpus. A degenerate first calibration
  artifact was caught and replaced; see BENCHMARK.md.
- OOXML relationship analysis (external relationships, remote
  template injection T1221, macro projects), Authenticode
  image-hash recomputation with stored-digest comparison, PE
  resource-tree parsing, Mach-O code-signature page-hash
  verification, and ELF note and build-id extraction.
- Behavioural chain analysis with weighted partial credit and
  order sensitivity; a Sigma-subset importer (JSON form) that
  rejects unsupported constructs by name; an RFC 6962 Merkle
  transparency log for pack manifests with signed tree heads;
  deterministic multiprocess scanning.
- Hold-out releases 2 and 3, a 10,000-file corpus benchmark,
  and a reproducible source zip built and compared twice in
  the release workflow with build-provenance attestation.

### Fixed
- The fixture corpus generator's high-entropy fixture had
  entropy 0.0 (a fresh Random instance per byte). The bug
  survived three releases disguised as a detector miss;
  root-caused by the release-2 hold-out and covered by a
  property test. BENCHMARK.md carries the correction.

## [1.0.0] - 2026-11-09

First full release: layered scanning pipeline, archive budget
and in-memory container scanning, deep PE, ELF, and Mach-O
parsers, hex-pattern rule language with linter, Ed25519-signed
rule packs with rollback refusal, loopback daemon and polling
watch (user-space, notify-only), explainable integer scoring
(off by default, capped at suspicious), ATT&CK Navigator, STIX
2.1 subset, and SARIF exports, hold-out protocol with release
1 scored once, and a 5-run benchmark. 37 tests, three-OS CI.
