# Changelog

## [5.0.0] - 2026-11-09

### Added
- Sigma correlation subset (Sigma spec 2.1.0): event_count,
  value_count, temporal, temporal_ordered over sliding
  windows with grouping; aggregation correlations rejected
  by name. Shipped example over the vssadmin base rule.
- Human-promoted behaviour chains: PrefixSpan candidates stay
  behind their type wall; promotion records must name the
  mined pattern, its support, and a human approver, and the
  loader refuses unsigned promotions.
- Calibration round 2: per-format Mondrian conditioning with
  honest global fallback for small groups, and adaptive
  conformal inference (level adaptation plus history refits)
  whose guarantee is stated as long-run coverage only, with
  worst-window coverage reported beside it.
- Provenance evidence: Zone.Identifier and user/com.apple
  extended attributes attached to scan_file verdicts, never
  scored, with a test pinning score invariance (which caught
  and fixed a verdict-cache pollution bug).
- EVTX chunk inventory with CRC-32 tamper tripwires
  (BinXml rendering out of scope and stated).
- JAR/APK signing triage: v1 manifest digests recomputed,
  .SF manifest digest checked, APK v2 block signers named
  (naming, never trust).
- mmap scanning with the empty-file and changed-during-scan
  cases specified; a published worker-scaling curve.
- inotify watch backend (Linux), shipped under its kill
  criterion: it lives only while the shared semantics suite
  passes in CI. Polling remains the default.

### Not implemented, by decision
- OneNote parsing: the research kill criterion triggered
  (spec revision unpinned, no independent fixture writer).
  Identification by header GUID only; docs/onenote_decision.md
  records what would revive it.

### Measured
- Hold-out families A/B/C (seeds 20280101-3), each scored
  exactly once: TP 4, FP 0, FN 1, TN 6 per family; every miss
  is the high-entropy fixture, the standing entropy boundary.
- 10k corpus: 1,068 files/sec parallel (4 workers), single
  process median 0.41 ms per file; fixture accounting
  identical (375 of 500). Worker scaling on this 1.5-vCPU VM
  inverts: 1 worker is fastest (1,654 files/sec), published
  as measured.

## [4.0.0] - 2026-11-09

### Added
- Parser fuzzing round 2 (field-aware mutator, zero crashes over
  the campaign) and per-parser constant-mutation scores in the
  test suite, with the PDF module's low score published and
  covered by boundary tests instead of a lowered floor.
- ClamAV differential harness (Mode A: equal-knowledge custom
  database, per-string hits through Aegis's conditions, named
  disagreement buckets, unexplained == 0 gate). Verified end to
  end against a contract stub; a real-clamscan run is pending
  an environment that has one, and the harness says so.
- Script deobfuscation-lite: bounded pure transforms (Base64,
  UTF-16LE EncodedCommand form, [char] arrays, Chr() chains,
  concatenation, backticks, hex escapes) with every recovered
  layer re-matched; encoding alone never scores.
- Delivery formats: LNK (arguments handed to the script
  analyser), EML/MIME attachments sub-scanned, RTF objdata
  extraction and sub-scan, ISO 9660 + Joliet member scanning.
- Streaming hex parity: hex rules evaluated exactly in
  scan_stream via bounded carry windows; a first-chunk format
  identification bug at tiny chunk sizes found and fixed.
- Delivery rule pack under full lint, FP-budget, and mutation
  discipline (score 1.0); daemon hardening (constant-time
  token comparison, 16 MiB body cap, JSONL audit log);
  single-file escaped HTML reports via `aegis report`.

### Measured
- Hold-out families A/B/C (seeds 20270101-3), each scored
  exactly once: TP 4, FP 0, FN 1, TN 6 per family; every miss
  is the high-entropy fixture, the standing entropy boundary.
- 10k corpus: 1,280 files/sec parallel (v3: 1,861), single
  process median 0.36 ms per file. The slowdown is the v4
  per-file script-layer analysis on a text-heavy corpus and
  is reported, not hidden. Fixture accounting identical:
  375 of 500 flagged, the 125 unflagged exactly the
  random-bytes class.

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
