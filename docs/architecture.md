# Aegis architecture

Pipeline, in order, earliest exit first:

1. Ingest and identify (aegis/formats.py): magic-based format ID
   for PE, ELF, Mach-O thin and fat, PDF, ZIP containers, scripts.
2. Exact reputation (aegis/hashing.py): SHA-256 and MD5 digests,
   a bloom pre-filter in front of the known-bad set, and a verdict
   cache keyed by hash, which is also the determinism mechanism.
3. String engine (aegis/strings_engine.py): Aho-Corasick, one pass,
   all rule patterns at once, cost independent of pattern count.
4. Static features and heuristic scorecard (aegis/rules.py): a
   small set of PE features plus entropy analysis, scored through
   named, weighted, inspectable contributions. No opaque model in
   the default path.
5. Fuzzy digest (aegis/hashing.py): a documented ssdeep-style
   digest for near-duplicate fixture matching.
6. Behavioural correlator (aegis/behaviour.py): ATT&CK chains over
   JSONL telemetry, convicting on chains, not single events.
7. Verdict and remediation (aegis/engine.py, aegis/quarantine.py):
   every verdict is a JSON object carrying its full evidence, and
   quarantine moves files with signed receipts and a restore path.

Cross-platform: pure Python standard library, no native code, no
platform APIs in the engine. The same bytes produce the same
verdict on Windows, macOS and Linux, which the three-OS CI matrix
verifies on every push. On-access blocking is out of scope by
design (see the research summary in docs/competitive_research.md):
each OS reserves that for signed, entitled system components, and
a public scanning engine gains nothing by pretending otherwise.
