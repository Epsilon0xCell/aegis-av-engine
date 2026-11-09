# Model card: Aegis static scoring module

- **What it is:** an integer linear model over `aegis-features@1.0.0`, computed from this engine's own parsers. Off by default. Ceiling: it can flag a file SUSPICIOUS and can never convict.
- **Why integer weights:** every contribution is exact and sums to the score. No approximate explanation method is used or claimed.
- **Training data:** none. Weights are hand-set from published detection-engineering practice and this project's fixtures. This is a scorecard with a feature set, not a learned model, and it is not described otherwise anywhere in this project.
- **Evaluation:** measured only on this project's generated corpora (clean, fixtures, hold-out when released). No claim is made about real-world malware, which this project never handles.
- **Known limits:** hand-set weights encode the author's judgement and will mis-rank unusual files; entropy-driven features punish packed and compressed legitimate files; evaluation on self-generated corpora cannot measure dataset shift. The TESSERACT research (Pendlebury et al.) showed biased evaluation can inflate malware-ML results substantially; treat any score-based claim from any vendor, including this module's fixture numbers, with that warning attached.
