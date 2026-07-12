# Project Upgrades — What We Had vs. What Was Added

This document records the state of the NIDS project before and after the upgrade pass,
so reviewers can see exactly what the original build delivered and what was improved on top of it.

---

## 1. What We Had (Original Build)

- **Streamlit dashboard** with three modes: Simulator (replays UNSW-NB15 CSV records), Offline PCAP audit (NFStream), and Live interface capture.
- **Binary XGBoost classifier** (Attack / Normal) trained on UNSW-NB15, stored as a Python pickle.
- **Custom NFStream `SecurityPlugin`** extracting TCP handshake timing (RTT, SYN-ACK, ACK-DAT), TTLs, and window sizes from raw packets.
- **`FlowMemory` sliding window** (last 100 flows) computing UNSW-NB15 connection-count features (`ct_srv_dst`, `ct_dst_src_ltm`, …) in real time.
- **Flow inspector** showing all engineered features per flow.
- Dark cyber-themed UI with metric tiles, timeline chart, service distribution chart, and alert tables.

---

## 2. Problems Found & Fixed

### 🐛 Fix 1 — Benign traffic was flagged as attacks (critical)
A clean DNS lookup was classified **ATTACK with 99.96% confidence**. Root cause: UNSW-NB15 is
a lab-generated dataset where attack traffic used fixed TTL values and constant TCP window
sizes. Features like `sttl`, `dttl`, `ct_state_ttl`, `swin`, `dwin`, `stcpb`, `dtcpb` are
near-perfect class separators *inside the dataset* but are pure artifacts — real traffic has
different TTL distributions, so the model misfired on everything live.

**Fix:** retrained without the 7 artifact features. Benchmark accuracy dropped only
**0.05 percentage points** (86.81% → 86.76%), while the live false-positive problem disappeared:
the same DNS flow now scores **NORMAL at 99.96% confidence**. This robustness-over-leaderboard
tradeoff is documented in the in-app Model Performance page.

### 🐛 Fix 2 — Model version skew (reliability)
The model and encoders were pickled with scikit-learn 1.3 / an older XGBoost; loading them on
newer versions produced explicit "results may be invalid" warnings.

**Fix:** models are now saved in **XGBoost's native JSON format** (`xgboost_network_model.json`),
which is version-independent by design, and the encoders were regenerated with the current
scikit-learn. A reproducible `train_model.py` script replaces the untracked notebook state —
anyone can rebuild every artifact with one command.

### 🐛 Fix 3 — Swapped dataset files / demo leakage (integrity)
`data/NB_testing-set.csv` (175,341 rows) is actually the official UNSW-NB15 **training** split,
and `NB_training-set.csv` (82,332 rows) is the **testing** split. The original simulator streamed
the 175k file — i.e., the model was being demoed on **its own training data**.

**Fix:** training now uses the 175k split and the simulator + all reported metrics use the 82k
**held-out** split the model has never seen. Every number shown is genuine generalization.

### 🐛 Fix 4 — Prediction/probability mismatch
`label` came from `model.predict()` while the confidence came from `predict_proba()`, which can
disagree at the boundary. The label is now derived directly from the probability (`prob >= 0.5`).

---

## 3. What Was Added (New Capabilities)

### 🎯 Attack-type classification (multi-class model)
A second XGBoost model identifies **which of 10 UNSW-NB15 attack categories** a malicious flow
belongs to — Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor, Shellcode,
Worms — at **75.7% accuracy** across 10 classes. Alerts no longer just say "attack"; they say
*what kind* of attack.

### 🧠 Explainable AI (per-flow SHAP-style explanations)
Every flow in the inspector now has a **"Why did the model decide this?"** chart: the exact
per-feature contributions from the XGBoost trees (`pred_contribs`), showing which features
pushed the decision toward ATTACK (red) and which toward NORMAL (green). Judges can pick any
alert and see the model justify itself — no black box.

### ⚠️ Severity triage
Alerts are ranked 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW based on attack category (DoS, Exploits,
Backdoor, Shellcode, Worms ⇒ high) and model confidence, mirroring how a real SOC prioritizes.

### 📊 Model Performance Report page (in-app)
A new dashboard mode showing honest, held-out evaluation: accuracy / precision / recall /
ROC-AUC tiles, an interactive confusion matrix, top-15 feature importances, the full per-class
precision/recall table for the attack categorizer, and an explanation of the artifact-feature
tradeoff. **Evaluated on 82,332 unseen flows:** 86.8% accuracy, 97.9% attack detection rate
(recall), 0.981 ROC-AUC.

### 📥 CSV report export
One-click download of the full flow report and the alerts-only report from the simulator and
PCAP modes — the audit leaves with you.

### 📱 Mobile-responsive UI
The dashboard now adapts to phones and tablets: metric tiles reflow into a 2×2 grid (single
column under 480px), the glowing title scales down, columns stack vertically, and page padding
tightens so tables use the full width.

### 🔁 Reproducible training pipeline
`train_model.py` rebuilds every artifact (both models, encoders, feature list, metrics) from the
raw CSVs in one command, and prints a side-by-side comparison of the full-feature vs.
robust-feature models.

### 🖥️ Cross-platform capture engine (Windows + Linux)
NFStream does not build on Windows, so the original PCAP and live-capture modes were
Linux-only. A new pure-Python **Scapy fallback engine** (`packet_engine.py`) reproduces the
NFStream flow interface — bidirectional 5-tuple aggregation, TCP handshake timing
(SYN→SYN/ACK→ACK), TTLs, window sizes, inter-packet timing statistics — so **Offline PCAP
analysis now works on Windows out of the box**, and live capture works too when
[Npcap](https://npcap.com) is installed. The app picks the best available engine automatically
and shows which one is active.

Additional artifact discovery during this work: `tcprtt`, `synack` and `ackdat` were found to
encode *lab topology* (UNSW normal traffic ran on a ~0.1 ms LAN; attack traffic on ~60 ms
paths), so any real internet flow looked "attack-like". They joined the dropped-features list —
total benchmark cost of all 10 dropped artifact features: **0.2 percentage points**.

### 🐧 Automated Linux testing (GitHub Actions)
Every push to `main` runs a full Linux test suite on GitHub's Ubuntu runners
(`.github/workflows/linux-test.yml`): installs NFStream from Linux wheels, runs the CLI
pipeline, generates the synthetic capture, parses it with **both** engines (NFStream and
Scapy), pushes every flow through the models, and asserts that benign DNS stays NORMAL and
the SYN scan is detected. Windows can't run NFStream locally — CI proves the Linux path on
every commit instead.

### 🧪 Synthetic test capture + generator
`make_test_pcap.py` produces `data/test_traffic.pcap` — benign flows statistically matched to
UNSW-NB15 normal medians (DNS lookup, full HTTP session with realistic sizes, latency and
bursty jitter) plus a 10-port SYN scan. Used by CI and handy for live demos of the PCAP mode.

### 🐳 Docker deployment
A `Dockerfile` ships the full Linux stack (NFStream included) for one-command deployment:
`docker build -t nids . && docker run --rm -p 8501:8501 nids`.

---

## 4. Final Model Scorecard (held-out 82,332 flows)

| Metric | Binary model (shipped) |
|---|---|
| Accuracy | 86.76% |
| Precision | 81.72% |
| Recall (detection rate) | **97.85%** |
| F1 score | 89.06% |
| ROC-AUC | 0.981 |
| Missed attacks | 973 of 45,332 (2.1%) |

| Attack categorizer | 75.7% accuracy over 10 classes |
|---|---|

*All numbers are reproducible via `py train_model.py`.*
