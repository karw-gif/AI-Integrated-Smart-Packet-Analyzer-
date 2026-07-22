# 🛡️ AI Integrated Smart Packet Analyzer (NIDS)

**A real-time, machine-learning-powered Network Intrusion Detection System** that watches network traffic, decides in milliseconds whether each connection is normal or an attack, names the *type* of attack, explains *why* it made that decision — and shows it all on a live dashboard.

Built as a Cybersecurity Final Year Project using **Python, XGBoost, NFStream/Scapy, and Streamlit**, trained on the **UNSW-NB15** intrusion detection dataset.

---

## 1. The Problem (in plain words)

Every device on a network constantly opens *connections* — to websites, DNS servers, email servers. Hidden among those millions of normal connections, attackers run port scans, denial-of-service floods, exploits, and backdoors.

Traditional firewalls use fixed rules ("block port 23"). Rules can't catch attacks that *look* like normal traffic. **This project instead teaches a machine-learning model what attacks look like statistically** — how many packets they send, how fast, in which patterns — so it can flag brand-new malicious connections it has never seen before.

---

## 2. What the System Does

| Capability | What it means |
|---|---|
| 🔍 **Classifies every network flow** | Each connection is scored ATTACK or NORMAL with a confidence percentage |
| 🎯 **Names the attack type** | A second model identifies the category: DoS, Exploits, Reconnaissance, Fuzzers, Backdoor, Shellcode, Worms, Generic, Analysis |
| ⚠️ **Ranks severity** | Alerts are triaged 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW, like a real Security Operations Center |
| 🧠 **Explains itself** | For any flow, a chart shows exactly which features pushed the decision toward "attack" (red) or "normal" (green) — no black box |
| 📊 **Proves its accuracy** | A built-in Model Performance page shows the confusion matrix, precision/recall per attack class, and ROC-AUC on data the model never trained on |
| 📥 **Exports reports** | One-click CSV download of all flows and alerts |
| 📱 **Works on any screen** | The dashboard is fully responsive, phone to desktop |

---

## 3. The Four Dashboard Modes

1. **🖥️ Simulator (Demo Mode)** — replays 82,332 real traffic records from the UNSW-NB15 *held-out test set* through the live pipeline. Perfect for demos: no special permissions needed, works anywhere.
2. **📂 Offline PCAP Analysis** — upload any `.pcap`/`.pcapng` capture file (e.g. from Wireshark) and get a full security audit: threat distribution, alerts table, per-flow inspection.
3. **🔌 Live Interface Capture** — listens on a real network interface (Wi-Fi/Ethernet) and classifies traffic *as it happens*. Verified live on Linux Wi-Fi.
4. **📊 Model Performance Report** — the honest scorecard: every metric computed on 82,332 flows the model never saw during training.

---

## 4. How It Works (Architecture)

```
 Packets on the wire
        │
        ▼
 ┌─────────────────────────────┐   NFStream (Linux/macOS — Deep Packet Inspection)
 │  1. CAPTURE ENGINE          │   or Scapy engine (Windows — pure Python)
 │  packets → "flows"          │   The app auto-selects whichever is available.
 └─────────────┬───────────────┘
               ▼
 ┌─────────────────────────────┐   feature_extractor.py maps each flow to the
 │  2. FEATURE ENGINEERING     │   42-feature UNSW-NB15 schema: duration, bytes,
 │  flow → 30+ ML features     │   packet rates, TCP handshake timing, jitter…
 │                             │   A sliding window of the last 100 flows adds
 │                             │   context features (e.g. "how many times has
 │                             │   this host hit this service recently?")
 └─────────────┬───────────────┘
               ▼
 ┌─────────────────────────────┐   Model A (binary XGBoost): attack or normal?
 │  3. ML INFERENCE            │   Model B (multi-class XGBoost): which of the
 │  two XGBoost models         │   10 attack categories?
 └─────────────┬───────────────┘
               ▼
 ┌─────────────────────────────┐   Streamlit dashboard: metric tiles, timeline,
 │  4. VISUALIZATION & ALERTS  │   protocol charts, alert tables with severity,
 │                             │   per-flow explainability, CSV export
 └─────────────────────────────┘
```

**A "flow"** = one conversation between two machines (same source IP/port, destination IP/port, protocol). The system never inspects your *content* — it works purely from traffic *shape and behavior*, which is why it works even on encrypted traffic.

---

## 5. The Machine Learning Story (what makes this project rigorous)

### Trained properly
- Trained on the official 175,341-flow UNSW-NB15 training split; **every reported number comes from the 82,332-flow test split the model never saw**.
- Fully reproducible: `python train_model.py` rebuilds both models and all metrics from the raw CSVs in one command.

### We found and removed hidden dataset "cheats"
UNSW-NB15 was generated in a lab, and some features secretly encode *the lab setup* rather than attack behavior:
- **TTL values & TCP window sizes** — fixed per traffic generator, near-perfect class separators *in the lab*, meaningless in the real world.
- **TCP handshake latency** (`tcprtt`, `synack`, `ackdat`) — normal traffic ran on a ~0.1 ms LAN, attacks came through ~60 ms paths. Any real internet connection (20–100 ms) therefore "looked like an attack".

Result before the fix: a clean DNS lookup was flagged as an attack with **99.96% confidence**. We identified all 10 artifact features **using our own explainability tool** and retrained without them at a cost of only **0.2 percentage points** of benchmark accuracy. A second low-noise threshold calibration now limits held-out benign alerts to approximately **0.1%**. *Robustness over leaderboard scores.*

### Final scorecard (held-out test data)

| Metric | Value |
|---|---|
| Benchmark accuracy (0.5 cutoff) | **86.6%** |
| Benchmark attack recall (0.5 cutoff) | **97.5%** |
| ROC-AUC | **0.980** |
| Low-noise threshold | **0.9985** |
| Low-noise false-positive rate | **0.05%** |
| Low-noise precision / recall | **99.94% / 68.89%** |
| Attack-category accuracy (10 classes) | **75.4%** |

### Verified on real infrastructure
- **Real Linux machine**: parsed a test capture with the NFStream DPI engine — benign DNS correctly NORMAL, **10/10 SYN-scan flows detected** with correct categories; live Wi-Fi capture verified end-to-end.
- **Automated CI**: every push to `main` triggers a GitHub Actions workflow on Ubuntu that reruns the full pipeline with **both** capture engines and fails the build if detection quality drops.

### Known limitation (and why stating it matters)
The dataset is from 2015; modern browsing is dominated by QUIC/HTTP3 (encrypted UDP), which did not exist then, so short QUIC fragments can be over-flagged on live traffic. The app defaults to a threshold measured from held-out benign traffic and also applies live-traffic guardrails. The stricter operating point reduces false positives at the expected cost of lower recall. *Knowing precisely where your model breaks is part of the engineering.*

---

## 6. Quick Start

### Windows (simulator + PCAP analysis work out of the box)
```bash
git clone https://github.com/Lynmwita/Network_analyzer.git
cd Network_analyzer
pip install -r requirements.txt
streamlit run app.py
```
For live capture on Windows, additionally install [Npcap](https://npcap.com) (tick "WinPcap API-compatible mode").

### Linux (full DPI engine)
```bash
git clone https://github.com/Lynmwita/Network_analyzer.git
cd Network_analyzer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install nfstream                      # full Deep Packet Inspection engine
streamlit run app.py                      # dashboard
sudo venv/bin/streamlit run app.py        # needed for live capture (raw sockets)
```
Find your interface name with `ip link` (e.g. `wlp108s0`, `eth0`) and enter it in the Live Capture page.

### Docker (one command, any OS with Docker)
```bash
docker build -t nids .
docker run --rm -p 8501:8501 nids
```

Open **http://localhost:8501** in your browser.

### Verify everything works
```bash
python test_pipeline.py          # CLI smoke test: model + feature mapping
python make_test_pcap.py         # generate the synthetic demo capture
python linux_nfstream_test.py    # (Linux) full NFStream integration test
```

---

## 7. A 5-Minute Demo Script

1. Open the **Model Performance Report** — show the confusion matrix and explain the numbers are from unseen data.
2. Switch to **Simulator**, press Start — watch flows stream in, alerts accumulate, charts update.
3. Open **Offline PCAP Analysis**, upload `data/test_traffic.pcap` — point out the SYN scan being caught 10/10 with attack categories.
4. Pick any flagged flow in the **Flow Inspector** — show the explainability chart: "here is exactly why the model called this an attack."
5. (Linux, optional showstopper) **Live Capture** on your Wi-Fi while running `nmap -sS <your-own-machine>` from another device — watch Reconnaissance alerts appear in real time. *Only scan machines you own.*

---

## 8. Project Structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit dashboard — all four modes, charts, alerts, explainability UI |
| `feature_extractor.py` | Flow → UNSW-NB15 features, encoding, both-model inference, SHAP-style explanations |
| `packet_engine.py` | Cross-platform Scapy capture engine (Windows PCAP + live support) |
| `nfplugin.py` | NFStream plugin: parses TTL/window/seq from raw packet bytes, handshake timing |
| `train_model.py` | Reproducible training: both models, metrics, artifact-feature analysis |
| `make_test_pcap.py` | Generates the synthetic demo capture (realistic benign flows + SYN scan) |
| `test_pipeline.py` | CLI smoke test |
| `linux_nfstream_test.py` | Linux integration test (used by CI) |
| `.github/workflows/linux-test.yml` | Automated Linux testing on every push |
| `Dockerfile` | One-command Linux deployment |
| `xgboost_network_model.json` | Binary attack/normal classifier (version-independent format) |
| `xgboost_attack_model.json` | 10-class attack categorizer |
| `deployment_threshold.pkl` | Held-out low-noise alert threshold used by the dashboard |
| `model_metrics.pkl` | Held-out evaluation metrics shown in the dashboard |
| `data/` | UNSW-NB15 splits + `test_traffic.pcap` demo capture |
| `UPGRADES.md` | Full engineering changelog: every bug found, fix applied, and feature added |

---

## 9. Technology Stack

- **XGBoost** — gradient-boosted trees; two models (binary + 10-class)
- **NFStream** — Deep Packet Inspection flow metering (Linux/macOS)
- **Scapy** — pure-Python packet engine (Windows fallback, PCAP + live)
- **Streamlit + Altair** — interactive dashboard and charts
- **scikit-learn / pandas / NumPy** — preprocessing and evaluation
- **GitHub Actions + Docker** — continuous Linux testing and deployment

---

## 10. Authors & Scope

Developed as a **Cybersecurity Final Year Project**. The complete engineering journey — including the dataset-artifact investigation, the capture-engine bug found through real-Linux testing, and every design tradeoff — is documented in [UPGRADES.md](UPGRADES.md).
