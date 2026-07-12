# Network Intrusion Detection System (NIDS) 🛡️

A real-time machine learning-powered Network Intrusion Detection System (NIDS) built for cybersecurity analysis. This application extracts live traffic features using **NFStream**, performs classification using an **XGBoost** model trained on the **UNSW-NB15** dataset, and visualizes security metrics in a **Streamlit** dashboard.

## Features

- **Real-Time Live Capture**: Intercepts packets on any network interface (e.g. Loopback, Ethernet, Wi-Fi), processes flows using Deep Packet Inspection (DPI) with NFStream, and evaluates threat statuses dynamically.
- **Offline PCAP Auditing**: Upload any `.pcap` or `.pcapng` file to perform a retrospective security audit of connection records.
- **Real-Time Simulation (Demo Mode)**: Replays flows directly from the UNSW-NB15 test dataset, demonstrating classification, alerts, and time-series charts without requiring elevated capture permissions or active traffic.
- **Dynamic Flow Analyzer**: Maintains a sliding memory window of connections to calculate count-based statistics (like `ct_srv_dst`, `ct_dst_src_ltm`) in real-time.
- **Interactive Inspector**: Inspect any flow in detail, displaying all base and engineered features fed into the ML model alongside classification confidence levels.
- **Attack-Type Classification**: A second multi-class XGBoost model names the category of each detected intrusion (DoS, Exploits, Reconnaissance, Fuzzers, Backdoor, Shellcode, Worms, …) with a severity triage level (HIGH / MEDIUM / LOW).
- **Explainable AI**: Every inspected flow shows a SHAP-style feature-contribution chart explaining exactly why the model classified it as attack or normal.
- **Model Performance Report**: An in-app page with held-out evaluation metrics — confusion matrix, precision/recall per attack class, ROC-AUC, and feature importances.
- **CSV Report Export**: Download full flow and alerts-only reports from any analysis session.
- **Aesthetic Cyber Dashboard**: Dark-mode styling, threat distribution charts, active security alert logs, bandwidth metrics — fully **mobile-responsive**.

> 📋 See [UPGRADES.md](UPGRADES.md) for a complete record of what the original build contained, the critical bugs that were fixed (dataset artifact false-positives, model version skew, train/test file swap), and every capability added on top.

---

## Technical Architecture

The project bridges the gap between raw network packets and machine learning feature inputs:
1. **Packet Capture Layer**: NFStream intercepts frames. A custom `SecurityPlugin` extracts TCP handshake latency (RTT, SYN-ACK, ACK-DAT durations), TTLs, and window sizes from packet headers.
2. **Feature Engineering Layer**: `feature_extractor.py` maps base flow variables to the exact schema of the UNSW-NB15 dataset and uses a sliding deque window of the last 100 flows to compute dynamic connection frequency metrics.
3. **ML Inference Layer**: The mapped inputs are encoded via `sklearn` LabelEncoders and predicted as Benign (0) or Malicious (1) by the `xgboost` classifier.
4. **Visual Dashboard Layer**: Streamlit displays metrics, generates real-time graphs, and updates active alert tables.

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- Works on **Windows, Linux, and macOS**:
  - **Linux/macOS** — install `nfstream` for the full DPI capture engine
  - **Windows** — the bundled Scapy engine handles PCAP analysis natively; install [Npcap](https://npcap.com) for live capture
- The app auto-detects the best available engine and shows which one is active

### Run on Linux via Docker
```bash
docker build -t nids .
docker run --rm -p 8501:8501 nids
```

### Continuous Linux testing
Every push to `main` triggers a GitHub Actions workflow that tests the complete
NFStream + Scapy + model pipeline on Ubuntu — see `.github/workflows/linux-test.yml`.

### Dependencies
Install the required python packages:
```bash
pip install -r requirements.txt
```

*(`nfstream` is optional and only needed for PCAP/live-capture modes; the simulator and performance report work without it.)*

### Retrain the Models (reproducible)
All model artifacts can be rebuilt from the raw CSVs in one command:
```bash
python3 train_model.py
```
This trains the binary intrusion model and the multi-class attack categorizer, evaluates them on the held-out 82k-flow test split, and writes `xgboost_network_model.json`, `xgboost_attack_model.json`, the encoders, and `model_metrics.pkl`.

### Run the CLI Test Pipeline
Verify that feature mapping and ML predictions run correctly:
```bash
python3 test_pipeline.py
```

### Launch the Streamlit Dashboard
To run the interactive web application:
```bash
python3 -m streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## Authors & Project Scope
This project was developed as a Final Year Project in Cybersecurity.
- **ML Framework**: XGBoost Classifier
- **Feature Extraction Engine**: NFStream (DPI & Statistical analysis)
- **Frontend Dashboard**: Streamlit
