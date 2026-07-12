# Network Intrusion Detection System (NIDS) 🛡️

A real-time machine learning-powered Network Intrusion Detection System (NIDS) built for cybersecurity analysis. This application extracts live traffic features using **NFStream**, performs classification using an **XGBoost** model trained on the **UNSW-NB15** dataset, and visualizes security metrics in a **Streamlit** dashboard.

## Features

- **Real-Time Live Capture**: Intercepts packets on any network interface (e.g. Loopback, Ethernet, Wi-Fi), processes flows using Deep Packet Inspection (DPI) with NFStream, and evaluates threat statuses dynamically.
- **Offline PCAP Auditing**: Upload any `.pcap` or `.pcapng` file to perform a retrospective security audit of connection records.
- **Real-Time Simulation (Demo Mode)**: Replays flows directly from the UNSW-NB15 test dataset, demonstrating classification, alerts, and time-series charts without requiring elevated capture permissions or active traffic.
- **Dynamic Flow Analyzer**: Maintains a sliding memory window of connections to calculate count-based statistics (like `ct_srv_dst`, `ct_dst_src_ltm`) in real-time.
- **Interactive Inspector**: Inspect any flow in detail, displaying all 42 base and engineered features fed into the ML model alongside classification confidence levels.
- **Aesthetic Cyber Dashboard**: Features dark-mode styling, threat distribution charts, active security alert logs, and bandwidth metrics.

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
- Linux environment (for live network capturing capabilities)

### Dependencies
Install the required python packages:
```bash
pip install pandas scikit-learn streamlit nfstream xgboost
```

*(Note: If you run into a timeout or constraint, you can install xgboost without GPU dependencies using `pip install xgboost --no-deps`)*

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
