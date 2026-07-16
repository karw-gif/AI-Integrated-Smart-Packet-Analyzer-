import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import tempfile
import altair as alt
from feature_extractor import FeatureExtractor
from pdf_report import generate_security_report

# We import nfstream conditionally in case the system environment fails to compile C dependencies,
# allowing the Simulator/Demo mode to run gracefully regardless.
try:
    from nfstream import NFStreamer
    from nfplugin import SecurityPlugin
    NFSTREAM_AVAILABLE = True
except ImportError:
    NFSTREAM_AVAILABLE = False

# Cross-platform fallback engine (pure-Python Scapy) so PCAP analysis and
# basic live capture also work on Windows, where NFStream cannot build.
try:
    from packet_engine import read_pcap as scapy_read_pcap, sniff_live as scapy_sniff_live
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# The SecurityPlugin (TCP handshake metrics, TTLs, windows) lives in
# nfplugin.py and parses raw packet bytes, since NFStream's NFPacket does not
# expose ip_ttl/tcp_window/tcp_seq attributes directly.

# Page Config
st.set_page_config(
    page_title="CyberNetwork Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyberpunk / Dark styling
st.markdown("""
<style>
    /* Glowing title */
    .cyber-title {
        color: #00ffcc;
        text-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc;
        font-family: 'Courier New', Courier, monospace;
        font-weight: bold;
        text-align: center;
        margin-bottom: 25px;
    }
    
    /* Metrics panel styling */
    .metric-container {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: bold;
        font-family: 'Courier New', Courier, monospace;
    }
    .metric-value.safe {
        color: #10b981;
    }
    .metric-value.danger {
        color: #ef4444;
        text-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
    }
    .metric-value.info {
        color: #3b82f6;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #9ca3af;
        margin-top: 5px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Severity badges */
    .sev-high { color: #ef4444; font-weight: bold; }
    .sev-med  { color: #f59e0b; font-weight: bold; }
    .sev-low  { color: #10b981; font-weight: bold; }

    /* ---- Mobile responsiveness ---- */
    @media (max-width: 768px) {
        h1.cyber-title, .cyber-title {
            font-size: 1.3rem !important;
            text-shadow: 0 0 6px #00ffcc;
            margin-bottom: 12px;
            padding-top: 0 !important;
        }
        .metric-container {
            padding: 10px 6px;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .metric-value {
            font-size: 1.3rem;
        }
        .metric-label {
            font-size: 0.62rem;
            letter-spacing: 0.02em;
        }
        /* Stack Streamlit columns vertically on small screens */
        div[data-testid="stHorizontalBlock"] {
            flex-wrap: wrap;
        }
        div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
            flex: 1 1 45% !important;
            min-width: 45% !important;
        }
        /* Reduce main padding so tables get full width */
        section.main > div.block-container,
        div[data-testid="stMainBlockContainer"] {
            padding-left: 0.6rem !important;
            padding-right: 0.6rem !important;
            padding-top: 2.2rem !important;
        }
    }
    @media (max-width: 480px) {
        h1.cyber-title, .cyber-title { font-size: 1.05rem !important; }
        div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
            flex: 1 1 100% !important;
            min-width: 100% !important;
        }
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='cyber-title'>🛡️ CYBER-NETWORK INTRUSION DETECTION SYSTEM</h1>", unsafe_allow_html=True)

# Cache model loading
@st.cache_resource
def load_feature_extractor():
    return FeatureExtractor()

try:
    extractor = load_feature_extractor()
    st.sidebar.success("✅ XGBoost Intrusion Model Loaded")
except Exception as e:
    st.sidebar.error(f"❌ Error loading model: {e}")
    st.stop()

# Sidebar configuration
st.sidebar.title("Configuration Panel")
analysis_mode = st.sidebar.selectbox(
    "Choose Analysis Mode",
    ["🖥️ Simulator (Demo Mode)", "📂 Offline PCAP Analysis", "🔌 Live Interface Capture",
     "📊 Model Performance Report"]
)

# Confidence Threshold Slider
confidence_threshold = st.sidebar.slider(
    "Model Alert Threshold",
    min_value=0.50,
    max_value=0.99,
    value=0.90,
    step=0.01,
    help="Minimum probability required to flag a flow as malicious."
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**Cybersecurity Final Year Project**\n\n"
    "Built using **Streamlit**, **NFStream**, and **XGBoost** classifier trained on the "
    "UNSW-NB15 Intrusion Detection dataset."
)

# Initialize Session States
if 'flows' not in st.session_state:
    st.session_state.flows = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'total_bytes' not in st.session_state:
    st.session_state.total_bytes = 0

def clear_session_data():
    st.session_state.flows = []
    st.session_state.alerts = []
    st.session_state.total_bytes = 0

def severity_of(pred):
    """Derive a human severity level from attack category + model confidence."""
    if pred['label'] == 0:
        return '—'
    high_cats = {'Exploits', 'Backdoor', 'Shellcode', 'Worms', 'DoS'}
    if pred['attack_cat'] in high_cats or pred['confidence'] >= 0.95:
        return '🔴 HIGH'
    if pred['confidence'] >= 0.85:
        return '🟠 MEDIUM'
    return '🟡 LOW'

def capture_alert_decision(flow_src, pred, threshold):
    """Require behavioral evidence before alerting on modern captured traffic."""
    probability = pred.get('attack_probability', 0.0)
    if pred.get('label') != 1 or probability < max(threshold, 0.98):
        return False, "Below production alert threshold"

    f = pred['features']
    packets = int(f.get('spkts', 0)) + int(f.get('dpkts', 0))
    byte_count = int(f.get('sbytes', 0)) + int(f.get('dbytes', 0))
    rate = float(f.get('rate', 0))
    service = str(f.get('service', '-')).lower()
    ports = {int(getattr(flow_src, 'src_port', 0)), int(getattr(flow_src, 'dst_port', 0))}
    bidirectional = int(f.get('spkts', 0)) > 0 and int(f.get('dpkts', 0)) > 0

    # QUIC did not exist in UNSW-NB15. Short UDP/443 exchanges are expected
    # modern browser traffic and must not alert from model confidence alone.
    if 443 in ports and getattr(flow_src, 'protocol', 0) == 17:
        suspicious = packets >= 100 or byte_count >= 1_000_000 or rate >= 1000
        return suspicious, ("High-volume QUIC behavior" if suspicious else
                            "Suppressed routine short QUIC/UDP 443 flow")

    if ports.intersection({80, 443}) or service in {'http', 'ssl'}:
        suspicious = packets >= 200 or byte_count >= 2_000_000 or rate >= 2000
        if bidirectional and not suspicious:
            return False, "Suppressed routine bidirectional web/TLS flow"
        repeated = max(int(f.get('ct_src_dport_ltm', 1)), int(f.get('ct_dst_ltm', 1))) >= 10
        if not suspicious and not repeated:
            return False, "Suppressed isolated short web/TLS flow"
        return True, "Web traffic has burst, volume, or repeated-probing indicators"

    if 53 in ports or service == 'dns':
        if bidirectional and packets < 50 and byte_count < 100_000:
            return False, "Suppressed routine bidirectional DNS flow"

    return True, "High-confidence model alert outside encrypted-traffic guardrails"


def build_flow_info(flow_src, pred, threshold, with_timestamp=True,
                    alert_override=None, policy_reason=None):
    """Common display record for simulator / PCAP / live flows."""
    is_alert = (pred['label'] == 1 and pred['confidence'] >= threshold
                if alert_override is None else bool(alert_override))
    was_suppressed = alert_override is False and pred['label'] == 1
    if alert_override is None:
        display_prediction = 'ATTACK' if is_alert else 'NORMAL'
    else:
        display_prediction = ('ACTIONABLE ALERT' if is_alert else
                              'SUPPRESSED MODEL ALERT' if was_suppressed else 'NORMAL')
    info = {
        'src_ip': flow_src.src_ip,
        'src_port': flow_src.src_port,
        'dst_ip': flow_src.dst_ip,
        'dst_port': flow_src.dst_port,
        'protocol': 'TCP' if flow_src.protocol == 6 else ('UDP' if flow_src.protocol == 17 else 'ICMP'),
        'service': pred['features']['service'],
        'duration': f"{pred['features']['dur']:.6f}s",
        'bytes': pred['features']['sbytes'] + pred['features']['dbytes'],
        'prediction': display_prediction,
        'attack_type': pred['attack_cat'] if is_alert else '—',
        'severity': severity_of(pred) if is_alert else '—',
        'confidence': f"{pred['confidence']*100:.2f}%",
        'raw_confidence': pred['confidence'],
        'raw_label': pred['label'],
        'actionable_alert': is_alert,
        'policy_reason': policy_reason or 'Benchmark model threshold',
        'details': pred['features']
    }
    if with_timestamp:
        info = {'timestamp': time.strftime("%H:%M:%S"), **info}
    return info

def export_buttons(key_prefix):
    """CSV exports and a complete downloadable PDF security report."""
    if not st.session_state.flows:
        return
    st.markdown("### Security Reports")
    anonymize = st.checkbox(
        "Anonymize IP addresses in PDF",
        value=False,
        key=f"{key_prefix}_anonymize_pdf",
        help="Replaces source and destination IPs with stable anonymous host IDs.",
    )
    exp_col1, exp_col2, exp_col3 = st.columns(3)
    df_all = pd.DataFrame(st.session_state.flows).drop(columns=['details'], errors='ignore')
    with exp_col1:
        st.download_button("⬇️ Export Flow Report (CSV)", df_all.to_csv(index=False),
                           file_name="nids_flow_report.csv", mime="text/csv",
                           key=f"{key_prefix}_flows", use_container_width=True)
    if st.session_state.alerts:
        df_al = pd.DataFrame(st.session_state.alerts).drop(columns=['details'], errors='ignore')
        with exp_col2:
            st.download_button("⬇️ Export Alerts Report (CSV)", df_al.to_csv(index=False),
                               file_name="nids_alerts_report.csv", mime="text/csv",
                               key=f"{key_prefix}_alerts", use_container_width=True)
    pdf_bytes = generate_security_report(
        st.session_state.flows,
        st.session_state.alerts,
        analysis_mode=analysis_mode,
        confidence_threshold=confidence_threshold,
        anonymize_ips=anonymize,
    )
    with exp_col3:
        st.download_button(
            "Download Security Report (PDF)",
            data=pdf_bytes,
            file_name=f"nids_security_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            key=f"{key_prefix}_pdf",
            use_container_width=True,
        )

# Dashboard Layout Elements
m_col1, m_col2, m_col3, m_col4 = st.columns(4)

with m_col1:
    flows_placeholder = st.empty()
with m_col2:
    alerts_placeholder = st.empty()
with m_col3:
    ratio_placeholder = st.empty()
with m_col4:
    bandwidth_placeholder = st.empty()

# Helper function to render metrics
def update_dashboard_metrics():
    total_flows = len(st.session_state.flows)
    total_alerts = len(st.session_state.alerts)
    ratio = (total_alerts / total_flows * 100) if total_flows > 0 else 0.0
    
    # Human readable bandwidth
    bytes_count = st.session_state.total_bytes
    if bytes_count < 1024:
        bw_str = f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        bw_str = f"{bytes_count/1024:.2f} KB"
    else:
        bw_str = f"{bytes_count/(1024*1024):.2f} MB"

    flows_placeholder.markdown(f"""
    <div class="metric-container">
        <div class="metric-value info">{total_flows}</div>
        <div class="metric-label">Analyzed Flows</div>
    </div>
    """, unsafe_allow_html=True)
    
    alerts_placeholder.markdown(f"""
    <div class="metric-container">
        <div class="metric-value danger">{total_alerts}</div>
        <div class="metric-label">Actionable Alerts</div>
    </div>
    """, unsafe_allow_html=True)
    
    ratio_placeholder.markdown(f"""
    <div class="metric-container">
        <div class="metric-value {'danger' if ratio > 5 else 'safe'}">{ratio:.2f}%</div>
        <div class="metric-label">Actionable Alert Ratio</div>
    </div>
    """, unsafe_allow_html=True)
    
    bandwidth_placeholder.markdown(f"""
    <div class="metric-container">
        <div class="metric-value info">{bw_str}</div>
        <div class="metric-label">Total Bandwidth</div>
    </div>
    """, unsafe_allow_html=True)

# Main Application Core
if analysis_mode == "🖥️ Simulator (Demo Mode)":
    st.subheader("⚡ Live Threat Classification Simulator")
    st.write(
        "Simulator mode streams real network traffic samples from the UNSW-NB15 "
        "test set and feeds them through our feature mapping and XGBoost model. "
        "Use this mode to see the dashboard in action. Simulator IP addresses are synthetic; "
        "the Ground Truth and Evaluation columns show whether each model alert is correct."
    )
    
    col_c1, col_c2 = st.columns([1, 4])
    with col_c1:
        run_sim = st.button("🚀 Start Simulation", use_container_width=True)
        stop_sim = st.button("⏹️ Stop", use_container_width=True)
        clear_sim = st.button("🗑️ Clear Dashboard", on_click=clear_session_data, use_container_width=True)
        sim_speed = st.slider("Simulation Delay (s)", 0.1, 2.0, 0.5)
        traffic_profile = st.selectbox(
            "Simulation traffic mix",
            ["Realistic network (95% benign)", "Balanced demonstration (50% benign)",
             "Original benchmark distribution"],
            help="UNSW-NB15 is attack-heavy. The realistic profile provides a more representative demo.",
        )
        
    with col_c2:
        # Load sample data
        @st.cache_data
        def load_simulator_dataset():
            # NOTE: despite its filename, NB_training-set.csv holds the official
            # 82k UNSW-NB15 *testing* split (the shipped files are swapped).
            # We stream the held-out split so the model never sees its own
            # training data during the demo.
            df = pd.read_csv('data/NB_training-set.csv')
            # Shuffle so attacks and normal traffic interleave realistically
            return df.sample(frac=1.0, random_state=7).reset_index(drop=True)
        
        try:
            sim_df = load_simulator_dataset()
            st.success(f"Loaded {len(sim_df)} simulation records successfully.")
        except Exception as e:
            st.error(f"Could not load simulator dataset from data/NB_testing-set.csv: {e}")
            st.stop()

    # Simulator loop
    if run_sim:
        st.session_state.running = True
        
        # We simulate the structure of an NFStream flow using dictionary entries
        # because the FeatureExtractor expects base fields and will calculate sliding count fields itself.
        if traffic_profile != "Original benchmark distribution":
            benign_share = 0.95 if traffic_profile.startswith("Realistic") else 0.50
            sample_size = min(5000, len(sim_df))
            benign_n = int(sample_size * benign_share)
            attack_n = sample_size - benign_n
            benign = sim_df[sim_df['label'] == 0].sample(n=benign_n, random_state=17, replace=False)
            attacks = sim_df[sim_df['label'] == 1].sample(n=attack_n, random_state=23, replace=False)
            active_sim_df = pd.concat([benign, attacks]).sample(frac=1.0, random_state=29)
        else:
            active_sim_df = sim_df
        sim_records = active_sim_df.to_dict('records')
        
        # Define mock flow class inside loop
        class SimulatorFlow:
            def __init__(self, record):
                self.bidirectional_duration_ms = record.get('dur', 0.0) * 1000.0
                # Approximate protocol name back to number
                proto_str = str(record.get('proto', 'tcp')).lower()
                self.protocol = 6 if proto_str == 'tcp' else (17 if proto_str == 'udp' else 1)
                
                self.src_ip = "192.168.1." + str(np.random.randint(10, 250))
                self.dst_ip = "10.0.0." + str(np.random.randint(10, 250))
                self.src_port = int(record.get('sport', np.random.randint(1024, 65535)))
                self.dst_port = int(record.get('dsport', np.random.randint(1, 1024)))
                self.application_name = str(record.get('service', '-')).upper()
                
                self.src2dst_packets = int(record.get('spkts', 1))
                self.dst2src_packets = int(record.get('dpkts', 0))
                self.src2dst_bytes = int(record.get('sbytes', 64))
                self.dst2src_bytes = int(record.get('dbytes', 0))
                self.bidirectional_packets = self.src2dst_packets + self.dst2src_packets
                
                self.src2dst_mean_piat_ms = record.get('sinpkt', 0.0)
                self.dst2src_mean_piat_ms = record.get('dinpkt', 0.0)
                self.src2dst_stddev_piat_ms = record.get('sjit', 0.0)
                self.dst2src_stddev_piat_ms = record.get('djit', 0.0)
                
                self.udps = type('UDPS', (), {})()
                self.udps.src_ttl = int(record.get('sttl', 64))
                self.udps.dst_ttl = int(record.get('dttl', 0))
                self.udps.src_win = int(record.get('swin', 0))
                self.udps.dst_win = int(record.get('dwin', 0))
                self.udps.src_tcp_seq = int(record.get('stcpb', 0))
                self.udps.dst_tcp_seq = int(record.get('dtcpb', 0))
                self.udps.tcp_rtt = float(record.get('tcprtt', 0.0))
                self.udps.synack = float(record.get('synack', 0.0))
                self.udps.ackdat = float(record.get('ackdat', 0.0))
                self.udps.tcp_flags_sum = 0x02 if self.protocol == 6 else 0

        # Run simulation in loop
        status_box = st.empty()
        status_box.info("Simulation running...")
        
        # Display placeholders for live charts
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown("### Threat Classification Timeline")
            timeline_placeholder = st.empty()
        with chart_col2:
            st.markdown("### Services Distribution")
            service_placeholder = st.empty()
            
        st.markdown("### 🔔 Active Security Alerts")
        alerts_table_placeholder = st.empty()
        
        st.markdown("### 🔍 Flow Analyzer Explorer")
        flows_table_placeholder = st.empty()

        # Iterate over records randomly or sequentially
        idx = 0
        while st.session_state.get('running', True) and idx < len(sim_records):
            record = sim_records[idx]
            mock_flow = SimulatorFlow(record)
            
            # Predict
            pred = extractor.predict_flow(mock_flow)
            flow_info = build_flow_info(mock_flow, pred, confidence_threshold)
            truth_is_attack = int(record.get('label', 0)) == 1
            model_alert = pred['label'] == 1 and pred['confidence'] >= confidence_threshold
            flow_info['ground_truth'] = 'ATTACK' if truth_is_attack else 'NORMAL'
            flow_info['ground_truth_attack_type'] = (
                str(record.get('attack_cat', 'Unknown')) if truth_is_attack else '-'
            )
            flow_info['evaluation'] = (
                'TRUE POSITIVE' if model_alert and truth_is_attack else
                'FALSE POSITIVE' if model_alert else
                'FALSE NEGATIVE' if truth_is_attack else 'TRUE NEGATIVE'
            )
            
            st.session_state.flows.append(flow_info)
            st.session_state.total_bytes += flow_info['bytes']
            
            if pred['label'] == 1 and pred['confidence'] >= confidence_threshold:
                st.session_state.alerts.append(flow_info)
                
            # Keep lists trimmed for dashboard performance
            if len(st.session_state.flows) > 500:
                st.session_state.flows.pop(0)
            # Alerts must describe the same visible 500-flow window as the metrics.
            st.session_state.alerts = [
                item for item in st.session_state.flows
                if item.get('raw_label') == 1 and item.get('raw_confidence', 0) >= confidence_threshold
            ]
            
            update_dashboard_metrics()
            
            # Draw Timeline Chart
            df_flows = pd.DataFrame(st.session_state.flows)
            if not df_flows.empty:
                chart_data = df_flows.groupby(['timestamp', 'prediction']).size().reset_index(name='count')
                timeline_chart = alt.Chart(chart_data).mark_line(point=True).encode(
                    x='timestamp:N',
                    y='count:Q',
                    color=alt.Color('prediction:N', scale=alt.Scale(domain=['ATTACK', 'NORMAL'], range=['#ef4444', '#10b981'])),
                    tooltip=['timestamp', 'prediction', 'count']
                ).properties(height=250)
                timeline_placeholder.altair_chart(timeline_chart, use_container_width=True)
                
                # Draw Service Distribution Chart
                srv_data = df_flows.groupby('service').size().reset_index(name='count')
                service_chart = alt.Chart(srv_data).mark_bar().encode(
                    x='service:N',
                    y='count:Q',
                    color=alt.value('#3b82f6'),
                    tooltip=['service', 'count']
                ).properties(height=250)
                service_placeholder.altair_chart(service_chart, use_container_width=True)
            
            # Update Alerts Table
            if st.session_state.alerts:
                df_alerts = pd.DataFrame(st.session_state.alerts)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'attack_type', 'severity', 'confidence', 'ground_truth', 'evaluation']]
                alerts_table_placeholder.dataframe(df_alerts.tail(10), use_container_width=True)
            else:
                alerts_table_placeholder.info("No security alerts triggered.")
                
            # Update Flows Table
            df_display = df_flows[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'attack_type', 'confidence', 'ground_truth', 'evaluation']]
            flows_table_placeholder.dataframe(df_display.tail(15), use_container_width=True)
            
            idx += 1
            time.sleep(sim_speed)

            # Handle manual stop via session state
            if stop_sim:
                st.session_state.running = False
                status_box.warning("Simulation stopped.")
                break

    # Offer CSV exports of whatever has been analyzed so far
    export_buttons("sim")

elif analysis_mode == "📂 Offline PCAP Analysis":
    st.subheader("📁 Offline Packet Capture Audit")

    if NFSTREAM_AVAILABLE:
        st.caption("Engine: **NFStream** (Deep Packet Inspection)")
    elif SCAPY_AVAILABLE:
        st.caption("Engine: **Scapy** (cross-platform fallback — NFStream not available on this OS)")
    else:
        st.error("❌ Neither NFStream nor Scapy is installed. Run `pip install scapy` to enable PCAP parsing.")
        st.stop()

    pcap_file = st.file_uploader("Upload a network capture file (.pcap or .pcapng)", type=["pcap", "pcapng"])
    
    if pcap_file is not None:
        # Save uploaded file to temp path
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(pcap_file.read())
            tmp_path = tmp.name

        st.info("🔄 Processing PCAP with NFStream and mapping features...")
        clear_session_data()
        
        progress_bar = st.progress(0.0)
        status_text = st.empty()
        
        # Analyze PCAP
        try:
            if NFSTREAM_AVAILABLE:
                # We instantiate NFStreamer with our SecurityPlugin to collect TCP handshakes and TTLs
                streamer = NFStreamer(
                    source=tmp_path,
                    udps=SecurityPlugin(),
                    statistical_analysis=True
                )
            else:
                streamer = scapy_read_pcap(tmp_path)

            flows_list = []
            alerts_list = []

            for flow in streamer:
                pred = extractor.predict_flow(flow)
                is_actionable, policy_reason = capture_alert_decision(flow, pred, confidence_threshold)
                flow_info = build_flow_info(
                    flow, pred, confidence_threshold, with_timestamp=False,
                    alert_override=is_actionable, policy_reason=policy_reason)
                flows_list.append(flow_info)
                st.session_state.total_bytes += flow_info['bytes']
                if is_actionable:
                    alerts_list.append(flow_info)
            
            st.session_state.flows = flows_list
            st.session_state.alerts = alerts_list
            update_dashboard_metrics()
            
            st.success(f"Successfully audited {len(flows_list)} network flows from PCAP.")
            
            # Display Results
            col_chart1, col_chart2 = st.columns(2)
            df_pcap = pd.DataFrame(flows_list)
            
            if not df_pcap.empty:
                with col_chart1:
                    st.markdown("### Threat Classification Distribution")
                    pie_data = df_pcap.groupby('prediction').size().reset_index(name='count')
                    pie_chart = alt.Chart(pie_data).mark_arc(innerRadius=50).encode(
                        theta='count:Q',
                        color=alt.Color('prediction:N', scale=alt.Scale(
                            domain=['ACTIONABLE ALERT', 'SUPPRESSED MODEL ALERT', 'NORMAL'],
                            range=['#ef4444', '#f59e0b', '#10b981'])),
                        tooltip=['prediction', 'count']
                    ).properties(height=250)
                    st.altair_chart(pie_chart, use_container_width=True)
                
                with col_chart2:
                    st.markdown("### Protocol Distribution")
                    proto_data = df_pcap.groupby('protocol').size().reset_index(name='count')
                    proto_chart = alt.Chart(proto_data).mark_bar().encode(
                        x='protocol:N',
                        y='count:Q',
                        color=alt.value('#10b981'),
                        tooltip=['protocol', 'count']
                    ).properties(height=250)
                    st.altair_chart(proto_chart, use_container_width=True)
                
                st.markdown("### 🚨 Intrusion Alerts triggered")
                if alerts_list:
                    df_a = pd.DataFrame(alerts_list)[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'attack_type', 'severity', 'confidence']]
                    st.dataframe(df_a, use_container_width=True)
                else:
                    st.info("No security anomalies detected in this capture file.")

                st.markdown("### 🔍 Full Flow Explorer")
                df_disp = df_pcap[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'attack_type', 'confidence']]
                st.dataframe(df_disp, use_container_width=True)
                export_buttons("pcap")
                
        except Exception as e:
            st.error(f"Error parsing PCAP: {e}")
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

elif analysis_mode == "🔌 Live Interface Capture":
    st.subheader("🔌 Real-time Live Network Capture")

    if NFSTREAM_AVAILABLE:
        st.caption("Engine: **NFStream** (streaming flows with DPI)")
    elif SCAPY_AVAILABLE:
        st.caption("Engine: **Scapy** (cross-platform fallback — captures in batches). "
                   "On Windows this requires [Npcap](https://npcap.com) to be installed.")
    else:
        st.error("❌ Neither NFStream nor Scapy is installed. Run `pip install scapy` to enable live capture.")
        st.stop()

    st.info(
        "Live alert policy: model scores are filtered through modern-traffic guardrails. "
        "Routine short TLS, QUIC, and bidirectional DNS flows remain visible but do not "
        "become actionable threats without suspicious behavior."
    )

    st.warning(
        "⚠️ **Permissions Notice**: Live capture requires net_raw capabilities. "
        "If you are running in a standard user space or container, this might fail "
        "unless the application has appropriate permissions (e.g., sudo / Npcap)."
    )
    
    if_col1, if_col2 = st.columns([2, 1])
    with if_col1:
        interface_name = st.text_input("Enter Network Interface name", value="lo")
    with if_col2:
        flow_limit = st.number_input("Capture Flow Limit", min_value=10, max_value=1000, value=100)
        
    cap_col1, cap_col2 = st.columns(2)
    with cap_col1:
        start_cap = st.button("🔴 Start Live Capture", use_container_width=True)
    with cap_col2:
        clear_cap = st.button("🗑️ Clear Live Stats", on_click=clear_session_data, use_container_width=True)
        
    if start_cap:
        clear_session_data()
        st.info(f"Listening on interface '{interface_name}' (capturing up to {flow_limit} flows)...")
        
        # Set up display containers
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown("### Threat Classification Timeline")
            live_timeline = st.empty()
        with chart_col2:
            st.markdown("### Protocol Distribution")
            live_protocols = st.empty()
            
        st.markdown("### Actionable Alerts - Needs Review")
        live_alerts_table = st.empty()
        
        st.markdown("### 🔍 Live Flow Inspector")
        live_flows_table = st.empty()
        
        try:
            if NFSTREAM_AVAILABLE:
                # Initiate NFStreamer on the network interface.
                # Short timeouts so flows appear within seconds during a live
                # demo (NFStream's defaults hold flows for 120s of idle time
                # before releasing them, which looks like a frozen dashboard).
                streamer = NFStreamer(
                    source=interface_name,
                    udps=SecurityPlugin(),
                    statistical_analysis=True,
                    promiscuous_mode=True,
                    idle_timeout=10,
                    active_timeout=30
                )
            else:
                # Scapy fallback: capture a batch of packets, then aggregate to flows
                with st.spinner("Capturing packets (up to 30s or 500 packets)..."):
                    streamer = scapy_sniff_live(
                        interface=interface_name if interface_name not in ("", "lo") else None,
                        packet_count=500,
                        timeout=30
                    )
                st.info(f"Captured and aggregated {len(streamer)} flows.")

            count = 0
            for flow in streamer:
                pred = extractor.predict_flow(flow)
                is_actionable, policy_reason = capture_alert_decision(flow, pred, confidence_threshold)
                flow_info = build_flow_info(
                    flow, pred, confidence_threshold,
                    alert_override=is_actionable, policy_reason=policy_reason)
                st.session_state.flows.append(flow_info)
                st.session_state.total_bytes += flow_info['bytes']
                if is_actionable:
                    st.session_state.alerts.append(flow_info)
                
                # Truncate older records to fit display memory
                if len(st.session_state.flows) > 300:
                    st.session_state.flows.pop(0)
                st.session_state.alerts = [
                    item for item in st.session_state.flows
                    if item.get('actionable_alert')
                ]
                    
                update_dashboard_metrics()
                
                # Render Charts
                df_live = pd.DataFrame(st.session_state.flows)
                if not df_live.empty:
                    # Timeline
                    c_data = df_live.groupby(['timestamp', 'prediction']).size().reset_index(name='count')
                    line_c = alt.Chart(c_data).mark_line(point=True).encode(
                        x='timestamp:N',
                        y='count:Q',
                        color=alt.Color('prediction:N', scale=alt.Scale(
                            domain=['ACTIONABLE ALERT', 'SUPPRESSED MODEL ALERT', 'NORMAL'],
                            range=['#ef4444', '#f59e0b', '#10b981'])),
                        tooltip=['timestamp', 'prediction', 'count']
                    ).properties(height=250)
                    live_timeline.altair_chart(line_c, use_container_width=True)
                    
                    # Protocols
                    p_data = df_live.groupby('protocol').size().reset_index(name='count')
                    bar_c = alt.Chart(p_data).mark_bar().encode(
                        x='protocol:N',
                        y='count:Q',
                        color=alt.value('#10b981'),
                        tooltip=['protocol', 'count']
                    ).properties(height=250)
                    live_protocols.altair_chart(bar_c, use_container_width=True)
                
                # Live Tables
                if st.session_state.alerts:
                    df_la = pd.DataFrame(st.session_state.alerts)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'attack_type', 'severity', 'confidence']]
                    live_alerts_table.dataframe(df_la.tail(8), use_container_width=True)
                else:
                    live_alerts_table.info("Listening... No threats detected yet.")

                df_lf = pd.DataFrame(st.session_state.flows)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'attack_type', 'confidence', 'policy_reason']]
                live_flows_table.dataframe(df_lf.tail(12), use_container_width=True)
                
                count += 1
                if count >= flow_limit:
                    st.success("Reached flow capture limit.")
                    break
                    
        except Exception as e:
            st.error(f"Error during live capture: {e}")
            st.info("Check interface name or permissions. Make sure to run Streamlit with sufficient capture privileges.")

    # Keep exports available after capture completes and across Streamlit reruns.
    export_buttons("live")

elif analysis_mode == "📊 Model Performance Report":
    st.subheader("📊 Model Evaluation on Held-Out UNSW-NB15 Test Data")
    st.write(
        "These metrics were computed on **82,332 flows the model never saw during training**, "
        "so they reflect true generalization performance rather than memorization."
    )

    import joblib as _joblib
    try:
        mm = _joblib.load('model_metrics.pkl')
    except Exception as e:
        st.error(f"model_metrics.pkl not found — run `py train_model.py` first. ({e})")
        st.stop()

    b = mm['binary']
    p_col1, p_col2, p_col3, p_col4 = st.columns(4)
    for col, (label, val) in zip(
        [p_col1, p_col2, p_col3, p_col4],
        [("Accuracy", b['accuracy']), ("Precision", b['precision']),
         ("Recall (Detection Rate)", b['recall']), ("ROC-AUC", b['roc_auc'])]):
        with col:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-value safe">{val*100:.2f}%</div>
                <div class="metric-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("")
    perf_c1, perf_c2 = st.columns(2)

    with perf_c1:
        st.markdown("### Confusion Matrix")
        cm = b['confusion_matrix']
        cm_df = pd.DataFrame([
            {'Actual': 'Normal', 'Predicted': 'Normal', 'count': cm[0][0]},
            {'Actual': 'Normal', 'Predicted': 'Attack', 'count': cm[0][1]},
            {'Actual': 'Attack', 'Predicted': 'Normal', 'count': cm[1][0]},
            {'Actual': 'Attack', 'Predicted': 'Attack', 'count': cm[1][1]},
        ])
        cm_chart = alt.Chart(cm_df).mark_rect().encode(
            x=alt.X('Predicted:N'),
            y=alt.Y('Actual:N'),
            color=alt.Color('count:Q', scale=alt.Scale(scheme='tealblues'), legend=None),
        ).properties(height=260)
        cm_text = alt.Chart(cm_df).mark_text(fontSize=18, fontWeight='bold', color='white').encode(
            x='Predicted:N', y='Actual:N', text='count:Q'
        )
        st.altair_chart(cm_chart + cm_text, use_container_width=True)
        st.caption(f"Attack detection rate: {b['recall']*100:.1f}% — only "
                   f"{cm[1][0]:,} of {cm[1][0]+cm[1][1]:,} attacks slipped through.")

    with perf_c2:
        st.markdown("### Top 15 Most Influential Features")
        imp_df = pd.DataFrame(mm['feature_importances'][:15], columns=['feature', 'importance'])
        imp_chart = alt.Chart(imp_df).mark_bar().encode(
            x=alt.X('importance:Q'),
            y=alt.Y('feature:N', sort='-x'),
            color=alt.value('#00ffcc'),
            tooltip=['feature', alt.Tooltip('importance:Q', format='.4f')]
        ).properties(height=340)
        st.altair_chart(imp_chart, use_container_width=True)

    st.markdown("### 🎯 Attack Category Classifier (Multi-Class)")
    st.write(f"A second XGBoost model names the **type** of each detected intrusion "
             f"(overall accuracy: **{mm['attack_cat_accuracy']*100:.1f}%** across 10 classes).")
    rep = mm['attack_cat_report']
    rep_rows = [{'Category': k, 'Precision': f"{v['precision']*100:.1f}%",
                 'Recall': f"{v['recall']*100:.1f}%", 'F1': f"{v['f1-score']*100:.1f}%",
                 'Test Samples': int(v['support'])}
                for k, v in rep.items() if isinstance(v, dict) and k not in ('macro avg', 'weighted avg')]
    st.dataframe(pd.DataFrame(rep_rows), use_container_width=True, hide_index=True)

    with st.expander("🔬 Why we deliberately dropped 7 dataset-artifact features"):
        st.write(
            "UNSW-NB15 was generated in a lab where attack traffic used fixed TTL values and "
            "constant TCP window sizes. Features like `sttl`, `dttl`, `ct_state_ttl`, `swin`, "
            "`dwin`, `stcpb` and `dtcpb` act as near-perfect separators *inside the dataset* "
            "but cause severe false positives on real captured traffic (benign DNS lookups were "
            "flagged as attacks with 99.9% confidence). Removing them cost only "
            f"**{(mm['binary_all_features']['accuracy']-b['accuracy'])*100:.2f} percentage points** of "
            "benchmark accuracy while making the model actually usable in live deployment — "
            "a classic robustness-over-leaderboard tradeoff."
        )

# Interactive Flow Detail Inspector at the bottom of the page
st.markdown("---")
st.markdown("### 🕵️ Flow Feature Details & Explainability")
if st.session_state.flows:
    df_inspect = pd.DataFrame(st.session_state.flows)
    
    # Let user select a flow to inspect
    flow_labels = [f"[{f['timestamp']}] {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} ({f['prediction']})" for f in st.session_state.flows]
    selected_idx = st.selectbox("Select a flow to inspect in detail", range(len(flow_labels)), format_func=lambda x: flow_labels[x])
    
    if selected_idx is not None:
        sel_flow = st.session_state.flows[selected_idx]
        
        # Display meta details
        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            st.markdown(f"**Flow ID**: {selected_idx}")
            st.markdown(f"**Source**: `{sel_flow['src_ip']}:{sel_flow['src_port']}`")
        with col_d2:
            st.markdown(f"**Protocol**: `{sel_flow['protocol']}`")
            st.markdown(f"**Destination**: `{sel_flow['dst_ip']}:{sel_flow['dst_port']}`")
        with col_d3:
            st.markdown(f"**Classification**: `{sel_flow['prediction']}`")
            st.markdown(f"**Attack Type**: `{sel_flow.get('attack_type', '—')}` | **Severity**: {sel_flow.get('severity', '—')}")
            st.markdown(f"**Confidence**: `{sel_flow['confidence']}`")

        # Explainable AI: which features pushed this decision?
        st.markdown("#### 🧠 Explainable AI — Why did the model decide this?")
        try:
            contribs = extractor.explain_flow(sel_flow['details'])[:10]
            expl_df = pd.DataFrame(contribs, columns=['feature', 'contribution'])
            expl_df['pushes_toward'] = expl_df['contribution'].apply(
                lambda v: '🚨 Attack' if v > 0 else '🟢 Normal')
            expl_chart = alt.Chart(expl_df).mark_bar().encode(
                x=alt.X('contribution:Q', title='Contribution to decision (log-odds)'),
                y=alt.Y('feature:N', sort=alt.EncodingSortField(field='contribution', op='sum', order='descending')),
                color=alt.Color('pushes_toward:N',
                                scale=alt.Scale(domain=['🚨 Attack', '🟢 Normal'],
                                                range=['#ef4444', '#10b981']),
                                legend=alt.Legend(title=None, orient='bottom')),
                tooltip=['feature', alt.Tooltip('contribution:Q', format='.4f')]
            ).properties(height=280)
            st.altair_chart(expl_chart, use_container_width=True)
            st.caption("SHAP-style feature contributions from the XGBoost model: red bars pushed "
                       "this flow toward ATTACK, green bars toward NORMAL.")
        except Exception as e:
            st.info(f"Explanation unavailable for this flow: {e}")

        # Display key features
        st.markdown("#### Key Engineered Features")
        feats = sel_flow['details']
        
        # Group features for readability
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        with col_f1:
            st.metric("Duration (dur)", f"{feats.get('dur', 0.0):.6f}s")
            st.metric("Source Packets (spkts)", feats.get('spkts', 0))
            st.metric("Destination Packets (dpkts)", feats.get('dpkts', 0))
        with col_f2:
            st.metric("Source Load (sload)", f"{feats.get('sload', 0.0)/1e6:.3f} Mbps")
            st.metric("Dest Load (dload)", f"{feats.get('dload', 0.0)/1e6:.3f} Mbps")
            st.metric("Packet Rate (rate)", f"{feats.get('rate', 0.0):.2f} pps")
        with col_f3:
            st.metric("Source TTL (sttl)", feats.get('sttl', 64))
            st.metric("Dest TTL (dttl)", feats.get('dttl', 0))
            st.metric("TCP RTT (tcprtt)", f"{feats.get('tcprtt', 0.0)*1000.0:.2f} ms")
        with col_f4:
            st.metric("ct_srv_dst", feats.get('ct_srv_dst', 1))
            st.metric("ct_dst_src_ltm", feats.get('ct_dst_src_ltm', 1))
            st.metric("ct_src_ltm", feats.get('ct_src_ltm', 1))
            
        # Expand full engineered feature set
        with st.expander("Show all engineered flow features"):
            st.json(feats)
else:
    st.info("No flow data captured yet. Start simulation or upload a PCAP file to explore flow features.")
