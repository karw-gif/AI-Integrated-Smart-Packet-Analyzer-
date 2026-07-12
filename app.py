import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import tempfile
import altair as alt
from feature_extractor import FeatureExtractor

# We import nfstream conditionally in case the system environment fails to compile C dependencies,
# allowing the Simulator/Demo mode to run gracefully regardless.
try:
    from nfstream import NFStreamer, NFPlugin
    NFSTREAM_AVAILABLE = True
except ImportError:
    NFSTREAM_AVAILABLE = False
    # Mock class so the file compiles if nfstream is missing
    class NFPlugin:
        pass

# Define Custom NFStream Plugin to extract TCP handshake metrics and TTLs
if NFSTREAM_AVAILABLE:
    class SecurityPlugin(NFPlugin):
        def on_init(self, packet, flow):
            # Capture initial TTL and Window sizes
            flow.udps.src_ttl = packet.ip_ttl if packet.ip_version else 64
            flow.udps.dst_ttl = 0
            flow.udps.src_win = packet.tcp_window if packet.tcp_flags else 0
            flow.udps.dst_win = 0
            flow.udps.src_tcp_seq = packet.tcp_seq if packet.tcp_flags else 0
            flow.udps.dst_tcp_seq = 0
            flow.udps.tcp_rtt = 0.0
            flow.udps.synack = 0.0
            flow.udps.ackdat = 0.0
            flow.udps.tcp_flags_sum = packet.tcp_flags if packet.tcp_flags else 0
            
            # Check if packet is TCP SYN
            flow.udps.handshake_start = packet.time if packet.tcp_flags and (packet.tcp_flags & 0x02) else 0
            flow.udps.handshake_synack = 0
            flow.udps.handshake_ack = 0

        def on_update(self, packet, flow):
            if packet.tcp_flags:
                flow.udps.tcp_flags_sum |= packet.tcp_flags
            
            # Destination to Source (Response)
            if packet.direction == 1:
                if flow.udps.dst_ttl == 0:
                    flow.udps.dst_ttl = packet.ip_ttl if packet.ip_version else 64
                if packet.tcp_flags:
                    flow.udps.dst_win = packet.tcp_window
                    flow.udps.dst_tcp_seq = packet.tcp_seq
                
                # Check for SYN-ACK
                if packet.tcp_flags and (packet.tcp_flags & 0x12) == 0x12:
                    flow.udps.handshake_synack = packet.time
            # Source to Destination (Request / Completion)
            else:
                # Check for ACK completing handshake
                if (packet.tcp_flags and (packet.tcp_flags & 0x10) and 
                    flow.udps.handshake_synack > 0 and flow.udps.handshake_ack == 0):
                    flow.udps.handshake_ack = packet.time
                    
                    # Convert ms timestamp differences to seconds
                    flow.udps.synack = (flow.udps.handshake_synack - flow.udps.handshake_start) / 1000.0
                    flow.udps.ackdat = (flow.udps.handshake_ack - flow.udps.handshake_synack) / 1000.0
                    flow.udps.tcp_rtt = flow.udps.synack + flow.udps.ackdat

# Page Config
st.set_page_config(
    page_title="Antigravity CyberNetwork Analyzer",
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
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='cyber-title'>🛡️ CYBER-NETWORK INTRUSION DETECTION SYSTEM</h1>", unsafe_allow_html=True)

# Cache model loading
@st.cache_resource
def load_feature_extractor():
    return FeatureExtractor(
        model_path='xgboost_network_model.pkl',
        encoders_path='label_encoders.pkl',
        columns_path='feature_columns.pkl'
    )

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
    ["🖥️ Simulator (Demo Mode)", "📂 Offline PCAP Analysis", "🔌 Live Interface Capture"]
)

# Confidence Threshold Slider
confidence_threshold = st.sidebar.slider(
    "Alert Confidence Threshold",
    min_value=0.50,
    max_value=0.99,
    value=0.75,
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
        <div class="metric-label">Security Alerts</div>
    </div>
    """, unsafe_allow_html=True)
    
    ratio_placeholder.markdown(f"""
    <div class="metric-container">
        <div class="metric-value {'danger' if ratio > 5 else 'safe'}">{ratio:.2f}%</div>
        <div class="metric-label">Intrusion Ratio</div>
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
        "Use this mode to see the dashboard in action."
    )
    
    col_c1, col_c2 = st.columns([1, 4])
    with col_c1:
        run_sim = st.button("🚀 Start Simulation", use_container_width=True)
        stop_sim = st.button("⏹️ Stop", use_container_width=True)
        clear_sim = st.button("🗑️ Clear Dashboard", on_click=clear_session_data, use_container_width=True)
        sim_speed = st.slider("Simulation Delay (s)", 0.1, 2.0, 0.5)
        
    with col_c2:
        # Load sample data
        @st.cache_data
        def load_simulator_dataset():
            df = pd.read_csv('data/NB_testing-set.csv')
            return df
        
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
        sim_records = sim_df.to_dict('records')
        
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
            
            # Format display record
            flow_info = {
                'timestamp': time.strftime("%H:%M:%S"),
                'src_ip': mock_flow.src_ip,
                'src_port': mock_flow.src_port,
                'dst_ip': mock_flow.dst_ip,
                'dst_port': mock_flow.dst_port,
                'protocol': 'TCP' if mock_flow.protocol == 6 else ('UDP' if mock_flow.protocol == 17 else 'ICMP'),
                'service': pred['features']['service'],
                'duration': f"{pred['features']['dur']:.6f}s",
                'bytes': pred['features']['sbytes'] + pred['features']['dbytes'],
                'prediction': '🚨 ATTACK' if (pred['label'] == 1 and pred['confidence'] >= confidence_threshold) else '🟢 NORMAL',
                'confidence': f"{pred['confidence']*100:.2f}%",
                'raw_confidence': pred['confidence'],
                'raw_label': pred['label'],
                'details': pred['features']
            }
            
            st.session_state.flows.append(flow_info)
            st.session_state.total_bytes += flow_info['bytes']
            
            if pred['label'] == 1 and pred['confidence'] >= confidence_threshold:
                st.session_state.alerts.append(flow_info)
                
            # Keep lists trimmed for dashboard performance
            if len(st.session_state.flows) > 500:
                st.session_state.flows.pop(0)
            
            update_dashboard_metrics()
            
            # Draw Timeline Chart
            df_flows = pd.DataFrame(st.session_state.flows)
            if not df_flows.empty:
                chart_data = df_flows.groupby(['timestamp', 'prediction']).size().reset_index(name='count')
                timeline_chart = alt.Chart(chart_data).mark_line(point=True).encode(
                    x='timestamp:N',
                    y='count:Q',
                    color=alt.Color('prediction:N', scale=alt.Scale(domain=['🚨 ATTACK', '🟢 NORMAL'], range=['#ef4444', '#10b981'])),
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
                df_alerts = pd.DataFrame(st.session_state.alerts)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'confidence']]
                alerts_table_placeholder.dataframe(df_alerts.tail(10), use_container_width=True)
            else:
                alerts_table_placeholder.info("No security alerts triggered.")
                
            # Update Flows Table
            df_display = df_flows[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'confidence']]
            flows_table_placeholder.dataframe(df_display.tail(15), use_container_width=True)
            
            idx += 1
            time.sleep(sim_speed)
            
            # Handle manual stop via session state
            if stop_sim:
                st.session_state.running = False
                status_box.warning("Simulation stopped.")
                break

elif analysis_mode == "📂 Offline PCAP Analysis":
    st.subheader("📁 Offline Packet Capture Audit")
    
    if not NFSTREAM_AVAILABLE:
        st.error("❌ NFStream is not installed or failed to compile on this system. PCAP parsing is disabled.")
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
            # We instantiate NFStreamer with our SecurityPlugin to collect TCP handshakes and TTLs
            streamer = NFStreamer(
                source=tmp_path,
                udps=SecurityPlugin(),
                statistical_analysis=True
            )
            
            flows_list = []
            alerts_list = []
            
            for flow in streamer:
                pred = extractor.predict_flow(flow)
                
                flow_info = {
                    'src_ip': flow.src_ip,
                    'src_port': flow.src_port,
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'protocol': 'TCP' if flow.protocol == 6 else ('UDP' if flow.protocol == 17 else 'ICMP'),
                    'service': pred['features']['service'],
                    'duration': f"{pred['features']['dur']:.6f}s",
                    'bytes': pred['features']['sbytes'] + pred['features']['dbytes'],
                    'prediction': '🚨 ATTACK' if (pred['label'] == 1 and pred['confidence'] >= confidence_threshold) else '🟢 NORMAL',
                    'confidence': f"{pred['confidence']*100:.2f}%",
                    'raw_confidence': pred['confidence'],
                    'raw_label': pred['label'],
                    'details': pred['features']
                }
                
                flows_list.append(flow_info)
                st.session_state.total_bytes += flow_info['bytes']
                if pred['label'] == 1 and pred['confidence'] >= confidence_threshold:
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
                        color=alt.Color('prediction:N', scale=alt.Scale(domain=['🚨 ATTACK', '🟢 NORMAL'], range=['#ef4444', '#10b981'])),
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
                    df_a = pd.DataFrame(alerts_list)[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'confidence']]
                    st.dataframe(df_a, use_container_width=True)
                else:
                    st.info("No security anomalies detected in this capture file.")
                    
                st.markdown("### 🔍 Full Flow Explorer")
                df_disp = df_pcap[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'confidence']]
                st.dataframe(df_disp, use_container_width=True)
                
        except Exception as e:
            st.error(f"Error parsing PCAP: {e}")
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

elif analysis_mode == "🔌 Live Interface Capture":
    st.subheader("🔌 Real-time Live Network Capture")
    
    if not NFSTREAM_AVAILABLE:
        st.error("❌ NFStream is not installed or failed to compile on this system. Live capture is disabled.")
        st.stop()
        
    st.warning(
        "⚠️ **Permissions Notice**: Live capture requires net_raw capabilities. "
        "If you are running in a standard user space or container, this might fail "
        "unless the application has appropriate permissions (e.g., sudo)."
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
            
        st.markdown("### 🔔 Active Intrusion Alerts")
        live_alerts_table = st.empty()
        
        st.markdown("### 🔍 Live Flow Inspector")
        live_flows_table = st.empty()
        
        try:
            # Initiate NFStreamer on the network interface
            streamer = NFStreamer(
                source=interface_name,
                udps=SecurityPlugin(),
                statistical_analysis=True,
                promiscuous_mode=True
            )
            
            count = 0
            for flow in streamer:
                pred = extractor.predict_flow(flow)
                
                flow_info = {
                    'timestamp': time.strftime("%H:%M:%S"),
                    'src_ip': flow.src_ip,
                    'src_port': flow.src_port,
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'protocol': 'TCP' if flow.protocol == 6 else ('UDP' if flow.protocol == 17 else 'ICMP'),
                    'service': pred['features']['service'],
                    'duration': f"{pred['features']['dur']:.6f}s",
                    'bytes': pred['features']['sbytes'] + pred['features']['dbytes'],
                    'prediction': '🚨 ATTACK' if (pred['label'] == 1 and pred['confidence'] >= confidence_threshold) else '🟢 NORMAL',
                    'confidence': f"{pred['confidence']*100:.2f}%",
                    'raw_confidence': pred['confidence'],
                    'raw_label': pred['label'],
                    'details': pred['features']
                }
                
                st.session_state.flows.append(flow_info)
                st.session_state.total_bytes += flow_info['bytes']
                if pred['label'] == 1 and pred['confidence'] >= confidence_threshold:
                    st.session_state.alerts.append(flow_info)
                
                # Truncate older records to fit display memory
                if len(st.session_state.flows) > 300:
                    st.session_state.flows.pop(0)
                    
                update_dashboard_metrics()
                
                # Render Charts
                df_live = pd.DataFrame(st.session_state.flows)
                if not df_live.empty:
                    # Timeline
                    c_data = df_live.groupby(['timestamp', 'prediction']).size().reset_index(name='count')
                    line_c = alt.Chart(c_data).mark_line(point=True).encode(
                        x='timestamp:N',
                        y='count:Q',
                        color=alt.Color('prediction:N', scale=alt.Scale(domain=['🚨 ATTACK', '🟢 NORMAL'], range=['#ef4444', '#10b981'])),
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
                    df_la = pd.DataFrame(st.session_state.alerts)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'confidence']]
                    live_alerts_table.dataframe(df_la.tail(8), use_container_width=True)
                else:
                    live_alerts_table.info("Listening... No threats detected yet.")
                    
                df_lf = pd.DataFrame(st.session_state.flows)[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service', 'bytes', 'prediction', 'confidence']]
                live_flows_table.dataframe(df_lf.tail(12), use_container_width=True)
                
                count += 1
                if count >= flow_limit:
                    st.success("Reached flow capture limit.")
                    break
                    
        except Exception as e:
            st.error(f"Error during live capture: {e}")
            st.info("Check interface name or permissions. Make sure to run Streamlit with sufficient capture privileges.")

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
            st.markdown(f"**Confidence**: `{sel_flow['confidence']}`")
            
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
            
        # Expand full 42 features
        with st.expander("Show all 42 features fed to XGBoost model"):
            st.json(feats)
else:
    st.info("No flow data captured yet. Start simulation or upload a PCAP file to explore flow features.")
