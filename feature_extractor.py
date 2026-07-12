import os
import joblib
import pandas as pd
import numpy as np
from collections import deque

# Standard IANA protocol number to lowercase string mapping
PROTO_MAP = {
    0: 'hopopt', 1: 'icmp', 2: 'igmp', 3: 'ggp', 4: 'ipip', 5: 'st', 6: 'tcp',
    7: 'cbt', 8: 'egp', 9: 'igp', 12: 'pup', 17: 'udp', 22: 'xns-idp',
    27: 'rdp', 29: 'iso-tp4', 36: 'xtp', 41: 'ipv6', 43: 'ipv6-route',
    44: 'ipv6-frag', 46: 'rsvp', 47: 'gre', 50: 'esp', 51: 'ah', 58: 'ipv6-icmp',
    59: 'ipv6-no', 60: 'ipv6-opts', 80: 'iso-ip', 88: 'eigrp', 89: 'ospf',
    94: 'ipip', 97: 'etherip', 98: 'encap', 103: 'pim', 108: 'ipcomp',
    112: 'vrrp', 115: 'l2tp', 132: 'sctp'
}

class FlowMemory:
    """
    Maintains a sliding window of the last 100 flows to compute connection count-based metrics
    as defined in the UNSW-NB15 dataset.
    """
    def __init__(self, window_size=100):
        self.history = deque(maxlen=window_size)

    def add_flow(self, flow_summary):
        self.history.append(flow_summary)

    def compute_counts(self, current_flow):
        src = current_flow['src_ip']
        dst = current_flow['dst_ip']
        sport = current_flow['src_port']
        dport = current_flow['dst_port']
        srv = current_flow['service']
        st = current_flow['state']
        sttl = current_flow['sttl']

        ct_srv_src = 0
        ct_state_ttl = 0
        ct_dst_ltm = 0
        ct_src_dport_ltm = 0
        ct_dst_sport_ltm = 0
        ct_dst_src_ltm = 0
        ct_src_ltm = 0
        ct_srv_dst = 0

        for f in self.history:
            # ct_srv_src: count of same service and source address
            if f['service'] == srv and f['src_ip'] == src:
                ct_srv_src += 1
            # ct_state_ttl: count of same state and TTL
            if f['state'] == st and f['sttl'] == sttl:
                ct_state_ttl += 1
            # ct_dst_ltm: count of same destination address
            if f['dst_ip'] == dst:
                ct_dst_ltm += 1
            # ct_src_dport_ltm: count of same source address and destination port
            if f['src_ip'] == src and f['dst_port'] == dport:
                ct_src_dport_ltm += 1
            # ct_dst_sport_ltm: count of same destination address and source port
            if f['dst_ip'] == dst and f['src_port'] == sport:
                ct_dst_sport_ltm += 1
            # ct_dst_src_ltm: count of same destination and source address
            if f['dst_ip'] == dst and f['src_ip'] == src:
                ct_dst_src_ltm += 1
            # ct_src_ltm: count of same source address
            if f['src_ip'] == src:
                ct_src_ltm += 1
            # ct_srv_dst: count of same service and destination address
            if f['service'] == srv and f['dst_ip'] == dst:
                ct_srv_dst += 1

        return {
            'ct_srv_src': max(1, ct_srv_src),
            'ct_state_ttl': max(1, ct_state_ttl),
            'ct_dst_ltm': max(1, ct_dst_ltm),
            'ct_src_dport_ltm': max(1, ct_src_dport_ltm),
            'ct_dst_sport_ltm': max(1, ct_dst_sport_ltm),
            'ct_dst_src_ltm': max(1, ct_dst_src_ltm),
            'ct_src_ltm': max(1, ct_src_ltm),
            'ct_srv_dst': max(1, ct_srv_dst)
        }


class FeatureExtractor:
    """
    Handles feature mapping, encoding, and model inference for cybersecurity threat detection.
    """
    def __init__(self, model_path='xgboost_network_model.pkl',
                 encoders_path='label_encoders.pkl',
                 columns_path='feature_columns.pkl'):
        
        self.model = joblib.load(model_path)
        self.label_encoders = joblib.load(encoders_path)
        self.expected_features = joblib.load(columns_path)
        self.memory = FlowMemory(window_size=100)

    def map_nfstream_flow(self, flow):
        """
        Maps an NFStream flow object's attributes to a dictionary of UNSW-NB15 base features.
        """
        # Duration in seconds
        dur = flow.bidirectional_duration_ms / 1000.0

        # Protocol mapping
        proto_num = flow.protocol
        proto = PROTO_MAP.get(proto_num, str(proto_num)).lower()

        # Service mapping using DPI (nDPI application name) and port fallbacks
        service = '-'
        app_name = getattr(flow, 'application_name', '').upper()
        if 'HTTP' in app_name:
            service = 'http'
        elif 'DNS' in app_name:
            service = 'dns'
        elif 'FTP' in app_name:
            service = 'ftp'
        elif 'SSH' in app_name:
            service = 'ssh'
        elif 'SSL' in app_name or 'TLS' in app_name:
            service = 'ssl'
        elif 'SMTP' in app_name:
            service = 'smtp'
        elif 'DHCP' in app_name:
            service = 'dhcp'
        elif 'SNMP' in app_name:
            service = 'snmp'
        elif 'POP3' in app_name:
            service = 'pop3'
        elif 'IRC' in app_name:
            service = 'irc'
        else:
            # Port fallback
            ports = {53: 'dns', 80: 'http', 443: 'ssl', 21: 'ftp', 20: 'ftp-data',
                     22: 'ssh', 25: 'smtp', 67: 'dhcp', 68: 'dhcp', 161: 'snmp',
                     162: 'snmp', 110: 'pop3', 995: 'pop3', 194: 'irc', 6667: 'irc'}
            if flow.dst_port in ports:
                service = ports[flow.dst_port]
            elif flow.src_port in ports:
                service = ports[flow.src_port]

        # TCP window, TTL, and flags from custom plugin or default
        sttl = getattr(flow.udps, 'src_ttl', 64)
        dttl = getattr(flow.udps, 'dst_ttl', 0)
        swin = getattr(flow.udps, 'src_win', 0)
        dwin = getattr(flow.udps, 'dst_win', 0)
        stcpb = getattr(flow.udps, 'src_tcp_seq', 0)
        dtcpb = getattr(flow.udps, 'dst_tcp_seq', 0)
        tcprtt = getattr(flow.udps, 'tcp_rtt', 0.0)
        synack = getattr(flow.udps, 'synack', 0.0)
        ackdat = getattr(flow.udps, 'ackdat', 0.0)
        
        # State mapping based on connection details and protocol
        state = 'CON'
        flags = getattr(flow.udps, 'tcp_flags_sum', 0)
        if proto_num == 6:  # TCP
            if flags & 0x04:  # RST
                state = 'RST'
            elif flags & 0x01:  # FIN
                state = 'FIN'
            elif flow.dst2src_packets == 0:
                state = 'REQ'
        else:  # UDP / ICMP
            if flow.dst2src_packets == 0:
                state = 'INT'

        # Basic packet and byte rates
        spkts = flow.src2dst_packets
        dpkts = flow.dst2src_packets
        sbytes = flow.src2dst_bytes
        dbytes = flow.dst2src_bytes
        rate = flow.bidirectional_packets / (dur + 1e-6)

        # Loads (bits per second)
        sload = (sbytes * 8) / (dur + 1e-6)
        dload = (dbytes * 8) / (dur + 1e-6)

        # Loss (packet loss / retransmissions) - approximated as 0 if not tracked
        sloss = 0
        dloss = 0

        # Mean packet sizes
        smean = flow.src2dst_bytes / (spkts + 1e-6)
        dmean = flow.dst2src_bytes / (dpkts + 1e-6)

        # Inter-packet arrival times (in ms)
        sinpkt = getattr(flow, 'src2dst_mean_piat_ms', 0.0)
        dinpkt = getattr(flow, 'dst2src_mean_piat_ms', 0.0)
        sjit = getattr(flow, 'src2dst_stddev_piat_ms', 0.0)
        djit = getattr(flow, 'dst2src_stddev_piat_ms', 0.0)

        # FTP / HTTP specific features
        is_ftp_login = 1 if service == 'ftp' and (sbytes > 100 or dbytes > 100) else 0
        ct_ftp_cmd = 0
        ct_flw_http_mthd = 1 if service == 'http' else 0
        trans_depth = 1 if service == 'http' else 0
        response_body_len = dbytes if service == 'http' else 0
        
        is_sm_ips_ports = 1 if (flow.src_ip == flow.dst_ip and flow.src_port == flow.dst_port) else 0

        base_flow = {
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'dur': dur,
            'proto': proto,
            'service': service,
            'state': state,
            'spkts': spkts,
            'dpkts': dpkts,
            'sbytes': sbytes,
            'dbytes': dbytes,
            'rate': rate,
            'sttl': sttl,
            'dttl': dttl,
            'sload': sload,
            'dload': dload,
            'sloss': sloss,
            'dloss': dloss,
            'sinpkt': sinpkt,
            'dinpkt': dinpkt,
            'sjit': sjit,
            'djit': djit,
            'swin': swin,
            'stcpb': stcpb,
            'dtcpb': dtcpb,
            'dwin': dwin,
            'tcprtt': tcprtt,
            'synack': synack,
            'ackdat': ackdat,
            'smean': smean,
            'dmean': dmean,
            'trans_depth': trans_depth,
            'response_body_len': response_body_len,
            'is_ftp_login': is_ftp_login,
            'ct_ftp_cmd': ct_ftp_cmd,
            'ct_flw_http_mthd': ct_flw_http_mthd,
            'is_sm_ips_ports': is_sm_ips_ports
        }
        return base_flow

    def preprocess(self, flow_dict):
        """
        Applies Label Encoding, handles unseen classes, structure features in the exact
        sequence, and returns a DataFrame suitable for XGBoost inference.
        """
        df = pd.DataFrame([flow_dict])
        
        # Keep copy of metadata before dropping/encoding
        meta = {
            'src_ip': flow_dict['src_ip'],
            'dst_ip': flow_dict['dst_ip'],
            'src_port': flow_dict['src_port'],
            'dst_port': flow_dict['dst_port'],
        }

        # Encode categorical variables using loaded encoders
        for col, le in self.label_encoders.items():
            if col in df.columns:
                val = str(df.loc[0, col])
                # Handle unseen values gracefully like in training (-1)
                if val in le.classes_:
                    df[col] = le.transform([val])[0]
                else:
                    df[col] = -1

        # Select only expected features in the exact training order
        X = df[self.expected_features]
        return X, meta

    def predict_flow(self, flow):
        """
        Full pipeline: extracts base features, calculates window counts, preprocesses,
        and predicts the threat status of a flow.
        """
        # 1. Extract base flow features
        flow_data = self.map_nfstream_flow(flow)

        # 2. Compute count-based sliding window metrics
        counts = self.memory.compute_counts(flow_data)
        flow_data.update(counts)

        # 3. Add to sliding window history for future flows
        self.memory.add_flow(flow_data)

        # 4. Preprocess for XGBoost
        X, meta = self.preprocess(flow_data)

        # 5. Model Inference
        # Get raw probability
        prob = self.model.predict_proba(X)[0][1]
        label = int(self.model.predict(X)[0])

        return {
            'label': label,
            'confidence': float(prob if label == 1 else 1.0 - prob),
            'features': flow_data,
            'meta': meta
        }
