"""
Linux integration test for the NFStream capture path.

Runs the real NFStream engine (with the same SecurityPlugin the dashboard
uses) against data/test_traffic.pcap and pushes every flow through the
FeatureExtractor + XGBoost models. Exits non-zero on any failure so CI
can gate on it.

Run (Linux):  python linux_nfstream_test.py
"""
import sys

from nfstream import NFStreamer, NFPlugin
from feature_extractor import FeatureExtractor


class SecurityPlugin(NFPlugin):
    """Same plugin as app.py: TCP handshake timing, TTLs, windows, flags."""

    def on_init(self, packet, flow):
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
        flow.udps.handshake_start = packet.time if packet.tcp_flags and (packet.tcp_flags & 0x02) else 0
        flow.udps.handshake_synack = 0
        flow.udps.handshake_ack = 0

    def on_update(self, packet, flow):
        if packet.tcp_flags:
            flow.udps.tcp_flags_sum |= packet.tcp_flags
        if packet.direction == 1:
            if flow.udps.dst_ttl == 0:
                flow.udps.dst_ttl = packet.ip_ttl if packet.ip_version else 64
            if packet.tcp_flags:
                flow.udps.dst_win = packet.tcp_window
                flow.udps.dst_tcp_seq = packet.tcp_seq
            if packet.tcp_flags and (packet.tcp_flags & 0x12) == 0x12:
                flow.udps.handshake_synack = packet.time
        else:
            if (packet.tcp_flags and (packet.tcp_flags & 0x10) and
                    flow.udps.handshake_synack > 0 and flow.udps.handshake_ack == 0):
                flow.udps.handshake_ack = packet.time
                flow.udps.synack = (flow.udps.handshake_synack - flow.udps.handshake_start) / 1000.0
                flow.udps.ackdat = (flow.udps.handshake_ack - flow.udps.handshake_synack) / 1000.0
                flow.udps.tcp_rtt = flow.udps.synack + flow.udps.ackdat


def main():
    print("Loading FeatureExtractor + models...")
    extractor = FeatureExtractor()

    print("Parsing data/test_traffic.pcap with NFStream...")
    streamer = NFStreamer(source='data/test_traffic.pcap',
                          udps=SecurityPlugin(),
                          statistical_analysis=True)

    n_flows = 0
    n_attacks = 0
    dns_normal = False
    scan_flagged = 0
    for flow in streamer:
        pred = extractor.predict_flow(flow)
        n_flows += 1
        label = f"ATTACK {pred['attack_cat']}" if pred['label'] else 'NORMAL'
        print(f"  {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
              f"svc={pred['features']['service']} => {label} ({pred['confidence']*100:.1f}%)")
        if pred['label'] == 1:
            n_attacks += 1
            if flow.src_ip == '10.66.6.66':
                scan_flagged += 1
        if flow.dst_port == 53 and pred['label'] == 0:
            dns_normal = True

    print(f"\nParsed {n_flows} flows, {n_attacks} flagged as attacks, "
          f"{scan_flagged}/10 SYN-scan flows detected.")

    assert n_flows >= 10, f"Expected >=10 flows from the test pcap, got {n_flows}"
    assert dns_normal, "Benign DNS flow was misclassified as an attack"
    assert scan_flagged >= 7, f"SYN scan under-detected: only {scan_flagged}/10 flagged"
    print("\nLinux NFStream integration test PASSED ✔")


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print(f"\nFAILED: {e}")
        sys.exit(1)
