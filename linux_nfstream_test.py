"""
Linux integration test for the NFStream capture path.

Runs the real NFStream engine (with the same SecurityPlugin the dashboard
uses) against data/test_traffic.pcap and pushes every flow through the
FeatureExtractor + XGBoost models. Exits non-zero on any failure so CI
can gate on it.

Run (Linux):  python linux_nfstream_test.py
"""
import sys

from nfstream import NFStreamer
from nfplugin import SecurityPlugin
from feature_extractor import FeatureExtractor


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
