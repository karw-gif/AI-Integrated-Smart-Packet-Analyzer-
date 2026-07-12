import sys
from feature_extractor import FeatureExtractor

class MockFlow:
    """
    Mock class representing an NFStream flow object for testing the pipeline.
    """
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        # Create a nested object for user-defined properties
        self.udps = type('UDPS', (), {})()

def main():
    print("Initializing FeatureExtractor...")
    try:
        extractor = FeatureExtractor(
            model_path='xgboost_network_model.pkl',
            encoders_path='label_encoders.pkl',
            columns_path='feature_columns.pkl'
        )
        print("FeatureExtractor loaded successfully!")
    except Exception as e:
        print(f"Error loading model/artifacts: {e}")
        sys.exit(1)

    # Construct a mock flow representing normal UDP DNS traffic
    # This matches the structure of flow records processed by NFStream
    normal_dns_flow = MockFlow(
        bidirectional_duration_ms=11, # 11 ms
        protocol=17,                  # UDP
        application_name='DNS',
        src_port=52345,
        dst_port=53,
        src_ip='192.168.1.15',
        dst_ip='8.8.8.8',
        src2dst_packets=2,
        dst2src_packets=2,
        src2dst_bytes=150,
        dst2src_bytes=300,
        bidirectional_packets=4
    )
    # Set custom plugin fields
    normal_dns_flow.udps.src_ttl = 64
    normal_dns_flow.udps.dst_ttl = 56
    normal_dns_flow.udps.src_win = 0
    normal_dns_flow.udps.dst_win = 0
    normal_dns_flow.udps.src_tcp_seq = 0
    normal_dns_flow.udps.dst_tcp_seq = 0
    normal_dns_flow.udps.tcp_rtt = 0.0
    normal_dns_flow.udps.synack = 0.0
    normal_dns_flow.udps.ackdat = 0.0
    normal_dns_flow.udps.tcp_flags_sum = 0

    print("\nRunning prediction on Normal DNS Flow...")
    res = extractor.predict_flow(normal_dns_flow)
    print("Prediction Result:")
    print(f"  Label: {res['label']} ({'Attack' if res['label'] == 1 else 'Normal'})")
    print(f"  Confidence: {res['confidence']:.4f}")
    print(f"  Mapped Features (sample):")
    for k in ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'ct_srv_dst']:
        print(f"    {k}: {res['features'].get(k)}")

    # Construct a mock TCP flow representing a potential attack
    # E.g., very short duration, high volume, unusual state or flag sequence
    malicious_flow = MockFlow(
        bidirectional_duration_ms=1,
        protocol=6, # TCP
        application_name='HTTP',
        src_port=43210,
        dst_port=80,
        src_ip='172.16.0.5',
        dst_ip='192.168.1.10',
        src2dst_packets=10,
        dst2src_packets=0,
        src2dst_bytes=2000,
        dst2src_bytes=0,
        bidirectional_packets=10
    )
    malicious_flow.udps.src_ttl = 254
    malicious_flow.udps.dst_ttl = 0
    malicious_flow.udps.src_win = 1024
    malicious_flow.udps.dst_win = 0
    malicious_flow.udps.src_tcp_seq = 12345678
    malicious_flow.udps.dst_tcp_seq = 0
    malicious_flow.udps.tcp_rtt = 0.0
    malicious_flow.udps.synack = 0.0
    malicious_flow.udps.ackdat = 0.0
    malicious_flow.udps.tcp_flags_sum = 0x02 # SYN only (no ACK back)

    print("\nRunning prediction on Malicious Flow...")
    res2 = extractor.predict_flow(malicious_flow)
    print("Prediction Result:")
    print(f"  Label: {res2['label']} ({'Attack' if res2['label'] == 1 else 'Normal'})")
    print(f"  Confidence: {res2['confidence']:.4f}")
    print(f"  Mapped Features (sample):")
    for k in ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'ct_srv_dst']:
        print(f"    {k}: {res2['features'].get(k)}")

if __name__ == '__main__':
    main()
