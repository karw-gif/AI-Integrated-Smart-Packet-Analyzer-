"""Smoke test for the downloadable PDF security report."""

from pdf_report import generate_security_report


def main():
    flows = [
        {"timestamp": "12:00:00", "src_ip": "192.168.1.10", "src_port": 51515,
         "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "service": "dns",
         "bytes": 450, "prediction": "NORMAL", "attack_type": "-", "severity": "-",
         "confidence": "99.10%"},
        {"timestamp": "12:00:01", "src_ip": "10.0.0.5", "src_port": 40000,
         "dst_ip": "192.168.1.20", "dst_port": 22, "protocol": "TCP", "service": "ssh",
         "bytes": 1200, "prediction": "ATTACK", "attack_type": "Reconnaissance",
         "severity": "HIGH", "confidence": "97.20%"},
    ]
    alerts = [flows[1]]
    for anonymize in (False, True):
        pdf = generate_security_report(flows, alerts, "Automated smoke test", 0.75, anonymize)
        assert pdf.startswith(b"%PDF-"), "output is not a PDF"
        assert len(pdf) > 3000, "generated PDF is unexpectedly small"
    print("PDF report smoke test passed")


if __name__ == "__main__":
    main()
