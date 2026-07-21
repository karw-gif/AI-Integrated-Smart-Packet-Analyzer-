"""
Generates data/test_traffic.pcap — a synthetic capture with statistically
realistic benign flows (sized to match normal UNSW-NB15 traffic) and
suspicious ones (SYN scan burst) so the Offline PCAP mode can be
demonstrated on any machine without real captures.

Benign flow shapes are matched to the UNSW-NB15 normal medians:
  DNS : 2 pkts / ~146 B each way, ~1 ms
  HTTP: 12 src pkts / 18 dst pkts, ~1.5 KB up / ~10 KB down, ~1 s

Run:  py make_test_pcap.py
"""
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap

packets = []
t = 1000000.0


def at(pkt, ts):
    pkt.time = ts
    return pkt


E = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")

# --- Benign DNS lookup (2 packets each way, UNSW-normal sized) ---
c, r = "192.168.1.20", "8.8.8.8"
q1 = DNS(rd=1, qd=DNSQR(qname="www.example-corporate-site.com", qtype="A"))
q2 = DNS(rd=1, qd=DNSQR(qname="www.example-corporate-site.com", qtype="AAAA"))
packets.append(at(E / IP(src=c, dst=r, ttl=64) / UDP(sport=51000, dport=53) / q1, t))
packets.append(at(E / IP(src=c, dst=r, ttl=64) / UDP(sport=51000, dport=53) / q2, t + 0.0002))
packets.append(at(E / IP(src=r, dst=c, ttl=57) / UDP(sport=53, dport=51000) /
                  DNS(qr=1, qd=q1.qd, an=None) / Raw(b"\x00" * 60), t + 0.0008))
packets.append(at(E / IP(src=r, dst=c, ttl=57) / UDP(sport=53, dport=51000) /
                  DNS(qr=1, qd=q2.qd, an=None) / Raw(b"\x00" * 80), t + 0.0010))

# --- Benign complete HTTP session (handshake + 12/18 pkts + FIN, ~1s) ---
s = "93.184.216.34"
sp, dp = 52000, 80
seq_c, seq_s = 100, 500
t0 = t + 1.0
packets.append(at(E / IP(src=c, dst=s, ttl=64) / TCP(sport=sp, dport=dp, flags="S", seq=seq_c, window=64240), t0))
packets.append(at(E / IP(src=s, dst=c, ttl=54) / TCP(sport=dp, dport=sp, flags="SA", seq=seq_s, ack=seq_c + 1, window=65535), t0 + 0.045))
packets.append(at(E / IP(src=c, dst=s, ttl=64) / TCP(sport=sp, dport=dp, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=64240), t0 + 0.090))

req = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
       b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       b"(KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n"
       b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8\r\n"
       b"Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\n"
       b"Cookie: session=" + b"a" * 400 + b"; prefs=" + b"b" * 300 + b"\r\n"
       b"Connection: keep-alive\r\n\r\n")
packets.append(at(E / IP(src=c, dst=s, ttl=64) / TCP(sport=sp, dport=dp, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(req), t0 + 0.095))

# Server responds with ~10 KB over 14 data packets; client ACKs along the way.
# Gaps are deliberately bursty (real networks are not metronomes) so the flow
# exhibits realistic jitter instead of robotic evenly-spaced timing.
import random
random.seed(42)
ts_cursor = t0 + 0.15
ack_c = seq_c + 1 + len(req)
srv_seq = seq_s + 1
bursty_gaps = [0.004, 0.003, 0.180, 0.005, 0.002, 0.220, 0.004, 0.150,
               0.003, 0.005, 0.190, 0.002, 0.004, 0.160]
for i in range(14):
    payload = b"x" * 700
    packets.append(at(E / IP(src=s, dst=c, ttl=54) /
                      TCP(sport=dp, dport=sp, flags="PA", seq=srv_seq, ack=ack_c) / Raw(payload), ts_cursor))
    srv_seq += len(payload)
    ts_cursor += bursty_gaps[i]
    if i % 2 == 1:  # client ACK every second data packet
        packets.append(at(E / IP(src=c, dst=s, ttl=64) /
                          TCP(sport=sp, dport=dp, flags="A", seq=ack_c, ack=srv_seq), ts_cursor))
        ts_cursor += random.choice([0.002, 0.030, 0.120])

# Graceful close
packets.append(at(E / IP(src=c, dst=s, ttl=64) / TCP(sport=sp, dport=dp, flags="FA", seq=ack_c, ack=srv_seq), ts_cursor + 0.02))
packets.append(at(E / IP(src=s, dst=c, ttl=54) / TCP(sport=dp, dport=sp, flags="FA", seq=srv_seq, ack=ack_c + 1), ts_cursor + 0.06))
packets.append(at(E / IP(src=c, dst=s, ttl=64) / TCP(sport=sp, dport=dp, flags="A", seq=ack_c + 1, ack=srv_seq + 1), ts_cursor + 0.10))

# --- Suspicious: rapid SYN scan from one host against many ports (no replies) ---
for i, port in enumerate([21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]):
    packets.append(at(E / IP(src="10.66.6.66", dst="192.168.1.20", ttl=250) /
                      TCP(sport=40000 + i, dport=port, flags="S", seq=1, window=1024),
                      t + 4.0 + i * 0.001))

wrpcap("data/test_traffic.pcap", packets)
print(f"Wrote data/test_traffic.pcap with {len(packets)} packets")
