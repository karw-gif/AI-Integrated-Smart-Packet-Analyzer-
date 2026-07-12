"""
Cross-platform packet-to-flow engine (Scapy fallback).

NFStream is the preferred capture backend but does not build on Windows.
This module provides a pure-Python fallback built on Scapy that produces
flow objects with the exact attribute surface FeatureExtractor expects,
so Offline PCAP analysis (and basic live capture, if Npcap/libpcap is
present) works on Windows, Linux, and macOS alike.

Flow attribute contract (mirrors NFStream + SecurityPlugin):
    src_ip, dst_ip, src_port, dst_port, protocol, application_name,
    bidirectional_duration_ms, bidirectional_packets,
    src2dst_packets, dst2src_packets, src2dst_bytes, dst2src_bytes,
    src2dst_mean_piat_ms, dst2src_mean_piat_ms,
    src2dst_stddev_piat_ms, dst2src_stddev_piat_ms,
    udps.{src_ttl, dst_ttl, src_win, dst_win, src_tcp_seq, dst_tcp_seq,
          tcp_rtt, synack, ackdat, tcp_flags_sum}
"""
import math
import statistics

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Well-known ports -> nDPI-style application labels understood by FeatureExtractor
PORT_APPS = {
    53: 'DNS', 80: 'HTTP', 443: 'TLS', 21: 'FTP', 20: 'FTP',
    22: 'SSH', 25: 'SMTP', 67: 'DHCP', 68: 'DHCP', 161: 'SNMP',
    162: 'SNMP', 110: 'POP3', 995: 'POP3', 194: 'IRC', 6667: 'IRC',
}


class _UDPS:
    """Container for the user-defined per-flow state (mirrors NFStream udps)."""
    def __init__(self):
        self.src_ttl = 64
        self.dst_ttl = 0
        self.src_win = 0
        self.dst_win = 0
        self.src_tcp_seq = 0
        self.dst_tcp_seq = 0
        self.tcp_rtt = 0.0
        self.synack = 0.0
        self.ackdat = 0.0
        self.tcp_flags_sum = 0


class ScapyFlow:
    """Aggregates packets of one bidirectional 5-tuple into flow statistics."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, first_ts):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.udps = _UDPS()
        self._first_ts = first_ts
        self._last_ts = first_ts
        self._src_times = []
        self._dst_times = []
        self._syn_ts = 0.0
        self._synack_ts = 0.0
        self._ack_ts = 0.0

        self.src2dst_packets = 0
        self.dst2src_packets = 0
        self.src2dst_bytes = 0
        self.dst2src_bytes = 0

        app = PORT_APPS.get(dst_port) or PORT_APPS.get(src_port)
        self.application_name = app if app else '-'

    def add_packet(self, pkt, ts, from_src):
        ip = pkt[IP]
        size = len(pkt)
        self._last_ts = ts

        if from_src:
            self.src2dst_packets += 1
            self.src2dst_bytes += size
            self._src_times.append(ts)
        else:
            self.dst2src_packets += 1
            self.dst2src_bytes += size
            self._dst_times.append(ts)
            if self.udps.dst_ttl == 0:
                self.udps.dst_ttl = ip.ttl

        if from_src and self.src2dst_packets == 1:
            self.udps.src_ttl = ip.ttl

        if TCP in pkt:
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            self.udps.tcp_flags_sum |= flags
            if from_src:
                if self.udps.src_win == 0:
                    self.udps.src_win = tcp.window
                if self.udps.src_tcp_seq == 0:
                    self.udps.src_tcp_seq = tcp.seq
            else:
                if self.udps.dst_win == 0:
                    self.udps.dst_win = tcp.window
                if self.udps.dst_tcp_seq == 0:
                    self.udps.dst_tcp_seq = tcp.seq

            # TCP handshake timing (SYN -> SYN/ACK -> ACK)
            if flags & 0x02 and not flags & 0x10 and from_src and not self._syn_ts:
                self._syn_ts = ts
            elif (flags & 0x12) == 0x12 and not from_src and not self._synack_ts:
                self._synack_ts = ts
            elif (flags & 0x10) and from_src and self._synack_ts and not self._ack_ts:
                self._ack_ts = ts
                self.udps.synack = self._synack_ts - self._syn_ts if self._syn_ts else 0.0
                self.udps.ackdat = self._ack_ts - self._synack_ts
                self.udps.tcp_rtt = self.udps.synack + self.udps.ackdat

    def finalize(self):
        """Compute derived statistics once all packets are added."""
        self.bidirectional_packets = self.src2dst_packets + self.dst2src_packets
        self.bidirectional_duration_ms = max(0.0, (self._last_ts - self._first_ts) * 1000.0)

        def piat_stats(times):
            if len(times) < 2:
                return 0.0, 0.0
            gaps = [(t2 - t1) * 1000.0 for t1, t2 in zip(times, times[1:])]
            mean = sum(gaps) / len(gaps)
            std = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
            return mean, std

        self.src2dst_mean_piat_ms, self.src2dst_stddev_piat_ms = piat_stats(self._src_times)
        self.dst2src_mean_piat_ms, self.dst2src_stddev_piat_ms = piat_stats(self._dst_times)
        return self


def _flow_key(ip_layer, sport, dport):
    """Direction-agnostic key so both directions map to one flow."""
    a = (ip_layer.src, sport)
    b = (ip_layer.dst, dport)
    return (min(a, b), max(a, b), ip_layer.proto)


def flows_from_packets(packets):
    """Aggregate an iterable of (scapy_packet) into finalized ScapyFlow objects."""
    flows = {}
    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            sport, dport = 0, 0
        else:
            sport, dport = 0, 0

        ts = float(pkt.time)
        key = _flow_key(ip, sport, dport)
        flow = flows.get(key)
        if flow is None:
            flow = ScapyFlow(ip.src, ip.dst, sport, dport, ip.proto, ts)
            flows[key] = flow
        from_src = (ip.src == flow.src_ip and sport == flow.src_port)
        flow.add_packet(pkt, ts, from_src)

    return [f.finalize() for f in flows.values()]


def read_pcap(path):
    """Parse a .pcap/.pcapng file into flow objects. Pure Python — works everywhere."""
    with PcapReader(path) as reader:
        return flows_from_packets(reader)


def sniff_live(interface=None, packet_count=200, timeout=30):
    """
    Capture live packets and aggregate into flows.
    Requires Npcap on Windows or libpcap/root on Linux.
    Returns the flow list when packet_count packets are seen or timeout expires.
    """
    from scapy.sendrecv import sniff
    packets = sniff(iface=interface or None, count=packet_count, timeout=timeout,
                    filter="ip")
    return flows_from_packets(packets)
