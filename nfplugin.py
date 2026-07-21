"""
NFStream SecurityPlugin — extracts TTLs, TCP windows/sequence numbers and
handshake timing from raw packet bytes.

NFStream's NFPacket does NOT expose ip_ttl / tcp_window / tcp_seq / tcp_flags
directly; it provides TCP flag booleans (syn, ack, fin, rst, psh, urg) plus
the raw IP packet bytes. This module parses the missing fields from the raw
header so the FeatureExtractor gets the same per-flow state on Linux (NFStream)
as it does from the Scapy fallback engine.

Import only where nfstream is installed (Linux/macOS).
"""
from nfstream import NFPlugin

# tcp_flags_sum bit layout matches the standard TCP flag byte
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def parse_l3(packet):
    """
    Returns (ttl, tcp_window, tcp_seq, flags_int) parsed from an NFPacket.
    Handles IPv4 and IPv6; window/seq are 0 for non-TCP packets.
    """
    ttl = win = seq = 0
    raw = bytes(packet.ip_packet) if packet.ip_packet else b''

    if packet.ip_version == 4 and len(raw) >= 20:
        ttl = raw[8]
        ihl = (raw[0] & 0x0F) * 4
        if raw[9] == 6 and len(raw) >= ihl + 20:  # TCP
            seq = int.from_bytes(raw[ihl + 4:ihl + 8], 'big')
            win = int.from_bytes(raw[ihl + 14:ihl + 16], 'big')
    elif packet.ip_version == 6 and len(raw) >= 40:
        ttl = raw[7]  # hop limit
        if raw[6] == 6 and len(raw) >= 60:  # next header == TCP
            seq = int.from_bytes(raw[44:48], 'big')
            win = int.from_bytes(raw[54:56], 'big')

    flags = ((SYN if packet.syn else 0) | (ACK if packet.ack else 0) |
             (FIN if packet.fin else 0) | (RST if packet.rst else 0) |
             (PSH if packet.psh else 0) | (URG if packet.urg else 0))
    return ttl, win, seq, flags


class SecurityPlugin(NFPlugin):
    """Collects TTLs, windows, seq numbers and TCP handshake timing per flow."""

    def on_init(self, packet, flow):
        ttl, win, seq, flags = parse_l3(packet)
        flow.udps.src_ttl = ttl if ttl else 64
        flow.udps.dst_ttl = 0
        flow.udps.src_win = win
        flow.udps.dst_win = 0
        flow.udps.src_tcp_seq = seq
        flow.udps.dst_tcp_seq = 0
        flow.udps.tcp_rtt = 0.0
        flow.udps.synack = 0.0
        flow.udps.ackdat = 0.0
        flow.udps.tcp_flags_sum = flags

        # Handshake tracking (packet.time is epoch milliseconds)
        flow.udps.handshake_start = packet.time if (flags & SYN and not flags & ACK) else 0
        flow.udps.handshake_synack = 0
        flow.udps.handshake_ack = 0

    def on_update(self, packet, flow):
        ttl, win, seq, flags = parse_l3(packet)
        flow.udps.tcp_flags_sum |= flags

        if packet.direction == 1:  # destination -> source (response)
            if flow.udps.dst_ttl == 0 and ttl:
                flow.udps.dst_ttl = ttl
            if win and flow.udps.dst_win == 0:
                flow.udps.dst_win = win
            if seq and flow.udps.dst_tcp_seq == 0:
                flow.udps.dst_tcp_seq = seq
            if (flags & SYN) and (flags & ACK) and not flow.udps.handshake_synack:
                flow.udps.handshake_synack = packet.time
        else:  # source -> destination
            if ((flags & ACK) and not (flags & SYN) and
                    flow.udps.handshake_synack > 0 and flow.udps.handshake_ack == 0):
                flow.udps.handshake_ack = packet.time
                if flow.udps.handshake_start:
                    flow.udps.synack = (flow.udps.handshake_synack - flow.udps.handshake_start) / 1000.0
                flow.udps.ackdat = (flow.udps.handshake_ack - flow.udps.handshake_synack) / 1000.0
                flow.udps.tcp_rtt = flow.udps.synack + flow.udps.ackdat
