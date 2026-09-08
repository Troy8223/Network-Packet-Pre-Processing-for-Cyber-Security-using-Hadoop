import os
import socket
import sys

import dpkt
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def build_tcp_frame(src_ip, dest_ip, sport, dport, payload=b"x", flags=None,
                    src_mac=b"\x00\x11\x22\x33\x44\x55",
                    dest_mac=b"\x66\x77\x88\x99\xaa\xbb"):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)
    if flags is not None:
        tcp.flags = flags
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dest_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=src_mac, dst=dest_mac, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def build_udp_frame(src_ip, dest_ip, sport, dport, payload=b"mqtt"):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dest_ip),
        p=dpkt.ip.IP_PROTO_UDP,
        ttl=32,
        data=udp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x0a\x00\x00\x00\x00\x01",
        dst=b"\x0a\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def write_pcap(path, packets_with_ts):
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for ts, buf in packets_with_ts:
            writer.writepkt(buf, ts=ts)


@pytest.fixture
def tiny_pcap(tmp_path):
    path = str(tmp_path / "tiny.pcap")
    write_pcap(path, [
        (1000.0, build_tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, b"aa", flags=dpkt.tcp.TH_SYN)),
        (1000.1, build_tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, b"bbbb", flags=dpkt.tcp.TH_ACK)),
        (1000.2, build_tcp_frame("10.0.0.2", "10.0.0.1", 80, 1234, b"c", flags=dpkt.tcp.TH_ACK)),
        (1001.0, build_udp_frame("10.0.0.3", "10.0.0.4", 50000, 1883, b"hello")),
    ])
    return path
