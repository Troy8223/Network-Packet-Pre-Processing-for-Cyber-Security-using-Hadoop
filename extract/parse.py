"""Parse PCAP packets into dicts that contain only the configured fields."""

import socket

import dpkt

from extract.catalog import PACKET_FIELDS

_IOT_PORTS = {
    1883: "mqtt",
    8883: "mqtt",
    5683: "coap",
    5684: "coap",
    53: "dns",
    5353: "mdns",
    67: "dhcp",
    68: "dhcp",
}

_TCP_FLAG_FIELDS = {
    "tcp_syn": dpkt.tcp.TH_SYN,
    "tcp_ack": dpkt.tcp.TH_ACK,
    "tcp_fin": dpkt.tcp.TH_FIN,
    "tcp_rst": dpkt.tcp.TH_RST,
    "tcp_psh": dpkt.tcp.TH_PUSH,
}


def mac_addr(raw):
    return ":".join("%02x" % byte for byte in raw)


def iter_pcap_records(stream, config, previous_ts_by_key=None):
    """Yield packet dicts from a binary PCAP stream."""
    if previous_ts_by_key is None:
        previous_ts_by_key = {}
    reader = dpkt.pcap.Reader(stream)
    enabled = config.enabled_packet()
    for ts, buf in reader:
        rec = parse_packet(ts, buf, enabled)
        if rec is None:
            continue
        key = packet_key(rec, config)
        if "iat" in enabled:
            prev = previous_ts_by_key.get(key)
            rec["iat"] = (ts - prev) if prev is not None else 0.0
            previous_ts_by_key[key] = rec.get("ts", ts)
        yield rec


def parse_packet(ts, buf, enabled):
    """Return a packet dict, or None if the frame is not IP."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None

    ip, version = _ip_layer(eth)
    if ip is None:
        return None

    src_ip, dest_ip = _ip_addrs(ip, version)
    src_port, dest_port, proto_name, proto_type, l4 = _l4(ip)
    want = enabled

    rec = {}
    if "ts" in want:
        rec["ts"] = float(ts)
    if "src_ip" in want:
        rec["src_ip"] = src_ip
    if "dest_ip" in want:
        rec["dest_ip"] = dest_ip
    if "src_mac" in want:
        rec["src_mac"] = mac_addr(eth.src)
    if "dest_mac" in want:
        rec["dest_mac"] = mac_addr(eth.dst)
    if "src_port" in want:
        rec["src_port"] = src_port
    if "dest_port" in want:
        rec["dest_port"] = dest_port
    if "protocol" in want:
        rec["protocol"] = proto_name
    if "protocol_name" in want:
        rec["protocol_name"] = proto_name.upper() if proto_name != "other" else ""
    if "protocol_type" in want:
        rec["protocol_type"] = proto_type
    if "ip_version" in want:
        rec["ip_version"] = version
    if "ip_len" in want:
        rec["ip_len"] = int(getattr(ip, "len", 0) or _ip6_len(ip))
    if "frame_len" in want:
        rec["frame_len"] = len(buf)
    if "payload_len" in want:
        rec["payload_len"] = len(getattr(l4, "data", b"") or b"") if l4 is not None else 0
    if "header_length" in want:
        rec["header_length"] = _ip_header_len(ip, version)
    if "ttl" in want:
        rec["ttl"] = int(getattr(ip, "ttl", getattr(ip, "hlim", 0)) or 0)
    if "tcp_flags" in want:
        rec["tcp_flags"] = int(l4.flags) if isinstance(l4, dpkt.tcp.TCP) else 0
    for field_name, mask in _TCP_FLAG_FIELDS.items():
        if field_name in want:
            rec[field_name] = int(bool(isinstance(l4, dpkt.tcp.TCP) and (l4.flags & mask)))
    icmp_types = (dpkt.icmp.ICMP,)
    icmp6_cls = getattr(getattr(dpkt, "icmp6", None), "ICMP6", None)
    if icmp6_cls is not None:
        icmp_types = (dpkt.icmp.ICMP, icmp6_cls)
    if "icmp_type" in want:
        rec["icmp_type"] = int(l4.type) if isinstance(l4, icmp_types) else 0
    if "icmp_code" in want:
        rec["icmp_code"] = int(getattr(l4, "code", 0) or 0) if isinstance(l4, icmp_types) else 0
    if "iot_service" in want:
        rec["iot_service"] = _iot_service(src_port, dest_port)
    # iat is filled by iter_pcap_records once the key is known
    if "iat" in want and "iat" not in rec:
        rec["iat"] = 0.0
    return rec


def packet_key(rec, config):
    if config.bidirectional:
        return bidirectional_key(rec, config.key_fields)
    return tuple(_key_value(rec, name) for name in config.key_fields)


def bidirectional_key(rec, key_fields):
    """Order endpoints so A→B and B→A share a key when IPs/ports are in the key."""
    values = {name: _key_value(rec, name) for name in key_fields}
    src = (values.get("src_ip"), values.get("src_port"))
    dest = (values.get("dest_ip"), values.get("dest_port"))
    if src > dest:
        swapped = dict(values)
        if "src_ip" in swapped and "dest_ip" in swapped:
            swapped["src_ip"], swapped["dest_ip"] = swapped["dest_ip"], swapped["src_ip"]
        if "src_port" in swapped and "dest_port" in swapped:
            swapped["src_port"], swapped["dest_port"] = swapped["dest_port"], swapped["src_port"]
        if "src_mac" in swapped and "dest_mac" in swapped:
            swapped["src_mac"], swapped["dest_mac"] = swapped["dest_mac"], swapped["src_mac"]
        values = swapped
    return tuple(values[name] for name in key_fields)


def _key_value(rec, name):
    value = rec.get(name)
    if value is None:
        return ""
    return value


def _ip_layer(eth):
    data = eth.data
    if isinstance(data, dpkt.ip.IP):
        return data, 4
    if isinstance(data, dpkt.ip6.IP6):
        return data, 6
    return None, 0


def _ip_addrs(ip, version):
    if version == 4:
        return socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
    return socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)


def _ip6_len(ip):
    return int(getattr(ip, "plen", 0) or 0) + 40


def _ip_header_len(ip, version):
    if version == 4:
        return int(ip.hl) * 4
    return 40


def _l4(ip):
    payload = ip.data
    if isinstance(payload, dpkt.tcp.TCP):
        return payload.sport, payload.dport, "tcp", 6, payload
    if isinstance(payload, dpkt.udp.UDP):
        return payload.sport, payload.dport, "udp", 17, payload
    if isinstance(payload, dpkt.icmp.ICMP):
        return 0, 0, "icmp", 1, payload
    icmp6_cls = getattr(getattr(dpkt, "icmp6", None), "ICMP6", None)
    if icmp6_cls is not None and isinstance(payload, icmp6_cls):
        return 0, 0, "icmp", 58, payload
    proto = int(getattr(ip, "p", getattr(ip, "nxt", 0)) or 0)
    return 0, 0, "other", proto, payload if not isinstance(payload, bytes) else None


def _iot_service(src_port, dest_port):
    return _IOT_PORTS.get(src_port) or _IOT_PORTS.get(dest_port) or "none"


# Touch PACKET_FIELDS so unused-import checkers keep the catalog as the contract.
assert PACKET_FIELDS
