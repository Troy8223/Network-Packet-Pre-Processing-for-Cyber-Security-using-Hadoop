"""Registry of packet- and flow-level fields that a config may include.

Adding a field later: declare it here, extract it in parse.py (packet) or
aggregate.py (flow), and enable it from a JSON profile. Mapper and reducer
do not hard-code column lists.
"""

from collections import namedtuple

Field = namedtuple("Field", ["name", "kind", "dtype", "description"])

PACKET_FIELDS = {
    spec.name: spec
    for spec in (
        Field("ts", "packet", "float", "Packet timestamp in seconds"),
        Field("iat", "packet", "float", "Inter-arrival time vs previous packet of the same key"),
        Field("src_ip", "packet", "str", "Source IPv4 or IPv6 address"),
        Field("dest_ip", "packet", "str", "Destination IPv4 or IPv6 address"),
        Field("src_mac", "packet", "str", "Source Ethernet MAC"),
        Field("dest_mac", "packet", "str", "Destination Ethernet MAC"),
        Field("src_port", "packet", "int", "L4 source port (0 if none)"),
        Field("dest_port", "packet", "int", "L4 destination port (0 if none)"),
        Field("protocol", "packet", "str", "Protocol name: tcp, udp, icmp, other"),
        Field("protocol_name", "packet", "str", "Uppercase protocol label (TCP/UDP/ICMP)"),
        Field("protocol_type", "packet", "int", "IP protocol number (6/17/1/0)"),
        Field("ip_version", "packet", "int", "IP version (4 or 6)"),
        Field("ip_len", "packet", "int", "IP datagram length"),
        Field("frame_len", "packet", "int", "Captured Ethernet frame length"),
        Field("payload_len", "packet", "int", "L4 payload length"),
        Field("header_length", "packet", "int", "IP header length in bytes"),
        Field("ttl", "packet", "int", "IPv4 TTL or IPv6 hop limit"),
        Field("tcp_flags", "packet", "int", "Raw TCP flags byte (0 if not TCP)"),
        Field("tcp_syn", "packet", "int", "1 if TCP SYN is set"),
        Field("tcp_ack", "packet", "int", "1 if TCP ACK is set"),
        Field("tcp_fin", "packet", "int", "1 if TCP FIN is set"),
        Field("tcp_rst", "packet", "int", "1 if TCP RST is set"),
        Field("tcp_psh", "packet", "int", "1 if TCP PSH is set"),
        Field("icmp_type", "packet", "int", "ICMP type (0 if not ICMP)"),
        Field("icmp_code", "packet", "int", "ICMP code (0 if not ICMP)"),
        Field("iot_service", "packet", "str", "Guess from ports: mqtt, coap, dns, mdns, dhcp, none"),
    )
}

FLOW_FIELDS = {
    spec.name: spec
    for spec in (
        Field("first_ts", "flow", "float", "First packet timestamp in the group"),
        Field("last_ts", "flow", "float", "Last packet timestamp in the group"),
        Field("duration", "flow", "float", "last_ts minus first_ts"),
        Field("packets", "flow", "int", "Packet count"),
        Field("bytes", "flow", "int", "Sum of the configured size_field"),
        Field("packets_fwd", "flow", "int", "Packets in first-seen direction"),
        Field("packets_bwd", "flow", "int", "Packets in reverse direction"),
        Field("bytes_fwd", "flow", "int", "Bytes in first-seen direction"),
        Field("bytes_bwd", "flow", "int", "Bytes in reverse direction"),
        Field("iat_min", "flow", "float", "Min packet IAT (first IAT skipped)"),
        Field("iat_max", "flow", "float", "Max packet IAT"),
        Field("iat_mean", "flow", "float", "Mean packet IAT"),
        Field("iat_std", "flow", "float", "Sample stddev of packet IAT"),
        Field("size_min", "flow", "int", "Min size_field"),
        Field("size_max", "flow", "int", "Max size_field"),
        Field("size_mean", "flow", "float", "Mean size_field"),
        Field("size_std", "flow", "float", "Sample stddev of size_field"),
        Field("syn_count", "flow", "int", "TCP SYN flag count"),
        Field("ack_count", "flow", "int", "TCP ACK flag count"),
        Field("fin_count", "flow", "int", "TCP FIN flag count"),
        Field("rst_count", "flow", "int", "TCP RST flag count"),
        Field("psh_count", "flow", "int", "TCP PSH flag count"),
        Field("ttl_mean", "flow", "float", "Mean TTL / hop limit"),
        Field("src_ip", "flow", "str", "Source IP from the group key"),
        Field("dest_ip", "flow", "str", "Destination IP from the group key"),
        Field("src_mac", "flow", "str", "Source MAC from the first packet"),
        Field("dest_mac", "flow", "str", "Destination MAC from the first packet"),
        Field("src_port", "flow", "int", "Source port from the group key"),
        Field("dest_port", "flow", "int", "Destination port from the group key"),
        Field("protocol", "flow", "str", "Protocol from the group key"),
        Field("protocol_type", "flow", "int", "Protocol number from the first packet"),
        Field("iot_service", "flow", "str", "iot_service from the first packet"),
    )
}

# Flow fields that need extra packet columns at map time.
FLOW_PACKET_DEPS = {
    "first_ts": ("ts",),
    "last_ts": ("ts",),
    "duration": ("ts",),
    "bytes": (),  # filled with size_field at resolve time
    "packets_fwd": (),
    "packets_bwd": (),
    "bytes_fwd": (),
    "bytes_bwd": (),
    "iat_min": ("iat",),
    "iat_max": ("iat",),
    "iat_mean": ("iat",),
    "iat_std": ("iat",),
    "size_min": (),
    "size_max": (),
    "size_mean": (),
    "size_std": (),
    "syn_count": ("tcp_syn",),
    "ack_count": ("tcp_ack",),
    "fin_count": ("tcp_fin",),
    "rst_count": ("tcp_rst",),
    "psh_count": ("tcp_psh",),
    "ttl_mean": ("ttl",),
    "src_mac": ("src_mac",),
    "dest_mac": ("dest_mac",),
    "protocol_type": ("protocol_type",),
    "iot_service": ("iot_service",),
}

INPUT_MODES = ("hdfs_paths", "local_paths", "pcap_stdin", "pcap_file")
OUTPUT_FORMATS = ("csv", "json")


def list_fields():
    """Return packet and flow field specs in stable name order."""
    packets = [PACKET_FIELDS[name] for name in sorted(PACKET_FIELDS)]
    flows = [FLOW_FIELDS[name] for name in sorted(FLOW_FIELDS)]
    return packets, flows


def format_field_table():
    lines = ["kind\tname\tdtype\tdescription"]
    packets, flows = list_fields()
    for spec in packets + flows:
        lines.append("{}\t{}\t{}\t{}".format(spec.kind, spec.name, spec.dtype, spec.description))
    return "\n".join(lines) + "\n"
