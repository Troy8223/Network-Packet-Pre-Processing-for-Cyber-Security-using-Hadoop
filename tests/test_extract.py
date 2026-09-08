import json
import os
import subprocess
import sys

from extract.aggregate import reduce_records
from extract.config import load_config
from extract.iofmt import format_mapper_line, parse_mapper_line
from extract.parse import iter_pcap_records
from extract.sources import iter_configured_packets
from tests.conftest import ROOT


def _records(pcap_path, profile):
    cfg = load_config(profile=profile, overrides={"input": {"mode": "pcap_file", "path": pcap_path}})
    return list(iter_configured_packets(cfg)), cfg


def test_minimal_and_iot_emit_different_flow_columns(tiny_pcap):
    minimal_recs, minimal_cfg = _records(tiny_pcap, "minimal")
    iot_recs, iot_cfg = _records(tiny_pcap, "iot_v1")
    minimal_flows = list(reduce_records(minimal_recs, minimal_cfg))
    iot_flows = list(reduce_records(iot_recs, iot_cfg))
    assert set(minimal_flows[0]) == set(minimal_cfg.flow_fields)
    assert set(iot_flows[0]) == set(iot_cfg.flow_fields)
    assert "iat_mean" not in minimal_flows[0]
    assert "iat_mean" in iot_flows[0]
    assert "src_mac" not in minimal_recs[0]
    assert "src_mac" in iot_recs[0]


def test_default_uses_ip_len_and_five_tuple(tiny_pcap):
    recs, cfg = _records(tiny_pcap, "default")
    flows = list(reduce_records(recs, cfg))
    tcp = [row for row in flows if row["src_ip"] == "10.0.0.1"][0]
    assert tcp["packets"] == 2
    assert tcp["src_port"] == 1234
    assert tcp["dest_port"] == 80
    assert tcp["bytes"] == sum(r["ip_len"] for r in recs if r["src_ip"] == "10.0.0.1")
    assert abs(tcp["duration"] - 0.1) < 1e-9


def test_iot_merges_bidirectional_tcp(tiny_pcap):
    recs, cfg = _records(tiny_pcap, "iot_v1")
    flows = list(reduce_records(recs, cfg))
    tcp = [row for row in flows if row.get("iot_service") != "mqtt"]
    assert len(tcp) == 1
    assert tcp[0]["packets"] == 3
    assert tcp[0]["packets_fwd"] + tcp[0]["packets_bwd"] == 3
    assert tcp[0]["syn_count"] == 1


def test_iot_flags_mqtt_service(tiny_pcap):
    recs, cfg = _records(tiny_pcap, "iot_v1")
    mqtt = [r for r in recs if r["iot_service"] == "mqtt"]
    assert len(mqtt) == 1
    assert mqtt[0]["dest_port"] == 1883


def test_mapper_json_roundtrip(tiny_pcap):
    recs, cfg = _records(tiny_pcap, "default")
    line = format_mapper_line(recs[0], cfg)
    key, parsed = parse_mapper_line(line)
    assert parsed["src_ip"] == "10.0.0.1"
    assert key[0] == "10.0.0.1"
    assert "src_mac" not in parsed


def test_local_cli_profile_changes_header(tiny_pcap, tmp_path):
    out_min = tmp_path / "min.csv"
    out_iot = tmp_path / "iot.csv"
    common = [sys.executable, "-m", "extract", "run", "--input", tiny_pcap]
    subprocess.check_call(common + ["--profile", "minimal", "--output", str(out_min)], cwd=ROOT)
    subprocess.check_call(common + ["--profile", "iot_v1", "--output", str(out_iot)], cwd=ROOT)
    min_header = out_min.read_text().splitlines()[0].split(",")
    iot_header = out_iot.read_text().splitlines()[0].split(",")
    assert min_header == [
        "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "packets", "bytes",
    ]
    assert "iat_mean" in iot_header
    assert "src_mac" in iot_header
    assert min_header != iot_header


def test_mapper_reducer_scripts(tiny_pcap, tmp_path):
    env = os.environ.copy()
    env["FEATURE_PROFILE"] = "minimal"
    env["PYTHONPATH"] = ROOT
    mapped = subprocess.check_output(
        [sys.executable, os.path.join(ROOT, "mapper.py"), "--profile", "minimal"],
        input=(tiny_pcap + "\n").encode(),
        env=env,
        cwd=ROOT,
    )
    # mapper default profile uses hdfs_paths; force local via argv config
    cfg_path = tmp_path / "local_min.json"
    cfg_path.write_text(json.dumps({
        "extends": "minimal",
        "input": {"mode": "local_paths"},
    }))
    mapped = subprocess.check_output(
        [sys.executable, os.path.join(ROOT, "mapper.py"), "--config", str(cfg_path)],
        input=(tiny_pcap + "\n").encode(),
        env=env,
        cwd=ROOT,
    )
    assert mapped
    reduced = subprocess.check_output(
        [sys.executable, os.path.join(ROOT, "reducer.py"), "--config", str(cfg_path)],
        input=mapped,
        env=env,
        cwd=ROOT,
    )
    lines = [line for line in reduced.decode().splitlines() if line]
    assert len(lines) >= 2
    assert "10.0.0.1" in reduced.decode()


def test_iter_pcap_respects_enabled_fields(tiny_pcap):
    cfg = load_config(
        profile="minimal",
        overrides={"input": {"mode": "pcap_file", "path": tiny_pcap}},
    )
    with open(tiny_pcap, "rb") as handle:
        rec = next(iter_pcap_records(handle, cfg))
    assert set(rec) <= set(cfg.packet_fields)
    assert "ttl" not in rec
