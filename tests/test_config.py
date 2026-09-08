import json
import os

import pytest

from extract.catalog import FLOW_FIELDS, PACKET_FIELDS
from extract.config import ConfigError, FeatureConfig, load_config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_DIR = os.path.join(ROOT, "config")


def test_default_profile_loads():
    cfg = load_config(profile="default")
    assert cfg.name == "default"
    assert "src_port" in cfg.key_fields
    assert "ip_len" in cfg.packet_fields
    assert "packets" in cfg.flow_fields


def test_minimal_excludes_optional_stats():
    cfg = load_config(profile="minimal")
    assert "iat_mean" not in cfg.flow_fields
    assert "src_mac" not in cfg.packet_fields
    assert cfg.flow_fields == [
        "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "packets", "bytes",
    ]


def test_iot_profile_is_bidirectional_and_has_stats():
    cfg = load_config(profile="iot_v1")
    assert cfg.bidirectional is True
    assert "src_mac" in cfg.packet_fields
    assert "iat_mean" in cfg.flow_fields
    assert "iot_service" in cfg.packet_fields


def test_exclude_removes_fields():
    cfg = load_config(
        profile="iot_v1",
        overrides={"exclude": ["src_mac", "dest_mac", "iot_service"]},
    )
    assert "src_mac" not in cfg.packet_fields
    assert "iot_service" not in cfg.flow_fields


def test_include_extra_adds_fields():
    cfg = load_config(
        profile="minimal",
        overrides={"include_extra": {"flow": ["duration"], "packet": ["ts"]}},
    )
    assert "duration" in cfg.flow_fields
    assert "ts" in cfg.packet_fields


def test_unknown_field_raises():
    with pytest.raises(ConfigError, match="Unknown packet fields"):
        FeatureConfig({
            "key_fields": ["src_ip"],
            "include": {"packet": ["not_a_field"], "flow": ["packets"]},
        })


def test_flow_stats_pull_in_packet_dependencies():
    cfg = FeatureConfig({
        "key_fields": ["src_ip", "dest_ip"],
        "include": {"packet": ["src_ip", "dest_ip"], "flow": ["iat_mean", "bytes"]},
        "size_field": "ip_len",
    })
    assert "iat" in cfg.packet_fields
    assert "ip_len" in cfg.packet_fields


def test_flat_include_list_splits_packet_and_flow():
    cfg = FeatureConfig({
        "key_fields": ["src_ip"],
        "include": ["src_ip", "dest_ip", "packets", "bytes"],
        "size_field": "ip_len",
    })
    assert "src_ip" in cfg.packet_fields
    assert "packets" in cfg.flow_fields


def test_catalog_covers_profiles():
    for name in ("default", "minimal", "iot_v1", "legacy"):
        cfg = load_config(path=os.path.join(CONFIG_DIR, name + ".json"))
        for field in cfg.packet_fields:
            assert field in PACKET_FIELDS
        for field in cfg.flow_fields:
            assert field in FLOW_FIELDS


def test_show_config_roundtrip(tmp_path):
    cfg = load_config(profile="minimal")
    dumped = tmp_path / "copy.json"
    dumped.write_text(json.dumps(cfg.to_dict()))
    again = load_config(path=str(dumped))
    assert again.flow_fields == cfg.flow_fields
