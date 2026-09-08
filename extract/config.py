"""Load and validate feature-inclusion JSON configs."""

import copy
import json
import os

from extract.catalog import (
    FLOW_FIELDS,
    FLOW_PACKET_DEPS,
    INPUT_MODES,
    OUTPUT_FORMATS,
    PACKET_FIELDS,
)

DEFAULT_PROFILE = "default"
CONFIG_ENV = "FEATURE_CONFIG"
PROFILE_ENV = "FEATURE_PROFILE"

_SEARCH_DIRNAMES = (
    os.getcwd(),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
)


class ConfigError(ValueError):
    pass


class FeatureConfig(object):
    def __init__(self, data, path=None):
        self.raw = data
        self.path = path
        self.schema_version = data.get("schema_version", "v1")
        self.name = data.get("name") or data.get("profile") or "custom"
        self.description = data.get("description", "")
        self.input_mode = data.get("input", {}).get("mode", "local_paths")
        self.pcap_file = data.get("input", {}).get("path")
        self.key_fields = list(data.get("key_fields") or [])
        self.bidirectional = bool(data.get("bidirectional", False))
        self.size_field = data.get("size_field", "ip_len")
        self.iat_skip_first = bool(data.get("iat_skip_first", True))
        include = data.get("include") or {}
        if isinstance(include, list):
            self.packet_fields, self.flow_fields = _split_include_list(include)
        else:
            self.packet_fields = list(include.get("packet") or [])
            self.flow_fields = list(include.get("flow") or [])
        self.output_format = data.get("output", {}).get("format", "csv")
        self._apply_exclusions(data.get("exclude") or [])
        self._apply_extra(data.get("include_extra") or {})
        self._add_dependencies()
        self.validate()

    def _apply_exclusions(self, exclude):
        drop = set(exclude)
        self.packet_fields = [name for name in self.packet_fields if name not in drop]
        self.flow_fields = [name for name in self.flow_fields if name not in drop]
        self.key_fields = [name for name in self.key_fields if name not in drop]

    def _apply_extra(self, extra):
        if isinstance(extra, list):
            packet, flow = _split_include_list(extra)
        else:
            packet = list(extra.get("packet") or [])
            flow = list(extra.get("flow") or [])
        self.packet_fields = _unique(self.packet_fields + packet)
        self.flow_fields = _unique(self.flow_fields + flow)

    def _add_dependencies(self):
        needed = []
        for name in self.flow_fields:
            needed.extend(FLOW_PACKET_DEPS.get(name, ()))
        if any(name in self.flow_fields for name in ("bytes", "bytes_fwd", "bytes_bwd",
                                                     "size_min", "size_max", "size_mean", "size_std")):
            needed.append(self.size_field)
        if self.bidirectional or any(
            name in self.flow_fields
            for name in ("packets_fwd", "packets_bwd", "bytes_fwd", "bytes_bwd")
        ):
            needed.extend(("src_ip", "dest_ip", "src_port", "dest_port"))
        for key in self.key_fields:
            if key in PACKET_FIELDS:
                needed.append(key)
        self.packet_fields = _unique(list(self.packet_fields) + needed)

    def validate(self):
        if self.input_mode not in INPUT_MODES:
            raise ConfigError(
                "Unknown input.mode {!r}. Choose one of: {}".format(
                    self.input_mode, ", ".join(INPUT_MODES)
                )
            )
        if self.output_format not in OUTPUT_FORMATS:
            raise ConfigError(
                "Unknown output.format {!r}. Choose one of: {}".format(
                    self.output_format, ", ".join(OUTPUT_FORMATS)
                )
            )
        if not self.key_fields:
            raise ConfigError("key_fields must not be empty")
        unknown_keys = [name for name in self.key_fields if name not in PACKET_FIELDS]
        if unknown_keys:
            raise ConfigError(
                "Unknown key_fields: {}. Packet fields: {}".format(
                    ", ".join(unknown_keys), ", ".join(sorted(PACKET_FIELDS))
                )
            )
        unknown_packet = [name for name in self.packet_fields if name not in PACKET_FIELDS]
        if unknown_packet:
            raise ConfigError(
                "Unknown packet fields: {}. Available: {}".format(
                    ", ".join(unknown_packet), ", ".join(sorted(PACKET_FIELDS))
                )
            )
        unknown_flow = [name for name in self.flow_fields if name not in FLOW_FIELDS]
        if unknown_flow:
            raise ConfigError(
                "Unknown flow fields: {}. Available: {}".format(
                    ", ".join(unknown_flow), ", ".join(sorted(FLOW_FIELDS))
                )
            )
        if self.size_field not in PACKET_FIELDS:
            raise ConfigError("size_field {!r} is not a packet field".format(self.size_field))

    def enabled_packet(self):
        return set(self.packet_fields)

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "input": {"mode": self.input_mode, "path": self.pcap_file},
            "key_fields": self.key_fields,
            "bidirectional": self.bidirectional,
            "size_field": self.size_field,
            "iat_skip_first": self.iat_skip_first,
            "include": {
                "packet": self.packet_fields,
                "flow": self.flow_fields,
            },
            "output": {"format": self.output_format},
        }


def load_config(path=None, profile=None, overrides=None):
    """Resolve a profile or file path, apply optional dict overrides, return FeatureConfig."""
    data, resolved = _read_config(path, profile)
    if overrides:
        data = _deep_merge(data, overrides)
    return FeatureConfig(data, path=resolved)


def config_from_argv(argv):
    """Parse --config / --profile from argv; return (config, remaining_argv)."""
    path = None
    profile = None
    remaining = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--config", "-c") and i + 1 < len(argv):
            path = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--config="):
            path = arg.split("=", 1)[1]
            i += 1
            continue
        if arg in ("--profile", "-p") and i + 1 < len(argv):
            profile = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--profile="):
            profile = arg.split("=", 1)[1]
            i += 1
            continue
        remaining.append(arg)
        i += 1
    return load_config(path=path, profile=profile), remaining


def _read_config(path, profile):
    path = path or os.environ.get(CONFIG_ENV)
    profile = profile or os.environ.get(PROFILE_ENV)
    if path:
        return _load_file(path), os.path.abspath(path)
    if profile:
        found = _find_profile(profile)
        return _load_file(found), found
    found = _find_profile(DEFAULT_PROFILE)
    return _load_file(found), found


def _load_file(path):
    with open(path, "r") as handle:
        data = json.load(handle)
    extends = data.get("extends")
    if extends:
        parent_path = _find_profile(extends)
        parent = _load_file(parent_path)
        data = _deep_merge(parent, data)
        data.pop("extends", None)
    return data


def _find_profile(name):
    if os.path.isfile(name):
        return os.path.abspath(name)
    candidates = []
    filename = name if name.endswith(".json") else name + ".json"
    for directory in _SEARCH_DIRNAMES:
        candidates.append(os.path.join(directory, filename))
        candidates.append(os.path.join(directory, "config", filename))
    # Hadoop -files drops shipped files into the task cwd.
    candidates.append(os.path.join(os.getcwd(), filename))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise ConfigError(
        "Feature profile {!r} not found. Looked in: {}".format(name, ", ".join(candidates))
    )


def _split_include_list(names):
    packet = []
    flow = []
    unknown = []
    for name in names:
        if name in PACKET_FIELDS:
            packet.append(name)
        if name in FLOW_FIELDS:
            flow.append(name)
        if name not in PACKET_FIELDS and name not in FLOW_FIELDS:
            unknown.append(name)
    if unknown:
        raise ConfigError(
            "Unknown include fields: {}. Use python -m extract catalog to list fields.".format(
                ", ".join(unknown)
            )
        )
    return _unique(packet), _unique(flow)


def _unique(items):
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _deep_merge(base, overlay):
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if key == "extends":
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged
