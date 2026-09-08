"""Serialize mapper and reducer rows for Hadoop Streaming or local files."""

import json

from extract.parse import packet_key


def format_mapper_line(rec, config):
    key = packet_key(rec, config)
    key_text = "|".join("" if part is None else str(part) for part in key)
    payload = {name: rec[name] for name in config.packet_fields if name in rec}
    return "{}\t{}\n".format(key_text, json.dumps(payload, separators=(",", ":")))


def parse_mapper_line(line):
    line = line.rstrip("\n")
    if not line or "\t" not in line:
        return None, None
    key_text, raw = line.split("\t", 1)
    key = tuple(key_text.split("|"))
    rec = json.loads(raw)
    return key, rec


def format_reducer_line(rec, config):
    if config.output_format == "json":
        return json.dumps(rec, separators=(",", ":")) + "\n"
    return ",".join(_csv_cell(rec.get(name, "")) for name in config.flow_fields) + "\n"


def csv_header(config):
    return ",".join(config.flow_fields) + "\n"


def _csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, float):
        if value == int(value):
            return str(int(value)) if abs(value) >= 1e12 else ("{:g}".format(value))
        return "{:.9g}".format(value)
    text = str(value)
    if any(char in text for char in ",\"\n"):
        return '"' + text.replace('"', '""') + '"'
    return text
