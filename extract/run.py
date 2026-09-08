"""Local CLI: extract features from a PCAP without Hadoop."""

from __future__ import print_function

import argparse
import sys

from extract.aggregate import reduce_records
from extract.catalog import format_field_table
from extract.config import load_config
from extract.iofmt import csv_header, format_reducer_line
from extract.sources import iter_configured_packets


def build_parser():
    parser = argparse.ArgumentParser(
        description="Extract configurable flow features from a PCAP file."
    )
    parser.add_argument("--config", "-c", help="Path to a feature JSON config")
    parser.add_argument("--profile", "-p", help="Named profile in config/ (default, minimal, iot_v1, legacy)")
    parser.add_argument("--input", "-i", help="PCAP file (overrides input.path / uses pcap_file mode)")
    parser.add_argument("--output", "-o", help="Write features here (default: stdout)")
    parser.add_argument("--list-fields", action="store_true", help="Print the field catalog and exit")
    parser.add_argument("--show-config", action="store_true", help="Print the resolved config and exit")
    parser.add_argument("--no-header", action="store_true", help="Do not write a CSV header")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list_fields:
        sys.stdout.write(format_field_table())
        return 0
    overrides = None
    if args.input:
        overrides = {"input": {"mode": "pcap_file", "path": args.input}}
    config = load_config(path=args.config, profile=args.profile, overrides=overrides)
    if args.show_config:
        import json
        sys.stdout.write(json.dumps(config.to_dict(), indent=2) + "\n")
        return 0
    if config.input_mode == "pcap_file" and not config.pcap_file:
        sys.stderr.write("Pass --input PATH or set input.path in the config.\n")
        return 2
    records = iter_configured_packets(config)
    flows = reduce_records(records, config)
    out = open(args.output, "w") if args.output else sys.stdout
    try:
        if config.output_format == "csv" and not args.no_header:
            out.write(csv_header(config))
        for rec in flows:
            out.write(format_reducer_line(rec, config))
    finally:
        if args.output:
            out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
