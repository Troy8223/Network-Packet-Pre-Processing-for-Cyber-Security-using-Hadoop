#!/usr/bin/env python3
"""Hadoop Streaming mapper: emit configured packet fields as key\\tjson."""

from __future__ import print_function

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
for path in (_ROOT, os.getcwd()):
    if path not in sys.path:
        sys.path.insert(0, path)
for zip_path in (
    os.path.join(_ROOT, "extract.zip"),
    os.path.join(os.getcwd(), "extract.zip"),
):
    if os.path.isfile(zip_path) and zip_path not in sys.path:
        sys.path.insert(0, zip_path)

from extract.config import config_from_argv
from extract.iofmt import format_mapper_line
from extract.sources import iter_configured_packets


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        config, _rest = config_from_argv(argv)
    except Exception as exc:
        sys.stderr.write("ERROR loading feature config: {}\n".format(exc))
        return 1
    sys.stderr.write("Running mapper profile={}\n".format(config.name))
    try:
        for rec in iter_configured_packets(config):
            sys.stdout.write(format_mapper_line(rec, config))
            sys.stdout.flush()
    except Exception as exc:
        sys.stderr.write("ERROR: {}\n".format(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
