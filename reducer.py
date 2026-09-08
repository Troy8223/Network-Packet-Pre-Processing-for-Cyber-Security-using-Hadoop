#!/usr/bin/env python3
"""Hadoop Streaming reducer: aggregate configured packet rows by key."""

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

from extract.aggregate import FlowAccumulator
from extract.config import config_from_argv
from extract.iofmt import format_reducer_line, parse_mapper_line


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        config, _rest = config_from_argv(argv)
    except Exception as exc:
        sys.stderr.write("ERROR loading feature config: {}\n".format(exc))
        return 1
    sys.stderr.write("Running reducer profile={}\n".format(config.name))
    current_key = None
    acc = None
    for line in sys.stdin:
        try:
            key, rec = parse_mapper_line(line)
        except ValueError as exc:
            sys.stderr.write("ERROR parsing line: {}\n".format(exc))
            continue
        if rec is None:
            continue
        if current_key != key:
            if acc is not None:
                sys.stdout.write(format_reducer_line(acc.result(), config))
                sys.stdout.flush()
            current_key = key
            acc = FlowAccumulator(config, key)
        acc.add(rec)
    if acc is not None:
        sys.stdout.write(format_reducer_line(acc.result(), config))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
