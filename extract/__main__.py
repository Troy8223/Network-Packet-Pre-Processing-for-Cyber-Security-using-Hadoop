"""python -m extract catalog|run ..."""

from __future__ import print_function

import sys

from extract.catalog import format_field_table
from extract.run import main as run_main


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(
            "Usage:\n"
            "  python -m extract catalog\n"
            "  python -m extract run [--profile NAME] [--config FILE] --input FILE.pcap\n"
        )
        return 0
    command = argv[0]
    if command == "catalog":
        sys.stdout.write(format_field_table())
        return 0
    if command == "run":
        return run_main(argv[1:])
    return run_main(argv)


if __name__ == "__main__":
    sys.exit(main())
