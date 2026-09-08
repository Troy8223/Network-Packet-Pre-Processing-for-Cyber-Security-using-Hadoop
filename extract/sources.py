"""Open PCAP input according to config.input.mode."""

import os
import sys
from subprocess import PIPE, Popen

from extract.parse import iter_pcap_records


def iter_configured_packets(config, stdin=None, filenames=None):
    """Yield packet records for the configured input mode."""
    stdin = sys.stdin if stdin is None else stdin
    previous = {}
    mode = config.input_mode
    if mode == "pcap_stdin":
        stream = stdin.buffer if hasattr(stdin, "buffer") else stdin
        for rec in iter_pcap_records(stream, config, previous):
            yield rec
        return
    if mode == "pcap_file":
        path = config.pcap_file
        if not path:
            raise ValueError("input.mode pcap_file requires input.path")
        with open(path, "rb") as handle:
            for rec in iter_pcap_records(handle, config, previous):
                yield rec
        return
    if filenames is None:
        filenames = _read_filenames(stdin)
    for filename in filenames:
        opener = _open_hdfs if mode == "hdfs_paths" else _open_local
        with opener(filename) as handle:
            for rec in iter_pcap_records(handle, config, previous):
                yield rec


def _read_filenames(stdin):
    stream = stdin.buffer if hasattr(stdin, "buffer") else stdin
    for raw in stream:
        if isinstance(raw, bytes):
            filename = raw.strip().replace(b"\x00", b"").decode("utf-8")
        else:
            filename = raw.strip().replace("\x00", "")
        if filename:
            yield filename


def _open_local(filename):
    return open(filename, "rb")


class _HdfsCat(object):
    def __init__(self, filename):
        hadoop = os.environ.get("HADOOP_FS_BIN", "/usr/local/hadoop/bin/hadoop")
        self.proc = Popen([hadoop, "fs", "-cat", filename], stdout=PIPE)
        self.stdout = self.proc.stdout

    def __enter__(self):
        return self.stdout

    def __exit__(self, exc_type, exc, tb):
        if self.stdout:
            self.stdout.close()
        if self.proc:
            self.proc.wait()
        return False


def _open_hdfs(filename):
    return _HdfsCat(filename)
