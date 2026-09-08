"""Reduce configured packet rows into flow records."""

import math

from extract.parse import bidirectional_key, packet_key


class RunningStats(object):
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min_value = None
        self.max_value = None

    def add(self, value):
        value = float(value)
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)
        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value

    def std(self):
        if self.n < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.n - 1))


class FlowAccumulator(object):
    def __init__(self, config, key):
        self.config = config
        self.key = key
        self.packets = 0
        self.bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.packets_fwd = 0
        self.packets_bwd = 0
        self.bytes_fwd = 0
        self.bytes_bwd = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.identity = {}
        self._fwd_tuple = None
        self._iat = RunningStats()
        self._size = RunningStats()
        self._ttl = RunningStats()

    def add(self, rec):
        size = int(rec.get(self.config.size_field) or 0)
        ts = rec.get("ts")
        self.packets += 1
        self.bytes += size
        if ts is not None:
            ts = float(ts)
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        if self._fwd_tuple is None:
            self._fwd_tuple = (
                rec.get("src_ip"),
                rec.get("dest_ip"),
                rec.get("src_port"),
                rec.get("dest_port"),
            )
            for name in (
                "src_ip",
                "dest_ip",
                "src_port",
                "dest_port",
                "protocol",
                "protocol_type",
                "src_mac",
                "dest_mac",
                "iot_service",
            ):
                if name in rec:
                    self.identity[name] = rec[name]
            for index, name in enumerate(self.config.key_fields):
                self.identity[name] = self.key[index]
        if self._is_forward(rec):
            self.packets_fwd += 1
            self.bytes_fwd += size
        else:
            self.packets_bwd += 1
            self.bytes_bwd += size
        iat = rec.get("iat")
        if iat is not None:
            if not (self.config.iat_skip_first and self.packets == 1 and float(iat) == 0.0):
                self._iat.add(iat)
        self._size.add(size)
        if rec.get("ttl") is not None:
            self._ttl.add(rec["ttl"])
        self.syn_count += int(rec.get("tcp_syn") or 0)
        self.ack_count += int(rec.get("tcp_ack") or 0)
        self.fin_count += int(rec.get("tcp_fin") or 0)
        self.rst_count += int(rec.get("tcp_rst") or 0)
        self.psh_count += int(rec.get("tcp_psh") or 0)

    def _is_forward(self, rec):
        current = (
            rec.get("src_ip"),
            rec.get("dest_ip"),
            rec.get("src_port"),
            rec.get("dest_port"),
        )
        return current == self._fwd_tuple

    def result(self):
        duration = 0.0
        if self.first_ts is not None and self.last_ts is not None:
            duration = self.last_ts - self.first_ts
        values = {
            "first_ts": self.first_ts if self.first_ts is not None else 0.0,
            "last_ts": self.last_ts if self.last_ts is not None else 0.0,
            "duration": duration,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_fwd": self.packets_fwd,
            "packets_bwd": self.packets_bwd,
            "bytes_fwd": self.bytes_fwd,
            "bytes_bwd": self.bytes_bwd,
            "iat_min": self._iat.min_value if self._iat.n else 0.0,
            "iat_max": self._iat.max_value if self._iat.n else 0.0,
            "iat_mean": self._iat.mean if self._iat.n else 0.0,
            "iat_std": self._iat.std(),
            "size_min": int(self._size.min_value) if self._size.n else 0,
            "size_max": int(self._size.max_value) if self._size.n else 0,
            "size_mean": self._size.mean if self._size.n else 0.0,
            "size_std": self._size.std(),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "ttl_mean": self._ttl.mean if self._ttl.n else 0.0,
        }
        values.update(self.identity)
        return {name: values.get(name, "") for name in self.config.flow_fields}


def reduce_records(records, config):
    """Group an iterable of packet dicts and yield flow dicts in first-seen key order."""
    groups = []
    index = {}
    for rec in records:
        key = packet_key(rec, config)
        acc = index.get(key)
        if acc is None:
            acc = FlowAccumulator(config, key)
            index[key] = acc
            groups.append(acc)
        acc.add(rec)
    for acc in groups:
        yield acc.result()


def make_key(rec, config):
    if config.bidirectional:
        return bidirectional_key(rec, config.key_fields)
    return packet_key(rec, config)
