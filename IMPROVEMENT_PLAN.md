# Improvement Plan

This repository is a Hadoop Streaming prototype that turns PCAP files into tabular packet/flow rows. The intended role is the **feature stage** of a cybersecurity pipeline (and later an IoT ML-IDS):

```
capture / HDFS PCAP  →  parse & aggregate  →  feature table  →  model / SIEM
```

The current mapper and reducer are **not** ready for that role. This plan keeps the role and rebuilds the schema, aggregation, and runtime in phases.

## Goal

Produce a **versioned, windowed, per-device or per-flow feature table** that can train and serve an IoT ML-IDS.

Target outcome:

- Same PCAP in twice produces the same Parquet out.
- A simple classifier on a public IoT dataset (CIC-IoT / Bot-IoT style) beats a dummy baseline.
- The same feature function can run **without Hadoop** (CLI today, gateway loop later).

## Current gaps

These are the blockers in `mapper.py` and `reducer.py`:

| Issue | What happens today |
| --- | --- |
| Size field is wrong | `ip.len` is computed and never written. The reducer treats `len(eth)` as `packet_size`. |
| Duration is wrong | `flow_duration` is the gap between consecutive packets **in the whole capture**, not one flow. |
| Flow key is incomplete | Reducer groups `(src_ip, dest_ip, protocol)` and ignores ports. |
| Last-wins fields | Timestamp, ports, and `count` come from the last line in the group, not the flow. |
| Features are too thin | No TCP flags, TTL, directional bytes, or IAT/size statistics. |
| IPv4 Ethernet only | IPv6 and non-IP frames are skipped. No MAC identity. |
| Hadoop is mandatory | Mapper shells out to `hadoop fs -cat`. No unit-testable extractor. |

Do **not** start with more Hadoop flags, extra Docker slaves, or new ML models on the current CSV. Those would lock in the bugs above.

---

## Phase 0 — Make current output honest

**Why:** Nothing downstream can be trusted until keys and sizes are correct.

Fixes:

1. Emit named fields: `ip_len`, `frame_len`, `payload_len`. Stop overloading `header_length`.
2. Rename the mapper time delta to `iat` (inter-arrival). Compute real `duration` in the reducer as `last_ts - first_ts` per key.
3. Change the aggregation key to the 5-tuple: `(src_ip, dest_ip, proto, src_port, dest_port)`.
4. Emit `first_ts` and `last_ts` from the group. Drop last-wins `count`.
5. Document that Hadoop must sort by the same key the reducer groups on.

**Acceptance:** `mapper | sort | reducer` on one PCAP is deterministic. Each row is one 5-tuple with packet/byte sums and true duration.

**Touch:** `mapper.py`, `reducer.py` only. Hadoop remains a runner, not the design.

---

## Phase 1 — Feature contract (the actual product)

Define `schema/v1` in code and generate the output from that definition.

**Identity**

- 5-tuple or `flow_id`
- `src_mac`, `dst_mac` (IoT inventory)
- Forward/backward columns relative to the device or to the first observed direction

**Required numeric fields (v1)**

- `packets_fwd`, `packets_bwd`
- `bytes_fwd`, `bytes_bwd`
- `duration`
- `iat_mean`, `iat_std`, `iat_min`, `iat_max`
- `size_mean`, `size_std`, `size_min`, `size_max`
- TCP flag counts: `syn`, `ack`, `fin`, `rst`, `psh`
- `ttl_mean`
- `protocol` (`tcp` / `udp` / `icmp`)

**Encoding:** Parquet for datasets; CSV only for debug. Every file includes `schema_version`.

**Acceptance:** A notebook trains scikit-learn on `features.parquet` plus labels without hand-parsing mapper lines.

---

## Phase 2 — IoT windows, not whole-file flows

One row per 5-tuple for an entire PCAP is weak for IoT (long-lived MQTT, periodic beacons).

Add windowing. Pick one default and document it:

- Time windows: 1s / 10s / 60s per device
- Or volume windows: every N packets per MAC or IP

**Preferred IoT key:** `src_mac` or `src_ip` + `window_id`  
**Optional second table:** 5-tuple + `window_id`

Align overlapping column names with CIC-IoT2023 or N-BaIoT so models can be benchmarked.

**Acceptance:** A 10-minute camera + MQTT capture yields many window rows per device, not one collapsed TCP blob.

---

## Phase 3 — Coverage the mapper must not silently drop

| Gap | v1.1 change |
| --- | --- |
| IPv6 | Parse `dpkt.ip6.IP6`; do not skip |
| Non-IP | Count ARP/EAPOL as `other`; do not treat them as IP flows |
| IoT ports | Flag 1883/8883 (MQTT), 5683 (CoAP), 53/5353 (DNS/mDNS), 67/68 (DHCP) |
| Other radios | Document “Ethernet/IP only”; do not claim Zigbee/BLE |

**Acceptance:** An IPv6 PCAP produces rows. The README states the radio limit in one sentence.

---

## Phase 4 — Runtime: keep Hadoop optional

Hadoop Streaming is acceptable as a **lab batch** runner. It is the wrong default for an IDS feature stage.

```
extract.py  (pure function: packets → feature rows)
    ├── cli:     extract --input a.pcap --out features.parquet
    ├── hadoop:  thin mapper/reducer wrappers (optional)
    └── later:   Spark/Flink or a 1s gateway loop
```

Replace `hadoop fs -cat` inside every map task. Use local files for tests; object storage or Spark `binaryFiles` for scale.

**Acceptance:** `pytest` on a tiny PCAP with no Hadoop. The Hadoop job is an extra entry in setup notes, not the only way to run.

---

## Phase 5 — Train / serve contract

- Training and inference call the **same** `extract` function.
- Label join keys: `pcap_id`, `window_start`, `device_id`.
- Split by **device or time**, not random rows (avoids leakage).
- Store `schema_version` and extractor git hash on every dataset.

**Acceptance:** A retrain job and a dummy inferencer both import `extract.features_for_window`.

**Phase 5b (later):** live gateway path — same function on a ring buffer, no HDFS.

---

## Work order

| Order | Work | Risk if skipped |
| --- | --- | --- |
| 0 | Honest 5-tuple, named sizes, real duration | Any model is invalid |
| 1 | Versioned schema, stats, TCP flags, MAC | Still not an IDS feature stage |
| 2 | Windowed per-device tables | Misses IoT periodicity and C2 |
| 3 | IPv6 and protocol flags | Silent blind spots |
| 4 | Extractor library + tests; Hadoop optional | No CI, no deploy path |
| 5 | Label join and leakage-safe splits | Optimistic accuracy |

Phases 0–2 are the core rewrite. Phases 3–5 are incremental.

---

## Target repo shape

```
extract/
  parse.py          # dpkt → packet records
  aggregate.py      # windows / 5-tuple
  schema.py         # v1 fields
mapper.py           # thin Hadoop adapter
reducer.py          # thin Hadoop adapter
tests/fixtures/     # tiny PCAPs
schema/v1.md        # field dictionary
```

Keep `intermediate produce/` as history. Do not extend those scripts.

---

## Done when used as an IoT ML-IDS intermediate

The project is a fit feature stage when all of the following are true:

1. Features are statistical and directional, not a single last packet.
2. Rows are per **device-window** or **5-tuple-window**.
3. Output is Parquet with a schema version.
4. Extraction runs without Hadoop.
5. A published IoT dataset can be reproduced well enough to report precision/recall.

Until Phase 2 is done, treat this repository as a **lab MapReduce demo**, not part of an IDS.
