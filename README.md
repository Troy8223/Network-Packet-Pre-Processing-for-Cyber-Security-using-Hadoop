# Network-Packet-Pre-Processing-for-Cyber-Security-using-Hadoop

Hadoop Streaming (and local) preprocessor that turns PCAP files into tabular flow features for cybersecurity models.

The longer roadmap toward a versioned, windowed IoT ML-IDS feature stage is in [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md).

**Which columns are extracted is configurable.** Training and detection jobs pick a JSON profile instead of changing `mapper.py` / `reducer.py`. Add fields to the catalog when a new model needs them.

## Feature profiles

| Profile | Use |
| --- | --- |
| `config/default.json` | 5-tuple flows, honest IP/frame/payload sizes, duration, packet and byte counts |
| `config/minimal.json` | Who talked, protocol, packets, bytes |
| `config/iot_v1.json` | MAC, MQTT/CoAP/DNS hints, IAT/size stats, TCP flags, bidirectional flows |
| `config/legacy.json` | Closest to the original 3-tuple mapper (frame length as size) |

List every field the extractor can emit:

```bash
python3 -m extract catalog
```

Run locally without Hadoop:

```bash
pip install -r requirements.txt
python3 -m extract run --profile iot_v1 --input test.pcap --output features.csv
python3 -m extract run --config config/minimal.json --input test.pcap
```

`--show-config` prints the resolved field lists after inheritance, `exclude`, and `include_extra`.

### Write a profile for a new model

Copy an existing file or extend one:

```json
{
  "schema_version": "v1",
  "name": "detector_v2",
  "extends": "iot_v1",
  "exclude": ["src_mac", "dest_mac"],
  "include_extra": {
    "flow": ["ttl_mean"]
  }
}
```

Or name an exact set (unknown names fail fast):

```json
{
  "key_fields": ["src_ip", "dest_ip", "protocol", "src_port", "dest_port"],
  "size_field": "ip_len",
  "include": {
    "packet": ["ts", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "ip_len"],
    "flow": ["src_ip", "dest_ip", "protocol", "packets", "bytes", "duration"]
  }
}
```

`include` may also be a flat list of catalog names; packet vs flow is resolved automatically.

Selection is applied at extract time: disabled packet fields are not parsed into the row, so a detection profile can stay smaller than a training profile.

| Knob | Meaning |
| --- | --- |
| `key_fields` | Flow identity (change this when the model wants device MAC vs 5-tuple) |
| `bidirectional` | Merge A→B and B→A into one flow |
| `size_field` | Which packet size is summed as `bytes` (`ip_len`, `frame_len`, or `payload_len`) |
| `include.packet` / `include.flow` | Columns to compute |
| `exclude` / `include_extra` | Delta on top of `extends` |
| `input.mode` | `hdfs_paths` (Hadoop), `local_paths`, `pcap_file`, `pcap_stdin` |

To add a **new** kind of data (not just toggle an existing column), declare it in `extract/catalog.py` and fill it in `extract/parse.py` (packet) or `extract/aggregate.py` (flow).

## Hadoop job

Ship the `extract` package, the chosen profile, and any parent it `extends`:

```bash
zip -r extract.zip extract
export HADOOP_STREAMING_JAR=$HADOOP_HOME/share/hadoop/tools/lib/hadoop-streaming-2.7.2.jar

hadoop jar $HADOOP_STREAMING_JAR \
  -files mapper.py,reducer.py,extract.zip,config/default.json,config/iot_v1.json \
  -cmdenv FEATURE_PROFILE=iot_v1 \
  -mapper "mapper.py --profile iot_v1" \
  -reducer "reducer.py --profile iot_v1" \
  -input input_directory \
  -output output_directory
```

Mapper input for `hdfs_paths` is a list of HDFS PCAP paths (same as `test_filename.txt`). Workers need `dpkt` (`pip3 install dpkt`).

Cluster setup notes: `intermediate produce/Setup.txt`, plus

- Linux: https://kiwenlau.com/2016/06/12/160612-hadoop-cluster-docker-update/
- Windows: https://medium.com/edward-hong-%E6%8A%80%E8%A1%93%E7%AD%86%E8%A8%98/hadoop-%E5%9C%A8-windows-%E4%B8%8A%E4%BD%BF%E7%94%A8doker-%E5%BB%BA%E7%BD%AE-hadoop-%E5%B9%B3%E5%8F%B0-8273ddc3ae2a

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/
```
