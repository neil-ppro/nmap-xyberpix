# SIEM integration examples (nmap-xyberpix NDJSON)

Nmap’s **`--siem-log`** appends **one JSON object per line** (NDJSON). Field definitions and versioning are in [SIEM-NDJSON-SCHEMA.md](../../SIEM-NDJSON-SCHEMA.md).

These snippets are starting points; tune indexes, retention, and PII rules for your environment.

## jq (shell pipelines)

Pretty-print each event:

```bash
grep '^{' siem.ndjson | jq .
```

Filter by event type:

```bash
grep '^{' siem.ndjson | jq 'select(.event == "port")'
```

Correlate by scan:

```bash
grep '^{' siem.ndjson | jq 'select(.scan_id == "SCAN_ID_HERE")'
```

## Splunk (props / transforms)

Assume NDJSON is ingested as a single indexed field `raw` or as `_raw` per line.

**props.conf** (conceptual):

```ini
[nmap_siem_ndjson]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 1048576
```

Use **Splunk Add-on** patterns or **INGEST_EVAL** / **props** with **INDEXED_EXTRACTIONS = json** if each line is pure JSON (no prefix text):

```ini
[nmap_siem_pure_json]
SHOULD_LINEMERGE = false
INDEXED_EXTRACTIONS = json
KV_MODE = none
```

If lines are mixed with non-JSON (e.g. `--siem-log -` on stdout), ingest the SIEM file path only, or pre-filter with `grep '^{'`.

Suggested **search-time** fields: `event`, `scan_id`, `ts`, `schema_version`, `target_ip`, `port`, `state`, `tag`.

## Elastic / OpenSearch (Filebeat)

**filebeat.yml** fragment for a dedicated SIEM file:

```yaml
filebeat.inputs:
  - type: filestream
    id: nmap-siem
    paths:
      - /var/log/nmap/siem.ndjson
    parsers:
      - ndjson:
          keys_under_root: true
          add_error_key: true
    processors:
      - timestamp:
          field: ts
          layouts:
            - '2006-01-02T15:04:05.999999999Z07:00'
            - '2006-01-02T15:04:05Z07:00'
          test:
            - '2026-03-27T12:00:00.123456Z'
```

Adjust `layouts` to match your actual `ts` strings (microsecond vs millisecond). Map `schema_version` as `long`, `ts` as `date`, `scan_id` as `keyword` for aggregations.

## Elasticsearch ingest pipeline (optional)

If JSON lands as a string field, use a **json** processor on that field, then **date** on `ts`:

```json
{
  "description": "Parse nmap-xyberpix SIEM line",
  "processors": [
    { "json": { "field": "message", "target_field": "nmap" } },
    { "date": { "field": "nmap.ts", "target_field": "@timestamp", "formats": [ "ISO8601" ] } }
  ]
}
```

## RFC 5424 syslog mirror (`--siem-syslog`)

The **MSG** payload is the same JSON string. On Elastic, parse the syslog header then **json** on the remainder, or use a pipeline that extracts `siem - ` suffix if your collector wraps the line.

## Security

Log streams may contain **targets, ports, service banners, and command lines**. Restrict access, redact if needed, and align retention with policy.
