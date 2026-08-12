# Telemetry and privacy

InterMed does not collect telemetry by default. A normal invocation creates no
telemetry file, contacts no telemetry service, and stores no consent setting for
future runs. Consent is per invocation and requires one of these flags:

```bash
# Inspect the exact privacy-filtered event locally.
intermed doctor ./mods --telemetry-out telemetry.json

# Send the same event to an endpoint you control.
intermed doctor ./mods --telemetry-endpoint https://example.invalid/intermed

# Log excerpts require separate, explicit consent.
intermed doctor ./server --telemetry-out telemetry.json \
  --telemetry-include-log-excerpts
```

`--telemetry-endpoint` accepts HTTPS only, rejects embedded credentials, does not
follow redirects, and uses bounded connect/read/write timeouts. A requested
export or send that fails is an operational error and remains non-zero even with
`--exit-zero`. Supplying both
destinations writes and sends the same event.

## Default event

Schema `intermed-telemetry-event-v1` contains:

- tool version, generation time, target kind, and detected OS/Java/loader/
  Minecraft/side/layout values;
- total duration and fact/compaction counts;
- aggregate finding counts by severity, category, and project rule id;
- aggregate collector status, collector fact counts, phase timings, and cache
  hit/miss/write counts;
- operational failure stage and component, without the raw error message;
- an explicit consent record.

It does not contain the target path, archive names, source locators, mod ids,
finding ids, affected components, finding explanations, raw operational error
messages, a user/account identifier, or a stable installation identifier.

## Optional log excerpts

Log text is excluded unless `--telemetry-include-log-excerpts` is present
together with a telemetry destination. At most 20 recognized signal excerpts are
included, each truncated to 240 characters. Before export, InterMed replaces
URLs, e-mail addresses, IPv4 addresses, common absolute paths, and common secret
assignments such as `token=...` or `password=...` with `<redacted>`.

Redaction reduces accidental disclosure; it cannot prove arbitrary text is
anonymous. Prefer `--telemetry-out`, inspect the JSON, and send it yourself when
the logs may contain private server or player data.
