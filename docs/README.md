# Documentation

InterMed is at `0.1.3-alpha`; the [roadmap](ROADMAP.md) tracks what is planned.

The documentation has three layers. Start at the top and go deeper only when you
need to.

## Start here

- [Quickstart](guides/quickstart.md) — install, your first run, and one recipe
  per command.

## Guides

Task-oriented. Each one walks a single job end to end.

- [Reading a report](guides/reading-a-report.md) — severities, the summary line,
  finding groups, `--explain`, and exit codes.
- [Using InterMed in CI](guides/ci.md) — gating a build on findings, machine
  output, caching between runs.
- [Dependencies](guides/dependencies.md) — missing, too-tight, too-loose,
  implicit, and blast-radius questions.
- [Resources and overlays](guides/resources.md) — who writes which file, safe
  merges vs. overrides, and previewing the merged result.
- [Mixins](guides/mixins.md) — reading mixin risk, overlaps, overwrites, and
  apply checks.
- [Security and SBOM](guides/security.md) — signatures, the dangerous-API
  surface, the low-trust × capability correlation, and exporting an SBOM.
- [Performance](guides/performance.md) — importing a Spark profile, hot
  methods/mods, and tying a hot method to the mixin that owns it.

## Reference

Complete and precise. Look here for the exact behaviour of a flag or a field.

- [Commands and flags](reference/commands.md) — every command, subcommand, and
  option.
- [Output formats](reference/output-formats.md) — terminal, JSON, SARIF, HTML,
  and the report shape.
- [What each analysis examines](reference/analysis.md) — the analysis areas, what
  each one reads, and what it can and cannot conclude.
- [The query engine](reference/engine.md) — how declarative rules are planned and
  run, the backends (`--logic`), and the engine's limits.
- [Configuration](reference/configuration.md) — every config key, its default,
  and the matching flag.
- [Caching](reference/caching.md) — the jar scan cache: how it keys, prunes, and
  invalidates.
- [Facts and schema](reference/facts.md) — the fact model and the
  `intermed-doctor-report-v1` JSON schema.

## Contributing

- [Contributing](../CONTRIBUTING.md) — how the project is built and checked, the
  layered architecture and crate map, and the invariants every change keeps.
- [Security policy](../SECURITY.md) — what counts as a vulnerability and how to
  report one privately.
