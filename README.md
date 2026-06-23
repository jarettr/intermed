# InterMed

InterMed inspects Minecraft mods, modpacks, servers, and logs without running
them. It reads the jars and files on disk, builds a graph of facts about what is
there, and reports findings — each one traceable back to the exact file it came
from.

It explains; it does not change anything. A run never edits your pack, downloads
mods, or starts the game. Output is a report you read in a terminal, or JSON /
SARIF / HTML for tools and CI.

This is `0.1.0-alpha`. The analysis runs and is tested; commands, flags, and
output shapes may still change. The [roadmap](docs/ROADMAP.md) tracks what is
planned and what is out of scope.

```
intermed doctor ./mods
```

```
InterMed Doctor v0.1.0
Target: ./mods (mods directory)
Env:    loader=fabric  mc=1.20.1  java=21

ERROR Missing dependency: cloth-config
      bewitchment requires cloth-config (*), but it is not installed.
      → Install cloth-config, or remove bewitchment.

WARNINGS  1 actionable, 10 informational  (0 fatal, 1 error, 0 warn, 10 note · 1073 facts)
```

## What it looks at

A single run can examine, depending on the target:

- **Metadata** — mod ids, versions, loaders, and the dependencies each mod
  declares.
- **Modpack manifests** — a Modrinth `.mrpack` or CurseForge export, which lists
  its mods by reference. When the jars are not present on disk, the report says so
  rather than reporting an empty pack as healthy.
- **Dependencies** — which declared dependencies are missing, which are pinned
  too tightly or left open-ended, and which mods depend on a missing one. Plus
  *implicit* dependencies a mod never declares but reveals through its data.
- **Resources / data** — recipes, tags, loot tables, advancements, models,
  blockstates, atlases. Which mods write the same file, whose copy wins, and
  whether a merge is safe or an override.
- **Mixins** — what each mixin targets, where two mods touch the same method,
  `@Overwrite`s that lock other mods out, and mixins that may not apply.
- **Scripts** — KubeJS / CraftTweaker recipe removals and replacements read from
  the script source.
- **Security & SBOM** — JAR signatures, a software bill of materials, and a
  preflight surface of sensitive API references (process spawning, sockets,
  reflection).
- **Logs** — crash reports and `latest.log` for known error signatures.
- **Performance** — a Spark profile, correlated against the mods that own the hot
  methods.

Every finding carries its evidence. `--explain <id>` prints the facts behind one
finding, down to the jar and the file inside it.

## Install

```
cargo build --release
# the binary is target/release/intermed
```

Requires a Rust toolchain. The build also writes a man page to
`docs/man/intermed.1` and shell completions to `docs/completions/`.

## Where to go next

- **[Quickstart](docs/guides/quickstart.md)** — install, first run, and a
  copy-paste recipe for every command.
- **Guides** — task by task:
  [reading a report](docs/guides/reading-a-report.md) ·
  [in CI](docs/guides/ci.md) ·
  [dependencies](docs/guides/dependencies.md) ·
  [resources & overlays](docs/guides/resources.md) ·
  [mixins](docs/guides/mixins.md) ·
  [security & SBOM](docs/guides/security.md)
- **Reference** — complete and exhaustive:
  [commands & flags](docs/reference/commands.md) ·
  [output formats](docs/reference/output-formats.md) ·
  [what each analysis examines](docs/reference/analysis.md) ·
  [the query engine](docs/reference/engine.md) ·
  [configuration](docs/reference/configuration.md) ·
  [caching](docs/reference/caching.md) ·
  [facts & schema](docs/reference/facts.md)

The [documentation index](docs/README.md) lists everything in one place, and the
[roadmap](docs/ROADMAP.md) covers what is planned.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) covers the architecture, the crate map, and how
to build, check, and extend InterMed. To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).
