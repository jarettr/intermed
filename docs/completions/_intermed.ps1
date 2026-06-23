
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'intermed' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'intermed'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'intermed' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Diagnose a server, instance, mods directory, or log/crash file')
            [CompletionResult]::new('vfs', 'vfs', [CompletionResultType]::ParameterValue, 'Inspect resource/data overrides and generate overlay previews')
            [CompletionResult]::new('deps', 'deps', [CompletionResultType]::ParameterValue, 'Layer-C dependency graph, resolution, and explainable queries')
            [CompletionResult]::new('impact', 'impact', [CompletionResultType]::ParameterValue, 'Blast-radius analysis for removing or updating a mod')
            [CompletionResult]::new('mixin-map', 'mixin-map', [CompletionResultType]::ParameterValue, 'Inspect static Mixin targets, overlaps, and overwrite risks')
            [CompletionResult]::new('spark-map', 'spark-map', [CompletionResultType]::ParameterValue, 'Import and summarize Spark performance reports')
            [CompletionResult]::new('lab', 'lab', [CompletionResultType]::ParameterValue, 'Compatibility Lab: corpus locks, smoke-test ingestion, matrices')
            [CompletionResult]::new('rules', 'rules', [CompletionResultType]::ParameterValue, 'Validate declarative rule packs')
            [CompletionResult]::new('db', 'db', [CompletionResultType]::ParameterValue, 'Query the DuckDB analytics store (`--features duckdb`)')
            [CompletionResult]::new('history', 'history', [CompletionResultType]::ParameterValue, 'Recurring conflicts across persisted diagnosis runs')
            [CompletionResult]::new('trends', 'trends', [CompletionResultType]::ParameterValue, 'Time-series analytics over persisted runs')
            [CompletionResult]::new('cache', 'cache', [CompletionResultType]::ParameterValue, 'Jar scan cache maintenance (`stats`, `prune`, `clear`)')
            [CompletionResult]::new('sbom', 'sbom', [CompletionResultType]::ParameterValue, 'SBOM export (SPDX / CycloneDX) from a mods directory')
            [CompletionResult]::new('demo', 'demo', [CompletionResultType]::ParameterValue, 'Presentation demo: aggregate a small real-mod run into launcher-facing reports')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;doctor' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--logic', '--logic', [CompletionResultType]::ParameterName, 'Rule backend. The in-process columnar query engine is the default and only in-process engine; `souffle`/`duckdb` are optional external backends over the same IR (require their tool / build feature)')
            [CompletionResult]::new('--jobs', '--jobs', [CompletionResultType]::ParameterName, 'Cap the worker thread count for parallel jar/log scanning. Unset or `0` uses all available cores; lower it on weak machines or shared CI runners')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Cap the worker thread count for parallel jar/log scanning. Unset or `0` uses all available cores; lower it on weak machines or shared CI runners')
            [CompletionResult]::new('--html', '--html', [CompletionResultType]::ParameterName, 'Write a self-contained HTML report (`index.html` style)')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Write wall-clock phase profile JSON (`intermed-doctor-profile-v1`)')
            [CompletionResult]::new('--cache-dir', '--cache-dir', [CompletionResultType]::ParameterName, 'Override jar cache root (default: $XDG_CACHE_HOME/intermed or ~/.cache/intermed)')
            [CompletionResult]::new('--cache-remote-dir', '--cache-remote-dir', [CompletionResultType]::ParameterName, 'Shared/remote cache tier directory (Tier 3). A scan payload written by one machine is reused by any other pointed at the same directory (e.g. a network mount or CI cache). The reference `LocalDirRemoteTier`; real S3/HTTP tiers implement the same `RemoteCacheTier` trait')
            [CompletionResult]::new('--cache-max-size', '--cache-max-size', [CompletionResultType]::ParameterName, 'Soft cap on jar cache size in MiB; oldest entries are pruned first (default: 512). Useful on space-constrained or CI machines')
            [CompletionResult]::new('--cache-max-age-days', '--cache-max-age-days', [CompletionResultType]::ParameterName, 'Maximum age of jar cache entries in days before automatic pruning (default: 180)')
            [CompletionResult]::new('--changed-since', '--changed-since', [CompletionResultType]::ParameterName, 'Incremental scan: only jars modified at or after this time (RFC3339 or unix seconds)')
            [CompletionResult]::new('--dump-facts', '--dump-facts', [CompletionResultType]::ParameterName, 'Write the raw Phase-2 fact snapshot to a JSON file')
            [CompletionResult]::new('--explain', '--explain', [CompletionResultType]::ParameterName, 'Explain one finding id with its supporting facts')
            [CompletionResult]::new('--spark-report', '--spark-report', [CompletionResultType]::ParameterName, 'Explicit spark report JSON (`intermed-spark-report-v1`)')
            [CompletionResult]::new('--perf-tick-spike-ms', '--perf-tick-spike-ms', [CompletionResultType]::ParameterName, 'Minimum tick spike duration in ms to report (default: 50)')
            [CompletionResult]::new('--perf-high-cpu-percent', '--perf-high-cpu-percent', [CompletionResultType]::ParameterName, 'CPU percent at or above which hot methods/mods are treated as severe (default: 50.0)')
            [CompletionResult]::new('--perf-hot-method-floor', '--perf-hot-method-floor', [CompletionResultType]::ParameterName, 'Minimum CPU percent for hot-method ↔ mixin correlation (default: 5.0)')
            [CompletionResult]::new('--perf-tick-spike-warn-ms', '--perf-tick-spike-warn-ms', [CompletionResultType]::ParameterName, 'Tick spike severity bump threshold in ms (default: 100)')
            [CompletionResult]::new('--metadata-level', '--metadata-level', [CompletionResultType]::ParameterName, 'Metadata analysis preset: `basic`, `enriched`, or `full`')
            [CompletionResult]::new('--resource-level', '--resource-level', [CompletionResultType]::ParameterName, 'Resource/data-semantics (Layer M) AST depth: `basic` (off), `semantic`, or `full`')
            [CompletionResult]::new('--security-min-note-signals', '--security-min-note-signals', [CompletionResultType]::ParameterName, 'Note-level security signals required before emitting a grouped finding (default: 2)')
            [CompletionResult]::new('--sbom-well-identified-trust', '--sbom-well-identified-trust', [CompletionResultType]::ParameterName, 'SBOM trust score (0..=100) for well-identified jars (default: 60)')
            [CompletionResult]::new('--log-parallel-line-threshold', '--log-parallel-line-threshold', [CompletionResultType]::ParameterName, 'Log line count above which scanning uses parallel workers (default: 4096)')
            [CompletionResult]::new('--security-corroborated-confidence', '--security-corroborated-confidence', [CompletionResultType]::ParameterName, 'Confidence for reflection-corroborated security facts (default: 0.4)')
            [CompletionResult]::new('--minecraft-jar', '--minecraft-jar', [CompletionResultType]::ParameterName, 'Minecraft client/server jar to index. Powers two layers: mixin apply-failure verification against vanilla classes (Layer F), and a vanilla resource index (Layer M) so `minecraft:` references resolve and tags expand against real vanilla data instead of being assumed present')
            [CompletionResult]::new('--minecraft-mappings', '--minecraft-mappings', [CompletionResultType]::ParameterName, 'Yarn/Mojmap Tiny v2 mappings (`mappings.tiny`) for named↔intermediary bridging during mixin apply-failure checks with `--minecraft-jar`')
            [CompletionResult]::new('--mixin-level', '--mixin-level', [CompletionResultType]::ParameterName, 'Mixin analysis preset: `normal` (overlaps/risk only), `detailed` (+ recommendations), `full` (+ per-handler intelligence findings)')
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'Persist this run to a DuckDB analytics file (requires `--features duckdb`)')
            [CompletionResult]::new('--rule-pack', '--rule-pack', [CompletionResultType]::ParameterName, 'Extra declarative rule packs: file path or installed pack id (repeatable)')
            [CompletionResult]::new('--rule-pack-dir', '--rule-pack-dir', [CompletionResultType]::ParameterName, 'Rule pack install directory (default: XDG `.../intermed/rule-packs`)')
            [CompletionResult]::new('--rule-pack-trusted-keys', '--rule-pack-trusted-keys', [CompletionResultType]::ParameterName, 'Trusted publisher keys file for verifying signed rule pack overlays')
            [CompletionResult]::new('--rule-pack-registry', '--rule-pack-registry', [CompletionResultType]::ParameterName, 'Registry index path or URL for resolving `--rule-pack` ids')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--mixin-risk', '--mixin-risk', [CompletionResultType]::ParameterName, 'Enable Layer-F Mixin risk scanning during doctor')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit the full report as `intermed-doctor-report-v1` JSON')
            [CompletionResult]::new('--sarif', '--sarif', [CompletionResultType]::ParameterName, 'Emit SARIF 2.1.0 (for IDE / CI code-scanning)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable ANSI colour even on a TTY')
            [CompletionResult]::new('--exit-zero', '--exit-zero', [CompletionResultType]::ParameterName, 'Exit 0 whenever the run completes, regardless of findings')
            [CompletionResult]::new('--no-cache', '--no-cache', [CompletionResultType]::ParameterName, 'Disable the on-disk jar scan cache (default: cache enabled at XDG path)')
            [CompletionResult]::new('--performance', '--performance', [CompletionResultType]::ParameterName, 'Enable Layer-I Spark report import during doctor')
            [CompletionResult]::new('--no-mixin-handler-effects', '--no-mixin-handler-effects', [CompletionResultType]::ParameterName, 'Skip per-handler bytecode intelligence facts and findings')
            [CompletionResult]::new('--mixin-handler-effects', '--mixin-handler-effects', [CompletionResultType]::ParameterName, 'Force per-handler bytecode intelligence on (overrides preset)')
            [CompletionResult]::new('--no-mixin-recommendations', '--no-mixin-recommendations', [CompletionResultType]::ParameterName, 'Skip safer-mixin recommendation facts and fix candidates')
            [CompletionResult]::new('--mixin-recommendations', '--mixin-recommendations', [CompletionResultType]::ParameterName, 'Force safer-mixin recommendations on (overrides preset)')
            [CompletionResult]::new('--db-best-effort', '--db-best-effort', [CompletionResultType]::ParameterName, 'Treat `--db` persistence failure as a warning instead of an error exit. By default a requested `--db` write that fails returns a non-zero exit so automation notices the result was not saved')
            [CompletionResult]::new('--core-rule-pack-only', '--core-rule-pack-only', [CompletionResultType]::ParameterName, 'Use only the embedded core rule pack (ignore installed/community overlays)')
            [CompletionResult]::new('--allow-insecure-registry', '--allow-insecure-registry', [CompletionResultType]::ParameterName, 'Allow `http://` rule-pack registries/packs (insecure; HTTPS is required by default)')
            [CompletionResult]::new('--allow-unsigned-rules', '--allow-unsigned-rules', [CompletionResultType]::ParameterName, 'Accept unsigned, or signed-but-unpinned, remote rule packs')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'intermed;vfs' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan jar assets/data writers and summarize resource collisions')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain each resource collision and its merge/override class')
            [CompletionResult]::new('overlay', 'overlay', [CompletionResultType]::ParameterValue, 'Write a read-only overlay preview directory from detected collisions')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;vfs;scan' {
            [CompletionResult]::new('--path', '--path', [CompletionResultType]::ParameterName, 'Explain a single resource path (e.g. `data/create/recipes/crushing/tuff.json`)')
            [CompletionResult]::new('--resource-level', '--resource-level', [CompletionResultType]::ParameterName, 'AST depth used by `--ast`: `semantic` (default) or `full`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--ast', '--ast', [CompletionResultType]::ParameterName, 'Show the Layer-M typed AST view (domain, semantic diff, references) for `--path`. Requires `--path`')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Accepted for script consistency; VFS output currently has no ANSI colour')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;vfs;explain' {
            [CompletionResult]::new('--path', '--path', [CompletionResultType]::ParameterName, 'Explain a single resource path (e.g. `data/create/recipes/crushing/tuff.json`)')
            [CompletionResult]::new('--resource-level', '--resource-level', [CompletionResultType]::ParameterName, 'AST depth used by `--ast`: `semantic` (default) or `full`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--ast', '--ast', [CompletionResultType]::ParameterName, 'Show the Layer-M typed AST view (domain, semantic diff, references) for `--path`. Requires `--path`')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Accepted for script consistency; VFS output currently has no ANSI colour')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;vfs;overlay' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'New output directory for the overlay preview')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--include-unsafe-winners', '--include-unsafe-winners', [CompletionResultType]::ParameterName, 'Also stage order-dependent collisions by picking a lexical winner. These are previews, NOT safe fixes: the manifest marks them safe_to_apply=false. By default only deterministic, order-independent merges are written')
            [CompletionResult]::new('--explain-plan', '--explain-plan', [CompletionResultType]::ParameterName, 'Print the semantic overlay plan (`intermed-overlay-plan-v2`: safe / review / unsafe buckets) to stdout and exit — read-only, writes nothing')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Accepted for script consistency; VFS output currently has no ANSI colour')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;vfs;help' {
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan jar assets/data writers and summarize resource collisions')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain each resource collision and its merge/override class')
            [CompletionResult]::new('overlay', 'overlay', [CompletionResultType]::ParameterValue, 'Write a read-only overlay preview directory from detected collisions')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;vfs;help;scan' {
            break
        }
        'intermed;vfs;help;explain' {
            break
        }
        'intermed;vfs;help;overlay' {
            break
        }
        'intermed;vfs;help;help' {
            break
        }
        'intermed;deps' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('graph', 'graph', [CompletionResultType]::ParameterValue, 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)')
            [CompletionResult]::new('resolve', 'resolve', [CompletionResultType]::ParameterValue, 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON')
            [CompletionResult]::new('why', 'why', [CompletionResultType]::ParameterValue, 'Explain why a mod/namespace is depended upon (declared + implicit reasons)')
            [CompletionResult]::new('why-missing', 'why-missing', [CompletionResultType]::ParameterValue, 'Explain why an absent dependency is required (the requiring edges)')
            [CompletionResult]::new('implicit', 'implicit', [CompletionResultType]::ParameterValue, 'List implicit references into a namespace (resource-derived dependencies)')
            [CompletionResult]::new('path', 'path', [CompletionResultType]::ParameterValue, 'Find a dependency chain between two mods (`deps path <from> <to>`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;deps;graph' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;resolve' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;why' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;why-missing' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;implicit' {
            [CompletionResult]::new('--namespace', '--namespace', [CompletionResultType]::ParameterName, 'The provider namespace to list implicit references for')
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;path' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;deps;help' {
            [CompletionResult]::new('graph', 'graph', [CompletionResultType]::ParameterValue, 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)')
            [CompletionResult]::new('resolve', 'resolve', [CompletionResultType]::ParameterValue, 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON')
            [CompletionResult]::new('why', 'why', [CompletionResultType]::ParameterValue, 'Explain why a mod/namespace is depended upon (declared + implicit reasons)')
            [CompletionResult]::new('why-missing', 'why-missing', [CompletionResultType]::ParameterValue, 'Explain why an absent dependency is required (the requiring edges)')
            [CompletionResult]::new('implicit', 'implicit', [CompletionResultType]::ParameterValue, 'List implicit references into a namespace (resource-derived dependencies)')
            [CompletionResult]::new('path', 'path', [CompletionResultType]::ParameterValue, 'Find a dependency chain between two mods (`deps path <from> <to>`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;deps;help;graph' {
            break
        }
        'intermed;deps;help;resolve' {
            break
        }
        'intermed;deps;help;why' {
            break
        }
        'intermed;deps;help;why-missing' {
            break
        }
        'intermed;deps;help;implicit' {
            break
        }
        'intermed;deps;help;path' {
            break
        }
        'intermed;deps;help;help' {
            break
        }
        'intermed;impact' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Blast radius of removing a mod (reverse resource graph + dependents)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Blast radius of bumping a mod''s version (which declared ranges reject it)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;impact;remove' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;impact;update' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'Override the mods directory (otherwise auto-detected)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit machine-readable JSON instead of text')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;impact;help' {
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Blast radius of removing a mod (reverse resource graph + dependents)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Blast radius of bumping a mod''s version (which declared ranges reject it)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;impact;help;remove' {
            break
        }
        'intermed;impact;help;update' {
            break
        }
        'intermed;impact;help;help' {
            break
        }
        'intermed;mixin-map' {
            [CompletionResult]::new('--graph-format', '--graph-format', [CompletionResultType]::ParameterName, 'Graph export format (default: json summary)')
            [CompletionResult]::new('--graph-out', '--graph-out', [CompletionResultType]::ParameterName, 'Write graph export to file (stdout when omitted for dot/graphml)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Accepted for script consistency; Mixin Map output currently has no ANSI colour')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'intermed;spark-map' {
            [CompletionResult]::new('--spark-report', '--spark-report', [CompletionResultType]::ParameterName, 'Explicit spark report JSON (`intermed-spark-report-v1`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Accepted for script consistency; Spark Map output currently has no ANSI colour')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;lab' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('discover', 'discover', [CompletionResultType]::ParameterValue, 'Build a reproducible corpus lock from a candidate pool')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Classify captured smoke-test outputs against a corpus lock')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render a compatibility matrix (JSON + HTML) from a lab run')
            [CompletionResult]::new('eval', 'eval', [CompletionResultType]::ParameterValue, 'Score Doctor predictions against lab ground truth (precision/recall)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;lab;discover' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output lock path')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;lab;run' {
            [CompletionResult]::new('--logs', '--logs', [CompletionResultType]::ParameterName, 'Directory of captured smoke outputs (`intermed-smoke-output-v1` JSON)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output directory for the run artifact (`lab-run.json`)')
            [CompletionResult]::new('--lab-excerpt-max', '--lab-excerpt-max', [CompletionResultType]::ParameterName, 'Maximum characters kept from a failure log excerpt (default: 280)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;lab;report' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output directory for `matrix.json` + `index.html`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;lab;eval' {
            [CompletionResult]::new('--manifest', '--manifest', [CompletionResultType]::ParameterName, 'Dataset manifest (`intermed-eval-manifest-v1`) listing report/run pairs')
            [CompletionResult]::new('--report', '--report', [CompletionResultType]::ParameterName, 'A single Doctor report JSON (`intermed-doctor-report-v1`); use with `--run`')
            [CompletionResult]::new('--run', '--run', [CompletionResultType]::ParameterName, 'A single lab run JSON (`intermed-lab-run-v1`); use with `--report`')
            [CompletionResult]::new('--min-severity', '--min-severity', [CompletionResultType]::ParameterName, 'Minimum prediction severity that counts as "flagged"')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output accuracy report path (`intermed-rule-accuracy-v3`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;lab;help' {
            [CompletionResult]::new('discover', 'discover', [CompletionResultType]::ParameterValue, 'Build a reproducible corpus lock from a candidate pool')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Classify captured smoke-test outputs against a corpus lock')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render a compatibility matrix (JSON + HTML) from a lab run')
            [CompletionResult]::new('eval', 'eval', [CompletionResultType]::ParameterValue, 'Score Doctor predictions against lab ground truth (precision/recall)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;lab;help;discover' {
            break
        }
        'intermed;lab;help;run' {
            break
        }
        'intermed;lab;help;report' {
            break
        }
        'intermed;lab;help;eval' {
            break
        }
        'intermed;lab;help;help' {
            break
        }
        'intermed;rules' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Validate rule-pack JSON/YAML files under a path')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack')
            [CompletionResult]::new('sign', 'sign', [CompletionResultType]::ParameterValue, 'Sign a v2 rule pack with an Ed25519 key')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify a signed rule pack (optional trusted-keys file)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Refresh an installed pack from the registry (embedded core by default)')
            [CompletionResult]::new('registry', 'registry', [CompletionResultType]::ParameterValue, 'List packs in a registry index (embedded default if omitted)')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a pack and its registry dependencies into XDG rule-packs')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Show the query-engine plan (EXPLAIN, and EXPLAIN ANALYZE with `--facts`) per rule')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;rules;check' {
            [CompletionResult]::new('--trusted-keys', '--trusted-keys', [CompletionResultType]::ParameterName, 'Trusted publisher public keys (one base64 key per line)')
            [CompletionResult]::new('--facts', '--facts', [CompletionResultType]::ParameterName, 'Fact snapshot JSON for `--trace` (from `doctor --dump-facts`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--require-signature', '--require-signature', [CompletionResultType]::ParameterName, 'Require a valid Ed25519 signature on v2 packs')
            [CompletionResult]::new('--trace', '--trace', [CompletionResultType]::ParameterName, 'Dry-run: evaluate each rule against facts JSON and print a trace table')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;generate' {
            [CompletionResult]::new('--backend', '--backend', [CompletionResultType]::ParameterName, 'Output backend: sql, rust, or datalog')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write to file instead of stdout')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'intermed;rules;sign' {
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Ed25519 seed file (32 raw bytes or base64 text)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output signed pack path (default: overwrite input)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;verify' {
            [CompletionResult]::new('--trusted-keys', '--trusted-keys', [CompletionResultType]::ParameterName, 'Trusted publisher public keys (one base64 key per line)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;update' {
            [CompletionResult]::new('--registry', '--registry', [CompletionResultType]::ParameterName, 'Registry index JSON or URL (`intermed-rule-registry-v1`). Defaults to embedded + community index')
            [CompletionResult]::new('--pack', '--pack', [CompletionResultType]::ParameterName, 'Pack id to refresh (default: intermed-core)')
            [CompletionResult]::new('--install-dir', '--install-dir', [CompletionResultType]::ParameterName, 'Install directory (default: XDG data/intermed/rule-packs)')
            [CompletionResult]::new('--trusted-keys', '--trusted-keys', [CompletionResultType]::ParameterName, 'Trusted publisher public keys (one base64 key per line) to pin signatures against')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--allow-insecure-registry', '--allow-insecure-registry', [CompletionResultType]::ParameterName, 'Allow `http://` registries/packs (insecure; HTTPS is required by default)')
            [CompletionResult]::new('--allow-unsigned-rules', '--allow-unsigned-rules', [CompletionResultType]::ParameterName, 'Accept unsigned, or signed-but-unpinned, remote rule packs')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;registry' {
            [CompletionResult]::new('--registry', '--registry', [CompletionResultType]::ParameterName, 'Registry index JSON or URL. Defaults to the embedded InterMed registry')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--allow-insecure-registry', '--allow-insecure-registry', [CompletionResultType]::ParameterName, 'Allow `http://` registries (insecure; HTTPS is required by default)')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;install' {
            [CompletionResult]::new('--registry', '--registry', [CompletionResultType]::ParameterName, 'registry')
            [CompletionResult]::new('--pack', '--pack', [CompletionResultType]::ParameterName, 'pack')
            [CompletionResult]::new('--install-dir', '--install-dir', [CompletionResultType]::ParameterName, 'install-dir')
            [CompletionResult]::new('--trusted-keys', '--trusted-keys', [CompletionResultType]::ParameterName, 'trusted-keys')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--allow-insecure-registry', '--allow-insecure-registry', [CompletionResultType]::ParameterName, 'Allow `http://` registries/packs (insecure; HTTPS is required by default)')
            [CompletionResult]::new('--allow-unsigned-rules', '--allow-unsigned-rules', [CompletionResultType]::ParameterName, 'Accept unsigned, or signed-but-unpinned, remote rule packs')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;explain' {
            [CompletionResult]::new('--rule', '--rule', [CompletionResultType]::ParameterName, 'Explain only this rule id (default: every lowerable rule)')
            [CompletionResult]::new('--facts', '--facts', [CompletionResultType]::ParameterName, 'A `doctor --dump-facts` JSON file: enables EXPLAIN ANALYZE on those real facts')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;rules;help' {
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Validate rule-pack JSON/YAML files under a path')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack')
            [CompletionResult]::new('sign', 'sign', [CompletionResultType]::ParameterValue, 'Sign a v2 rule pack with an Ed25519 key')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify a signed rule pack (optional trusted-keys file)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Refresh an installed pack from the registry (embedded core by default)')
            [CompletionResult]::new('registry', 'registry', [CompletionResultType]::ParameterValue, 'List packs in a registry index (embedded default if omitted)')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a pack and its registry dependencies into XDG rule-packs')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Show the query-engine plan (EXPLAIN, and EXPLAIN ANALYZE with `--facts`) per rule')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;rules;help;check' {
            break
        }
        'intermed;rules;help;generate' {
            break
        }
        'intermed;rules;help;sign' {
            break
        }
        'intermed;rules;help;verify' {
            break
        }
        'intermed;rules;help;update' {
            break
        }
        'intermed;rules;help;registry' {
            break
        }
        'intermed;rules;help;install' {
            break
        }
        'intermed;rules;help;explain' {
            break
        }
        'intermed;rules;help;help' {
            break
        }
        'intermed;db' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Run a read-only SQL query against the analytics store')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;db;query' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'DuckDB analytics database file')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;db;help' {
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Run a read-only SQL query against the analytics store')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;db;help;query' {
            break
        }
        'intermed;db;help;help' {
            break
        }
        'intermed;history' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('conflicts', 'conflicts', [CompletionResultType]::ParameterValue, 'Findings that recur across multiple runs within a time window')
            [CompletionResult]::new('patterns', 'patterns', [CompletionResultType]::ParameterValue, 'Recurring *kinds* of risk (rule + category) rolled up across all history')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Compare findings between two persisted runs')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Delete analytics runs older than a retention window')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;history;conflicts' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'DuckDB analytics database file')
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Relative look-back window (`30d`, `7d`, `24h`). Default: 30d')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;history;patterns' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'DuckDB analytics database file')
            [CompletionResult]::new('--limit', '--limit', [CompletionResultType]::ParameterName, 'Maximum patterns to show (highest severity / most recurring first)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;history;diff' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'db')
            [CompletionResult]::new('--run-a', '--run-a', [CompletionResultType]::ParameterName, 'run-a')
            [CompletionResult]::new('--run-b', '--run-b', [CompletionResultType]::ParameterName, 'run-b')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit structured JSON (`intermed-history-diff-v1`) instead of TSV')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;history;prune' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'db')
            [CompletionResult]::new('--keep', '--keep', [CompletionResultType]::ParameterName, 'Keep runs within this window (`90d`, `30d`). Older runs are deleted')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;history;help' {
            [CompletionResult]::new('conflicts', 'conflicts', [CompletionResultType]::ParameterValue, 'Findings that recur across multiple runs within a time window')
            [CompletionResult]::new('patterns', 'patterns', [CompletionResultType]::ParameterValue, 'Recurring *kinds* of risk (rule + category) rolled up across all history')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Compare findings between two persisted runs')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Delete analytics runs older than a retention window')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;history;help;conflicts' {
            break
        }
        'intermed;history;help;patterns' {
            break
        }
        'intermed;history;help;diff' {
            break
        }
        'intermed;history;help;prune' {
            break
        }
        'intermed;history;help;help' {
            break
        }
        'intermed;trends' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('mixin-risk', 'mixin-risk', [CompletionResultType]::ParameterValue, 'Mixin-category finding counts per persisted run')
            [CompletionResult]::new('mixin-overlaps', 'mixin-overlaps', [CompletionResultType]::ParameterValue, 'Top-N most frequent mixin overlaps (by mod set + target)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;trends;mixin-risk' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'DuckDB analytics database file')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;trends;mixin-overlaps' {
            [CompletionResult]::new('--db', '--db', [CompletionResultType]::ParameterName, 'DuckDB analytics database file')
            [CompletionResult]::new('--limit', '--limit', [CompletionResultType]::ParameterName, 'Number of rows to return (default: 10)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;trends;help' {
            [CompletionResult]::new('mixin-risk', 'mixin-risk', [CompletionResultType]::ParameterValue, 'Mixin-category finding counts per persisted run')
            [CompletionResult]::new('mixin-overlaps', 'mixin-overlaps', [CompletionResultType]::ParameterValue, 'Top-N most frequent mixin overlaps (by mod set + target)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;trends;help;mixin-risk' {
            break
        }
        'intermed;trends;help;mixin-overlaps' {
            break
        }
        'intermed;trends;help;help' {
            break
        }
        'intermed;cache' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Show hit/miss counters and on-disk cache size')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Force a prune pass (age + size limits)')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Delete all cached jar payloads and fingerprints')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;cache;stats' {
            [CompletionResult]::new('--cache-dir', '--cache-dir', [CompletionResultType]::ParameterName, 'cache-dir')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;cache;prune' {
            [CompletionResult]::new('--cache-dir', '--cache-dir', [CompletionResultType]::ParameterName, 'cache-dir')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;cache;clear' {
            [CompletionResult]::new('--cache-dir', '--cache-dir', [CompletionResultType]::ParameterName, 'cache-dir')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;cache;help' {
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Show hit/miss counters and on-disk cache size')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Force a prune pass (age + size limits)')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Delete all cached jar payloads and fingerprints')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;cache;help;stats' {
            break
        }
        'intermed;cache;help;prune' {
            break
        }
        'intermed;cache;help;clear' {
            break
        }
        'intermed;cache;help;help' {
            break
        }
        'intermed;sbom' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export SPDX or CycloneDX SBOM from jar metadata')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;sbom;export' {
            [CompletionResult]::new('--mods-dir', '--mods-dir', [CompletionResultType]::ParameterName, 'mods-dir')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'format')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'out')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;sbom;help' {
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export SPDX or CycloneDX SBOM from jar metadata')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;sbom;help;export' {
            break
        }
        'intermed;sbom;help;help' {
            break
        }
        'intermed;demo' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;demo;report' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output directory for `intermed-atlauncher-demo-summary.md`, `intermed-demo-report.html`, and JSON')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output directory for `intermed-atlauncher-demo-summary.md`, `intermed-demo-report.html`, and JSON')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md')
            [CompletionResult]::new('--dump-config', '--dump-config', [CompletionResultType]::ParameterName, 'Print the effective default config as TOML and exit (no subcommand required)')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress informational progress messages on stderr (errors still print)')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase informational detail (repeatable: `-v`, `-vv`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'intermed;demo;help' {
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;demo;help;report' {
            break
        }
        'intermed;demo;help;help' {
            break
        }
        'intermed;help' {
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Diagnose a server, instance, mods directory, or log/crash file')
            [CompletionResult]::new('vfs', 'vfs', [CompletionResultType]::ParameterValue, 'Inspect resource/data overrides and generate overlay previews')
            [CompletionResult]::new('deps', 'deps', [CompletionResultType]::ParameterValue, 'Layer-C dependency graph, resolution, and explainable queries')
            [CompletionResult]::new('impact', 'impact', [CompletionResultType]::ParameterValue, 'Blast-radius analysis for removing or updating a mod')
            [CompletionResult]::new('mixin-map', 'mixin-map', [CompletionResultType]::ParameterValue, 'Inspect static Mixin targets, overlaps, and overwrite risks')
            [CompletionResult]::new('spark-map', 'spark-map', [CompletionResultType]::ParameterValue, 'Import and summarize Spark performance reports')
            [CompletionResult]::new('lab', 'lab', [CompletionResultType]::ParameterValue, 'Compatibility Lab: corpus locks, smoke-test ingestion, matrices')
            [CompletionResult]::new('rules', 'rules', [CompletionResultType]::ParameterValue, 'Validate declarative rule packs')
            [CompletionResult]::new('db', 'db', [CompletionResultType]::ParameterValue, 'Query the DuckDB analytics store (`--features duckdb`)')
            [CompletionResult]::new('history', 'history', [CompletionResultType]::ParameterValue, 'Recurring conflicts across persisted diagnosis runs')
            [CompletionResult]::new('trends', 'trends', [CompletionResultType]::ParameterValue, 'Time-series analytics over persisted runs')
            [CompletionResult]::new('cache', 'cache', [CompletionResultType]::ParameterValue, 'Jar scan cache maintenance (`stats`, `prune`, `clear`)')
            [CompletionResult]::new('sbom', 'sbom', [CompletionResultType]::ParameterValue, 'SBOM export (SPDX / CycloneDX) from a mods directory')
            [CompletionResult]::new('demo', 'demo', [CompletionResultType]::ParameterValue, 'Presentation demo: aggregate a small real-mod run into launcher-facing reports')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'intermed;help;doctor' {
            break
        }
        'intermed;help;vfs' {
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan jar assets/data writers and summarize resource collisions')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain each resource collision and its merge/override class')
            [CompletionResult]::new('overlay', 'overlay', [CompletionResultType]::ParameterValue, 'Write a read-only overlay preview directory from detected collisions')
            break
        }
        'intermed;help;vfs;scan' {
            break
        }
        'intermed;help;vfs;explain' {
            break
        }
        'intermed;help;vfs;overlay' {
            break
        }
        'intermed;help;deps' {
            [CompletionResult]::new('graph', 'graph', [CompletionResultType]::ParameterValue, 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)')
            [CompletionResult]::new('resolve', 'resolve', [CompletionResultType]::ParameterValue, 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON')
            [CompletionResult]::new('why', 'why', [CompletionResultType]::ParameterValue, 'Explain why a mod/namespace is depended upon (declared + implicit reasons)')
            [CompletionResult]::new('why-missing', 'why-missing', [CompletionResultType]::ParameterValue, 'Explain why an absent dependency is required (the requiring edges)')
            [CompletionResult]::new('implicit', 'implicit', [CompletionResultType]::ParameterValue, 'List implicit references into a namespace (resource-derived dependencies)')
            [CompletionResult]::new('path', 'path', [CompletionResultType]::ParameterValue, 'Find a dependency chain between two mods (`deps path <from> <to>`)')
            break
        }
        'intermed;help;deps;graph' {
            break
        }
        'intermed;help;deps;resolve' {
            break
        }
        'intermed;help;deps;why' {
            break
        }
        'intermed;help;deps;why-missing' {
            break
        }
        'intermed;help;deps;implicit' {
            break
        }
        'intermed;help;deps;path' {
            break
        }
        'intermed;help;impact' {
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Blast radius of removing a mod (reverse resource graph + dependents)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Blast radius of bumping a mod''s version (which declared ranges reject it)')
            break
        }
        'intermed;help;impact;remove' {
            break
        }
        'intermed;help;impact;update' {
            break
        }
        'intermed;help;mixin-map' {
            break
        }
        'intermed;help;spark-map' {
            break
        }
        'intermed;help;lab' {
            [CompletionResult]::new('discover', 'discover', [CompletionResultType]::ParameterValue, 'Build a reproducible corpus lock from a candidate pool')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Classify captured smoke-test outputs against a corpus lock')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render a compatibility matrix (JSON + HTML) from a lab run')
            [CompletionResult]::new('eval', 'eval', [CompletionResultType]::ParameterValue, 'Score Doctor predictions against lab ground truth (precision/recall)')
            break
        }
        'intermed;help;lab;discover' {
            break
        }
        'intermed;help;lab;run' {
            break
        }
        'intermed;help;lab;report' {
            break
        }
        'intermed;help;lab;eval' {
            break
        }
        'intermed;help;rules' {
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Validate rule-pack JSON/YAML files under a path')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack')
            [CompletionResult]::new('sign', 'sign', [CompletionResultType]::ParameterValue, 'Sign a v2 rule pack with an Ed25519 key')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify a signed rule pack (optional trusted-keys file)')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Refresh an installed pack from the registry (embedded core by default)')
            [CompletionResult]::new('registry', 'registry', [CompletionResultType]::ParameterValue, 'List packs in a registry index (embedded default if omitted)')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a pack and its registry dependencies into XDG rule-packs')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Show the query-engine plan (EXPLAIN, and EXPLAIN ANALYZE with `--facts`) per rule')
            break
        }
        'intermed;help;rules;check' {
            break
        }
        'intermed;help;rules;generate' {
            break
        }
        'intermed;help;rules;sign' {
            break
        }
        'intermed;help;rules;verify' {
            break
        }
        'intermed;help;rules;update' {
            break
        }
        'intermed;help;rules;registry' {
            break
        }
        'intermed;help;rules;install' {
            break
        }
        'intermed;help;rules;explain' {
            break
        }
        'intermed;help;db' {
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Run a read-only SQL query against the analytics store')
            break
        }
        'intermed;help;db;query' {
            break
        }
        'intermed;help;history' {
            [CompletionResult]::new('conflicts', 'conflicts', [CompletionResultType]::ParameterValue, 'Findings that recur across multiple runs within a time window')
            [CompletionResult]::new('patterns', 'patterns', [CompletionResultType]::ParameterValue, 'Recurring *kinds* of risk (rule + category) rolled up across all history')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Compare findings between two persisted runs')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Delete analytics runs older than a retention window')
            break
        }
        'intermed;help;history;conflicts' {
            break
        }
        'intermed;help;history;patterns' {
            break
        }
        'intermed;help;history;diff' {
            break
        }
        'intermed;help;history;prune' {
            break
        }
        'intermed;help;trends' {
            [CompletionResult]::new('mixin-risk', 'mixin-risk', [CompletionResultType]::ParameterValue, 'Mixin-category finding counts per persisted run')
            [CompletionResult]::new('mixin-overlaps', 'mixin-overlaps', [CompletionResultType]::ParameterValue, 'Top-N most frequent mixin overlaps (by mod set + target)')
            break
        }
        'intermed;help;trends;mixin-risk' {
            break
        }
        'intermed;help;trends;mixin-overlaps' {
            break
        }
        'intermed;help;cache' {
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Show hit/miss counters and on-disk cache size')
            [CompletionResult]::new('prune', 'prune', [CompletionResultType]::ParameterValue, 'Force a prune pass (age + size limits)')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Delete all cached jar payloads and fingerprints')
            break
        }
        'intermed;help;cache;stats' {
            break
        }
        'intermed;help;cache;prune' {
            break
        }
        'intermed;help;cache;clear' {
            break
        }
        'intermed;help;sbom' {
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export SPDX or CycloneDX SBOM from jar metadata')
            break
        }
        'intermed;help;sbom;export' {
            break
        }
        'intermed;help;demo' {
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory')
            break
        }
        'intermed;help;demo;report' {
            break
        }
        'intermed;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
