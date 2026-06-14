# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_intermed_global_optspecs
	string join \n config= dump-config quiet v/verbose h/help V/version
end

function __fish_intermed_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_intermed_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_intermed_using_subcommand
	set -l cmd (__fish_intermed_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c intermed -n "__fish_intermed_needs_command" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_needs_command" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_needs_command" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_needs_command" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c intermed -n "__fish_intermed_needs_command" -s V -l version -d 'Print version'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "doctor" -d 'Diagnose a server, instance, mods directory, or log/crash file'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "vfs" -d 'Inspect resource/data overrides and generate overlay previews'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "deps" -d 'Layer-C dependency graph and PubGrub resolution'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "mixin-map" -d 'Inspect static Mixin targets, overlaps, and overwrite risks'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "spark-map" -d 'Import and summarize Spark performance reports'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "lab" -d 'Compatibility Lab: corpus locks, smoke-test ingestion, matrices'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "rules" -d 'Validate declarative rule packs'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "db" -d 'Query the DuckDB analytics store (`--features duckdb`)'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "history" -d 'Recurring conflicts across persisted diagnosis runs'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "trends" -d 'Time-series analytics over persisted runs'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "cache" -d 'Jar scan cache maintenance (`stats`, `prune`, `clear`)'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "sbom" -d 'SBOM export (SPDX / CycloneDX) from a mods directory'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "demo" -d 'Presentation demo: aggregate a small real-mod run into launcher-facing reports'
complete -c intermed -n "__fish_intermed_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l mods-dir -d 'Override the mods directory (otherwise auto-detected)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l logic -d 'Rule backend selection. Imperative remains the stable fallback' -r -f -a "imperative\t''
datalog\t''
souffle\t''
duckdb\t'In-process DuckDB SQL rule backend (requires `--features duckdb`)'"
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l jobs -l threads -d 'Cap the worker thread count for parallel jar/log scanning. Unset or `0` uses all available cores; lower it on weak machines or shared CI runners' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l html -d 'Write a self-contained HTML report (`index.html` style)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l profile -d 'Write wall-clock phase profile JSON (`intermed-doctor-profile-v1`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l cache-dir -d 'Override jar cache root (default: $XDG_CACHE_HOME/intermed or ~/.cache/intermed)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l cache-remote-dir -d 'Shared/remote cache tier directory (Tier 3). A scan payload written by one machine is reused by any other pointed at the same directory (e.g. a network mount or CI cache). The reference `LocalDirRemoteTier`; real S3/HTTP tiers implement the same `RemoteCacheTier` trait' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l cache-max-size -d 'Soft cap on jar cache size in MiB; oldest entries are pruned first (default: 512). Useful on space-constrained or CI machines' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l cache-max-age-days -d 'Maximum age of jar cache entries in days before automatic pruning (default: 180)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l changed-since -d 'Incremental scan: only jars modified at or after this time (RFC3339 or unix seconds)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l dump-facts -d 'Write the raw Phase-2 fact snapshot to a JSON file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l explain -d 'Explain one finding id with its supporting facts' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l spark-report -d 'Explicit spark report JSON (`intermed-spark-report-v1`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l perf-tick-spike-ms -d 'Minimum tick spike duration in ms to report (default: 50)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l perf-high-cpu-percent -d 'CPU percent at or above which hot methods/mods are treated as severe (default: 50.0)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l perf-hot-method-floor -d 'Minimum CPU percent for hot-method ↔ mixin correlation (default: 5.0)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l perf-tick-spike-warn-ms -d 'Tick spike severity bump threshold in ms (default: 100)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l metadata-level -d 'Metadata analysis preset: `basic`, `enriched`, or `full`' -r -f -a "basic\t''
enriched\t''
full\t''"
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l resource-level -d 'Resource/data-semantics (Layer M) AST depth: `basic` (off), `semantic`, or `full`' -r -f -a "basic\t''
semantic\t''
full\t''"
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l security-min-note-signals -d 'Note-level security signals required before emitting a grouped finding (default: 2)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l sbom-well-identified-trust -d 'SBOM trust score (0..=100) for well-identified jars (default: 60)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l log-parallel-line-threshold -d 'Log line count above which scanning uses parallel workers (default: 4096)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l security-corroborated-confidence -d 'Confidence for reflection-corroborated security facts (default: 0.4)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l minecraft-jar -d 'Minecraft client/server jar to index for mixin apply-failure verification. Without it, apply-failure checks cover only mod-targeting mixins' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l minecraft-mappings -d 'Yarn/Mojmap Tiny v2 mappings (`mappings.tiny`) for named↔intermediary bridging during mixin apply-failure checks with `--minecraft-jar`' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l mixin-level -d 'Mixin analysis preset: `normal` (overlaps/risk only), `detailed` (+ recommendations), `full` (+ per-handler intelligence findings)' -r -f -a "normal\t''
detailed\t''
full\t''"
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l db -d 'Persist this run to a DuckDB analytics file (requires `--features duckdb`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l rule-pack -d 'Extra declarative rule packs: file path or installed pack id (repeatable)' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l rule-pack-dir -d 'Rule pack install directory (default: XDG `.../intermed/rule-packs`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l rule-pack-trusted-keys -d 'Trusted publisher keys file for verifying signed rule pack overlays' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l rule-pack-registry -d 'Registry index path or URL for resolving `--rule-pack` ids' -r
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l mixin-risk -d 'Enable Layer-F Mixin risk scanning during doctor'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l json -d 'Emit the full report as `intermed-doctor-report-v1` JSON'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l sarif -d 'Emit SARIF 2.1.0 (for IDE / CI code-scanning)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l no-color -d 'Disable ANSI colour even on a TTY'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l exit-zero -d 'Exit 0 whenever the run completes, regardless of findings'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l no-cache -d 'Disable the on-disk jar scan cache (default: cache enabled at XDG path)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l performance -d 'Enable Layer-I Spark report import during doctor'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l no-mixin-handler-effects -d 'Skip per-handler bytecode intelligence facts and findings'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l mixin-handler-effects -d 'Force per-handler bytecode intelligence on (overrides preset)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l no-mixin-recommendations -d 'Skip safer-mixin recommendation facts and fix candidates'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l mixin-recommendations -d 'Force safer-mixin recommendations on (overrides preset)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l db-best-effort -d 'Treat `--db` persistence failure as a warning instead of an error exit. By default a requested `--db` write that fails returns a non-zero exit so automation notices the result was not saved'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l core-rule-pack-only -d 'Use only the embedded core rule pack (ignore installed/community overlays)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l allow-insecure-registry -d 'Allow `http://` rule-pack registries/packs (insecure; HTTPS is required by default)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l allow-unsigned-rules -d 'Accept unsigned, or signed-but-unpinned, remote rule packs'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -f -a "scan" -d 'Scan jar assets/data writers and summarize resource collisions'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -f -a "explain" -d 'Explain each resource collision and its merge/override class'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -f -a "overlay" -d 'Write a read-only overlay preview directory from detected collisions'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and not __fish_seen_subcommand_from scan explain overlay help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l path -d 'Explain a single resource path (e.g. `data/create/recipes/crushing/tuff.json`)' -r
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l resource-level -d 'AST depth used by `--ast`: `semantic` (default) or `full`' -r -f -a "basic\t''
semantic\t''
full\t''"
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l ast -d 'Show the Layer-M typed AST view (domain, semantic diff, references) for `--path`. Requires `--path`'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l no-color -d 'Accepted for script consistency; VFS output currently has no ANSI colour'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from scan" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l path -d 'Explain a single resource path (e.g. `data/create/recipes/crushing/tuff.json`)' -r
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l resource-level -d 'AST depth used by `--ast`: `semantic` (default) or `full`' -r -f -a "basic\t''
semantic\t''
full\t''"
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l ast -d 'Show the Layer-M typed AST view (domain, semantic diff, references) for `--path`. Requires `--path`'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l no-color -d 'Accepted for script consistency; VFS output currently has no ANSI colour'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l out -d 'New output directory for the overlay preview' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l include-unsafe-winners -d 'Also stage order-dependent collisions by picking a lexical winner. These are previews, NOT safe fixes: the manifest marks them safe_to_apply=false. By default only deterministic, order-independent merges are written'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l explain-plan -d 'Print the semantic overlay plan (`intermed-overlay-plan-v2`: safe / review / unsafe buckets) to stdout and exit — read-only, writes nothing'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l no-color -d 'Accepted for script consistency; VFS output currently has no ANSI colour'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from overlay" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from help" -f -a "scan" -d 'Scan jar assets/data writers and summarize resource collisions'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain each resource collision and its merge/override class'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from help" -f -a "overlay" -d 'Write a read-only overlay preview directory from detected collisions'
complete -c intermed -n "__fish_intermed_using_subcommand vfs; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -f -a "graph" -d 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -f -a "resolve" -d 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and not __fish_seen_subcommand_from graph resolve help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -l mods-dir -d 'Override the mods directory (otherwise auto-detected)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from graph" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -l mods-dir -d 'Override the mods directory (otherwise auto-detected)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from resolve" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from help" -f -a "graph" -d 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from help" -f -a "resolve" -d 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON'
complete -c intermed -n "__fish_intermed_using_subcommand deps; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l graph-format -d 'Graph export format (default: json summary)' -r -f -a "json\t'Human-readable mixin map summary (default)'
graph-json\t'Machine-readable interaction graph (`MixinGraphExport` JSON)'
dot\t''
graphml\t''
html\t''"
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l graph-out -d 'Write graph export to file (stdout when omitted for dot/graphml)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l no-color -d 'Accepted for script consistency; Mixin Map output currently has no ANSI colour'
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand mixin-map" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -l spark-report -d 'Explicit spark report JSON (`intermed-spark-report-v1`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -l no-color -d 'Accepted for script consistency; Spark Map output currently has no ANSI colour'
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand spark-map" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -f -a "discover" -d 'Build a reproducible corpus lock from a candidate pool'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -f -a "run" -d 'Classify captured smoke-test outputs against a corpus lock'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -f -a "report" -d 'Render a compatibility matrix (JSON + HTML) from a lab run'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -f -a "eval" -d 'Score Doctor predictions against lab ground truth (precision/recall)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and not __fish_seen_subcommand_from discover run report eval help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -l out -d 'Output lock path' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from discover" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l logs -d 'Directory of captured smoke outputs (`intermed-smoke-output-v1` JSON)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l out -d 'Output directory for the run artifact (`lab-run.json`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l lab-excerpt-max -d 'Maximum characters kept from a failure log excerpt (default: 280)' -r
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -l out -d 'Output directory for `matrix.json` + `index.html`' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l manifest -d 'Dataset manifest (`intermed-eval-manifest-v1`) listing report/run pairs' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l report -d 'A single Doctor report JSON (`intermed-doctor-report-v1`); use with `--run`' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l run -d 'A single lab run JSON (`intermed-lab-run-v1`); use with `--report`' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l min-severity -d 'Minimum prediction severity that counts as "flagged"' -r -f -a "note\t''
warn\t''
error\t''"
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l out -d 'Output accuracy report path (`intermed-rule-accuracy-v3`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from eval" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from help" -f -a "discover" -d 'Build a reproducible corpus lock from a candidate pool'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from help" -f -a "run" -d 'Classify captured smoke-test outputs against a corpus lock'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from help" -f -a "report" -d 'Render a compatibility matrix (JSON + HTML) from a lab run'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from help" -f -a "eval" -d 'Score Doctor predictions against lab ground truth (precision/recall)'
complete -c intermed -n "__fish_intermed_using_subcommand lab; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "check" -d 'Validate rule-pack JSON/YAML files under a path'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "generate" -d 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "sign" -d 'Sign a v2 rule pack with an Ed25519 key'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "verify" -d 'Verify a signed rule pack (optional trusted-keys file)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "update" -d 'Refresh an installed pack from the registry (embedded core by default)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "registry" -d 'List packs in a registry index (embedded default if omitted)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "install" -d 'Install a pack and its registry dependencies into XDG rule-packs'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and not __fish_seen_subcommand_from check generate sign verify update registry install help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l trusted-keys -d 'Trusted publisher public keys (one base64 key per line)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l facts -d 'Fact snapshot JSON for `--trace` (from `doctor --dump-facts`)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l require-signature -d 'Require a valid Ed25519 signature on v2 packs'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l trace -d 'Dry-run: evaluate each rule against facts JSON and print a trace table'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from check" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -l backend -d 'Output backend: sql, rust, or datalog' -r -f -a "sql\t''
rust\t''
datalog\t''"
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -l out -d 'Write to file instead of stdout' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from generate" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -l key -d 'Ed25519 seed file (32 raw bytes or base64 text)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -l out -d 'Output signed pack path (default: overwrite input)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from sign" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -l trusted-keys -d 'Trusted publisher public keys (one base64 key per line)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l registry -d 'Registry index JSON or URL (`intermed-rule-registry-v1`). Defaults to embedded + community index' -r
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l pack -d 'Pack id to refresh (default: intermed-core)' -r
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l install-dir -d 'Install directory (default: XDG data/intermed/rule-packs)' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l trusted-keys -d 'Trusted publisher public keys (one base64 key per line) to pin signatures against' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l allow-insecure-registry -d 'Allow `http://` registries/packs (insecure; HTTPS is required by default)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l allow-unsigned-rules -d 'Accept unsigned, or signed-but-unpinned, remote rule packs'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from update" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -l registry -d 'Registry index JSON or URL. Defaults to the embedded InterMed registry' -r
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -l allow-insecure-registry -d 'Allow `http://` registries (insecure; HTTPS is required by default)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from registry" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l registry -r
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l pack -r
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l install-dir -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l trusted-keys -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l allow-insecure-registry -d 'Allow `http://` registries/packs (insecure; HTTPS is required by default)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l allow-unsigned-rules -d 'Accept unsigned, or signed-but-unpinned, remote rule packs'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "check" -d 'Validate rule-pack JSON/YAML files under a path'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "generate" -d 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "sign" -d 'Sign a v2 rule pack with an Ed25519 key'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Verify a signed rule pack (optional trusted-keys file)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "update" -d 'Refresh an installed pack from the registry (embedded core by default)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "registry" -d 'List packs in a registry index (embedded default if omitted)'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "install" -d 'Install a pack and its registry dependencies into XDG rule-packs'
complete -c intermed -n "__fish_intermed_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -f -a "query" -d 'Run a read-only SQL query against the analytics store'
complete -c intermed -n "__fish_intermed_using_subcommand db; and not __fish_seen_subcommand_from query help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -l db -d 'DuckDB analytics database file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from query" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "query" -d 'Run a read-only SQL query against the analytics store'
complete -c intermed -n "__fish_intermed_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -f -a "conflicts" -d 'Findings that recur across multiple runs within a time window'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -f -a "patterns" -d 'Recurring *kinds* of risk (rule + category) rolled up across all history'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -f -a "diff" -d 'Compare findings between two persisted runs'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -f -a "prune" -d 'Delete analytics runs older than a retention window'
complete -c intermed -n "__fish_intermed_using_subcommand history; and not __fish_seen_subcommand_from conflicts patterns diff prune help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -l db -d 'DuckDB analytics database file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -l since -d 'Relative look-back window (`30d`, `7d`, `24h`). Default: 30d' -r
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from conflicts" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -l db -d 'DuckDB analytics database file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -l limit -d 'Maximum patterns to show (highest severity / most recurring first)' -r
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from patterns" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l db -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l run-a -r
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l run-b -r
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l json -d 'Emit structured JSON (`intermed-history-diff-v1`) instead of TSV'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from diff" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -l db -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -l keep -d 'Keep runs within this window (`90d`, `30d`). Older runs are deleted' -r
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from prune" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from help" -f -a "conflicts" -d 'Findings that recur across multiple runs within a time window'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from help" -f -a "patterns" -d 'Recurring *kinds* of risk (rule + category) rolled up across all history'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from help" -f -a "diff" -d 'Compare findings between two persisted runs'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from help" -f -a "prune" -d 'Delete analytics runs older than a retention window'
complete -c intermed -n "__fish_intermed_using_subcommand history; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -f -a "mixin-risk" -d 'Mixin-category finding counts per persisted run'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -f -a "mixin-overlaps" -d 'Top-N most frequent mixin overlaps (by mod set + target)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and not __fish_seen_subcommand_from mixin-risk mixin-overlaps help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -l db -d 'DuckDB analytics database file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-risk" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -l db -d 'DuckDB analytics database file' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -l limit -d 'Number of rows to return (default: 10)' -r
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from mixin-overlaps" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from help" -f -a "mixin-risk" -d 'Mixin-category finding counts per persisted run'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from help" -f -a "mixin-overlaps" -d 'Top-N most frequent mixin overlaps (by mod set + target)'
complete -c intermed -n "__fish_intermed_using_subcommand trends; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -f -a "stats" -d 'Show hit/miss counters and on-disk cache size'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -f -a "prune" -d 'Force a prune pass (age + size limits)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -f -a "clear" -d 'Delete all cached jar payloads and fingerprints'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and not __fish_seen_subcommand_from stats prune clear help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -l cache-dir -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from stats" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -l cache-dir -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from prune" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -l cache-dir -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from clear" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "stats" -d 'Show hit/miss counters and on-disk cache size'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "prune" -d 'Force a prune pass (age + size limits)'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "clear" -d 'Delete all cached jar payloads and fingerprints'
complete -c intermed -n "__fish_intermed_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -f -a "export" -d 'Export SPDX or CycloneDX SBOM from jar metadata'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and not __fish_seen_subcommand_from export help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l mods-dir -r -F
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l format -r -f -a "spdx-json\t''
cyclonedx-json\t''"
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l out -r -F
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export SPDX or CycloneDX SBOM from jar metadata'
complete -c intermed -n "__fish_intermed_using_subcommand sbom; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -f -a "report" -d 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and not __fish_seen_subcommand_from report help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -s o -l out -d 'Output directory for `intermed-atlauncher-demo-summary.md`, `intermed-demo-report.html`, and JSON' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -l config -d 'Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/CONFIG.md' -r -F
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -l dump-config -d 'Print the effective default config as TOML and exit (no subcommand required)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -l quiet -d 'Suppress informational progress messages on stderr (errors still print)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase informational detail (repeatable: `-v`, `-vv`)'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from help" -f -a "report" -d 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory'
complete -c intermed -n "__fish_intermed_using_subcommand demo; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "doctor" -d 'Diagnose a server, instance, mods directory, or log/crash file'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "vfs" -d 'Inspect resource/data overrides and generate overlay previews'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "deps" -d 'Layer-C dependency graph and PubGrub resolution'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "mixin-map" -d 'Inspect static Mixin targets, overlaps, and overwrite risks'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "spark-map" -d 'Import and summarize Spark performance reports'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "lab" -d 'Compatibility Lab: corpus locks, smoke-test ingestion, matrices'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "rules" -d 'Validate declarative rule packs'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "db" -d 'Query the DuckDB analytics store (`--features duckdb`)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "history" -d 'Recurring conflicts across persisted diagnosis runs'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "trends" -d 'Time-series analytics over persisted runs'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "cache" -d 'Jar scan cache maintenance (`stats`, `prune`, `clear`)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "sbom" -d 'SBOM export (SPDX / CycloneDX) from a mods directory'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "demo" -d 'Presentation demo: aggregate a small real-mod run into launcher-facing reports'
complete -c intermed -n "__fish_intermed_using_subcommand help; and not __fish_seen_subcommand_from doctor vfs deps mixin-map spark-map lab rules db history trends cache sbom demo help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from vfs" -f -a "scan" -d 'Scan jar assets/data writers and summarize resource collisions'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from vfs" -f -a "explain" -d 'Explain each resource collision and its merge/override class'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from vfs" -f -a "overlay" -d 'Write a read-only overlay preview directory from detected collisions'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from deps" -f -a "graph" -d 'Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from deps" -f -a "resolve" -d 'Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from lab" -f -a "discover" -d 'Build a reproducible corpus lock from a candidate pool'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from lab" -f -a "run" -d 'Classify captured smoke-test outputs against a corpus lock'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from lab" -f -a "report" -d 'Render a compatibility matrix (JSON + HTML) from a lab run'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from lab" -f -a "eval" -d 'Score Doctor predictions against lab ground truth (precision/recall)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "check" -d 'Validate rule-pack JSON/YAML files under a path'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "generate" -d 'Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "sign" -d 'Sign a v2 rule pack with an Ed25519 key'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "verify" -d 'Verify a signed rule pack (optional trusted-keys file)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "update" -d 'Refresh an installed pack from the registry (embedded core by default)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "registry" -d 'List packs in a registry index (embedded default if omitted)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "install" -d 'Install a pack and its registry dependencies into XDG rule-packs'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from db" -f -a "query" -d 'Run a read-only SQL query against the analytics store'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from history" -f -a "conflicts" -d 'Findings that recur across multiple runs within a time window'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from history" -f -a "patterns" -d 'Recurring *kinds* of risk (rule + category) rolled up across all history'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from history" -f -a "diff" -d 'Compare findings between two persisted runs'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from history" -f -a "prune" -d 'Delete analytics runs older than a retention window'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from trends" -f -a "mixin-risk" -d 'Mixin-category finding counts per persisted run'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from trends" -f -a "mixin-overlaps" -d 'Top-N most frequent mixin overlaps (by mod set + target)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from cache" -f -a "stats" -d 'Show hit/miss counters and on-disk cache size'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from cache" -f -a "prune" -d 'Force a prune pass (age + size limits)'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from cache" -f -a "clear" -d 'Delete all cached jar payloads and fingerprints'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from sbom" -f -a "export" -d 'Export SPDX or CycloneDX SBOM from jar metadata'
complete -c intermed -n "__fish_intermed_using_subcommand help; and __fish_seen_subcommand_from demo" -f -a "report" -d 'Render markdown, HTML, and JSON presentation artifacts from a demo run directory'
