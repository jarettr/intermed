#!/usr/bin/env bash
# InterMed — CPU flame graph of a `doctor` run via cargo-flamegraph.
#
# Requirements (the sampler is `perf`, which needs kernel access):
#   * cargo install flamegraph
#   * Linux `perf` installed (e.g. `dnf install perf` / `apt install linux-perf`)
#   * perf_event access: `sudo sysctl kernel.perf_event_paranoid=1`
#     (and `kernel.kptr_restrict=0` for kernel symbols)
#
# Usage:  scripts/flamegraph.sh [TARGET_DIR] [extra doctor args...]
#   TARGET_DIR defaults to ~/intermed_corpus/fabric_mega
#
# Output: flamegraph.svg in the repo root. The cache is warmed first so the graph
# reflects the steady-state analysis cost (the per-jar scan is cached), where the
# hot paths live (mixin-analyzer / resource-ast / vfs).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-$HOME/intermed_corpus/fabric_mega}"
shift || true

if ! command -v cargo-flamegraph >/dev/null 2>&1; then
  echo "error: cargo-flamegraph not installed — run: cargo install flamegraph" >&2
  exit 1
fi
if ! command -v perf >/dev/null 2>&1; then
  echo "error: 'perf' not found. Install it and set kernel.perf_event_paranoid<=1." >&2
  exit 1
fi

# Debug info in release so frames symbolicate. (Does not change codegen.)
export CARGO_PROFILE_RELEASE_DEBUG=1

# Warm the jar caches first so the flame graph is the steady-state analysis, not
# one-time bytecode parsing.
cargo run --release --quiet --bin intermed -- doctor "$TARGET" --mixin-risk --performance --json >/dev/null 2>&1 || true

echo "Sampling doctor on: $TARGET"
cargo flamegraph --release --bin intermed -- doctor "$TARGET" --mixin-risk --performance "$@" --json >/dev/null

echo "Wrote $ROOT/flamegraph.svg"
