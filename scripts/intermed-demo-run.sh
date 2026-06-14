#!/usr/bin/env bash
# InterMed — презентационный прогон: небольшой набор реальных модов + отчёты.
# Результат: ~/intermed_demo_runs/<timestamp>/ и симлинк LATEST.
# Затем: intermed demo report ~/intermed_demo_runs/LATEST --out <project-root>
set -u
set -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS_MANIFEST="$ROOT/demo/corpus.json"
CORPUS_ROOT="${INTERMED_DEMO_CORPUS:-$HOME/intermed_corpus}"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$HOME/intermed_demo_runs/$STAMP"
LATEST_LINK="$HOME/intermed_demo_runs/LATEST"
REPORT="$OUT/intermed-demo-run.log"

# Presentation scenarios (order matters for the narrative).
SCENARIOS=(fabric_clean broken_deps mixed_loader duplicate forge_pack)

mkdir -p "$OUT"
: >"$REPORT"

log() { echo "$@" | tee -a "$REPORT"; }
section() {
  echo "" | tee -a "$REPORT"
  echo "================================================================" | tee -a "$REPORT"
  echo " $1" | tee -a "$REPORT"
  echo "================================================================" | tee -a "$REPORT"
}

section "InterMed presentation run — $STAMP"
log "Root:     $ROOT"
log "Corpus:   $CORPUS_ROOT"
log "Manifest: $CORPUS_MANIFEST"
log "Output:   $OUT"
log "Started:  $(date -Iseconds 2>/dev/null || date)"

section "0. Build"
cd "$ROOT" || exit 1
if ! cargo build --features duckdb >>"$REPORT" 2>&1; then
  log "[FAIL] cargo build"
  exit 1
fi
log "[OK] cargo build --features duckdb"

IM="$ROOT/target/debug/intermed"
VERSION=$("$IM" --version 2>/dev/null || echo unknown)
log "Binary:   $IM"
log "Version:  $VERSION"

cp -f "$CORPUS_MANIFEST" "$OUT/corpus.json"

section "1. Doctor — presentation scenarios"
for name in "${SCENARIOS[@]}"; do
  dir="$CORPUS_ROOT/$name"
  if [[ ! -d "$dir" ]]; then
    log "[SKIP] $name — missing $dir"
    continue
  fi
  log ""
  log ">>> doctor $name"
  set +e
  "$IM" doctor "$dir" --mixin-risk >"$OUT/doctor-$name.txt" 2>&1
  ec=$?
  set -e
  if [[ $ec -eq 0 || $ec -eq 1 || $ec -eq 2 ]] && [[ -s "$OUT/doctor-$name.txt" ]]; then
    summary=$(grep -E "^(PROBLEMS|WARNINGS)" "$OUT/doctor-$name.txt" | tail -1 || true)
    log "    [OK exit=$ec] $summary"
  else
    log "    [FAIL exit=$ec] doctor $name"
  fi
done

section "2. Hero pack — full export sweep (fabric_clean)"
FC="$CORPUS_ROOT/fabric_clean"
if [[ -d "$FC" ]]; then
  for flag in json sarif; do
    log ">>> doctor fabric_clean --$flag"
    set +e
    "$IM" doctor "$FC" --mixin-risk "--$flag" >"$OUT/doctor-fabric_clean-$flag.json" 2>&1
    ec=$?
    set -e
    log "    [exit=$ec] doctor-fabric_clean-$flag.json"
  done
  log ">>> doctor fabric_clean --html"
  set +e
  "$IM" doctor "$FC" --mixin-risk --html "$OUT/fabric_clean.html" >"$OUT/doctor-fabric_clean.html.log" 2>&1
  ec=$?
  set -e
  log "    [exit=$ec] fabric_clean.html"
  log ">>> doctor fabric_clean --profile"
  set +e
  "$IM" doctor "$FC" --mixin-risk --profile "$OUT/fabric_clean-profile.json" >"$OUT/doctor-fabric_clean-profile.log" 2>&1
  ec=$?
  set -e
  log "    [exit=$ec] fabric_clean-profile.json"
fi

section "3. Subcommand samples"
[[ -d "$FC" ]] && "$IM" deps graph "$FC" >"$OUT/deps-graph-fabric_clean.json" 2>>"$REPORT" && log "[OK] deps graph fabric_clean"
[[ -d "$FC" ]] && "$IM" mixin-map "$FC" >"$OUT/mixin-map-fabric_clean.txt" 2>>"$REPORT" && log "[OK] mixin-map fabric_clean"
[[ -d "$FC" ]] && "$IM" sbom export "$FC" --format spdx-json --out "$OUT/sbom-fabric_clean.json" >>"$REPORT" 2>&1 && log "[OK] sbom fabric_clean"

section "4. Summary"
log ""
log "Scenario              | Status"
log "----------------------|----------------------------------------"
for name in "${SCENARIOS[@]}"; do
  f="$OUT/doctor-$name.txt"
  if [[ ! -f "$f" ]]; then
    log "$(printf '%-22s| SKIP' "$name")"
    continue
  fi
  line=$(grep -E "^(PROBLEMS|WARNINGS)" "$f" | tail -1 || echo "?")
  log "$(printf '%-22s| %s' "$name" "$line")"
done

ln -sfn "$OUT" "$LATEST_LINK"
log ""
log "Finished: $(date -Iseconds 2>/dev/null || date)"
log "Artifacts: $OUT"
log "LATEST → $LATEST_LINK"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Presentation run complete."
echo " Directory: $OUT"
echo " Next: intermed demo report $LATEST_LINK --out $ROOT"
echo "═══════════════════════════════════════════════════════════"