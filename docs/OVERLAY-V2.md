# Overlay plan v2 (semantic)

Layer E's `intermed vfs overlay` still writes a **byte-level preview** into
`--out` (safe tag/lang unions plus optional lexical-winner previews). Overlay
**plan v2** is a separate, read-only semantic classifier: it buckets every
collision into `safe` / `review` / `unsafe` using Layer-M evidence, without
staging files.

Schema: `intermed-overlay-plan-v2`.

## Commands

```bash
# v1 preview — writes only deterministic merges by default
intermed vfs overlay ./mods --out ./overlay

# opt into order-dependent winner previews (lexical pick, not guaranteed runtime order)
intermed vfs overlay ./mods --out ./overlay --include-unsafe-winners

# v2 plan — JSON to stdout, writes nothing
intermed vfs overlay ./mods --explain-plan
```

`--explain-plan` runs a full Layer-M scan internally (recipe/lang diff detection)
and prints the plan. It does not require `--out`.

## Plan shape

```json
{
  "schema": "intermed-overlay-plan-v2",
  "source_mods_dir": "./mods",
  "safe_items": [],
  "review_items": [],
  "unsafe_items": [],
  "writer_order_policy": "lexical-preview",
  "runtime_order_known": false
}
```

| Field | Meaning |
|-------|---------|
| `safe_items` | Deterministic, order-independent merges — safe to apply as-is |
| `review_items` | Human must choose; includes Layer-M semantic escalations |
| `unsafe_items` | Order-dependent winner picks; runtime load order decides |
| `writer_order_policy` | Always `lexical-preview` today (static winner ordering) |
| `runtime_order_known` | Always `false` — InterMed does not know mod load order |

Each item carries `path`, `class` (Layer-E `ConflictClass`), `writers`, and a
`reason` string.

## Bucketing rules

| Bucket | Examples |
|--------|----------|
| **Safe** | Tag union without `replace: true`; disjoint lang keys; identical content skipped |
| **Review** | `replace: true` tags; lang format mismatch; `json_merge_candidate`; **recipe output override** or **lang key conflict** (Layer M proved meaning differs) |
| **Unsafe** | Single-document JSON overrides with no semantic diff signal — lexical winner only |

The critical v2 upgrade over v1 is **semantic escalation**: when Layer M emits a
`resource_semantic_diff` for a path (recipe outputs differ, or locale keys bind to
different text), that collision is forced into `review_items` even if Layer E only
saw a generic `json_override_conflict`.

## Relationship to v1 overlay writes

| Surface | Mutates disk | Uses Layer M |
|---------|--------------|--------------|
| `vfs overlay --out` | Yes (preview dir) | No |
| `vfs overlay --explain-plan` | No | Yes |

Default overlay behaviour remains conservative: only deterministic merges are
written unless `--include-unsafe-winners` is set. The plan is for **deciding**
what to merge before you opt into unsafe previews.

## See also

- Layer E byte collisions: [LAYER-E-DYNAMICS.md](LAYER-E-DYNAMICS.md)
- Layer M semantics: [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md)
- PackOps implementation: [`intermed-packops`](../crates/intermed-packops/src/lib.rs)