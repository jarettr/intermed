# Community rule packs

InterMed ships a signed, embedded core declarative pack (`intermed-core`). Community
extensions are **data-only** JSON/YAML rule packs — no Rust plugins, no WASM — merged
at doctor runtime on top of the core.

## Install and update

```bash
# List packs in the default registry (embedded core + community index)
intermed rules registry

# Install or refresh the core pack to XDG data dir
intermed rules update --pack intermed-core

# Install from a custom registry (local file or HTTPS URL)
intermed rules update --pack my-pack --registry https://example.com/registry.json
intermed rules update --pack my-pack --registry ./rules/community-registry.json
```

Installed packs live at `$XDG_DATA_HOME/intermed/rule-packs/*.rules.json` (typically
`~/.local/share/intermed/rule-packs/`).

Registry entries support:

| URL scheme | Use |
|------------|-----|
| `embedded://` | Built-in core pack (offline-safe) |
| `file://` | Local path for development |
| `https://` / `http://` | Remote signed packs (digest + optional Ed25519) |

## Doctor integration

`intermed doctor` automatically merges:

1. Embedded core pack (minus mixin rules when `--mixin-risk` runs Layer F imperative)
2. All installed packs from the XDG install directory
3. Extra `--rule-pack PATH|ID` overlays (later entries override rule ids)

```bash
# Use only the embedded core (ignore installed overlays)
intermed doctor ./mods --core-rule-pack-only

# Add a local or installed pack by path / id
intermed doctor ./mods --rule-pack ./my-pack.rules.json
intermed doctor ./mods --rule-pack my-community-pack

# Verify signed overlays against trusted publisher keys
intermed doctor ./mods --rule-pack-trusted-keys ./trusted-keys.txt
```

Config file (`intermed-config-v1`):

```toml
[rules]
packs = ["my-community-pack"]
registry = "https://example.com/intermed-registry.json"
trusted_keys = "~/.config/intermed/trusted-keys.txt"
core_only = false
```

## Publish a pack

1. Author rules against the open fact vocabulary ([SCHEMA.md](SCHEMA.md)).
2. Validate: `intermed rules check ./my-pack.rules.json`
3. Sign (v2 schema): `intermed rules sign my-pack.rules.json --key publisher.key`
4. Compute digest: `intermed rules verify my-pack.rules.json` (after signing)
5. Add a `RegistryPackEntry` to your registry index with `url`, `sha256`, `publisher`.
6. List publisher Ed25519 public keys under `publishers[].public_keys` in the registry.

Template registry: [`rules/community-registry.json`](../rules/community-registry.json)

## Security model

* Unsigned packs load for local development; production registries should ship Ed25519
  signatures on v2 packs.
* Registry `sha256` pins the canonical signing payload; HTTPS fetch is size-capped.
* Doctor never executes arbitrary code from packs — only interprets validated JSON rules.