# Stone — handoff

Stone is a personal, local-first Markdown notes app: it opens existing Obsidian
vaults, syncs them end-to-end encrypted, and exposes every vault operation
through a headless CLI. All logic lives in one Rust core library; desktop and
mobile clients are thin shells over it (not built here — see "Not built").

## Naming decisions

The spec had an unfinished product rename in places. Everything is `stone`:

- binary: `stone` (CLI), `stone-server` (sync server)
- crates: `stone-core`, `stone-cli`, `stone-server`, `stone-sim`
- in-vault settings folder: `.stone/` (`vault.toml`, `sync.toml`, `trash/`, `cache/`)

## Workspace layout

```
crates/stone-core    everything: parser, index, engine, links, merge, crypto,
                     sync agent, journal, registry, daemon RPC, templates
crates/stone-cli     `stone` binary — thin: parses args → registry → print
crates/stone-server  `stone-server` — axum, blob CAS + change feed + auth
crates/stone-sim     deterministic multi-device simulation harness
```

## The model (inferred; spec's Contracts tab was not in the attachment)

- **Vault key**: random 256-bit key per vault. Content + metadata are encrypted
  client-side (XChaCha20-Poly1305); the server stores ciphertext only.
- **ids**: `path_id = keyed-BLAKE3(normalized-path)`, `blob_id = keyed-BLAKE3(content)`,
  `vault_id = keyed-BLAKE3(marker)` — all derived from the vault key, so the
  server can't reverse names/contents.
- **Key wrap**: Argon2id(password) wraps the vault key; the wrapped blob +
  salt live server-side so a second device can unwrap with the password. A
  second wrap under a recovery key is shown once at `sync setup`.
- **Devices**: `sync invite` mints a `stn_dev_*` token (only the hash is stored).
  `sync join` presents the token, downloads the wrapped key, unwraps with the
  password. Server assigns `dev-<uuid>` device ids; commits must carry the id
  matching the token.
- **Server CAS**: per `(vault_id, path_id)` head. `base_version` must equal the
  live head (`None` ⇔ no head or deleted head). A commit is atomic — every
  change lands or none does; on mismatch the server returns 409 `{stale:[…]}`.
- **Journal** (`.stone/cache/journal.db`): per-path `paths` table
  (path, path_id, version_id, seq, hash, base, deleted) + `pending` table
  (path, kind∈{Upsert,Delete,Rename}, old_path). `journal.rename(old,new)`
  migrates the row so the CAS base for the old path is derivable.

## Wire protocol (`stone-server`)

```
POST /v1/vaults                      create vault {vault_id, device_name,
                                     device_token_hash, wrapped_key_b64,
                                     argon2_salt_b64, recovery_wrapped_b64,
                                     recovery_salt_b64} → {device_id}
POST /v1/vaults/{v}/devices          {device_name, device_token_hash} (bearer)
                                     → {device_id}
GET  /v1/vaults/{v}/keys             (bearer) → wrapped key material + device_id
PUT  /v1/vaults/{v}/blobs/{id}       encrypted blob upload (id = keyed hash)
GET  /v1/vaults/{v}/blobs/{id}       download
GET  /v1/vaults/{v}/manifest         {seq, files:[{path_id, head_version, deleted}]}
GET  /v1/vaults/{v}/changes?since=N  {latest_seq, changes:[…]} — global seq order
POST /v1/vaults/{v}/commits          → 409 {stale:[{path_id, head}]} on CAS miss
GET  /v1/vaults/{v}/history/{path}   per-path version list
GET  /v1/vaults/{v}/versions/{vid}   one version's data
GET  /v1/ws?vault={v}&seq={n}        websocket liveness feed (wakeups)
GET  /health
```

## Sync agent semantics (`stone-core::sync`)

- `sync_now`: pull changes since `journal.last_seq`, apply **in strict global
  seq order**, then collect local changes (pending + dirty scanner fallback),
  commit. On 409 the journal's head view may be stale for reasons the local
  feed can't show (head moved by a change we merged away) — so a rejected batch
  is repaired against `/manifest` and retried once directly.
- `last_seq` never advances to our own commit seq: foreign commits interleave
  inside our commit's seq range on the server. Our own changes echo back on the
  next pull and re-apply as idempotent no-ops.
- Renames push `Put(new, base=None, old_path=old)` + `Delete(old, base=head[old])`.
  A remote edit to a renamed-away path whose delete hasn't landed merges into
  the new file and records a tracking row at the old path (supplies the CAS
  base for the delete) — the old file is not resurrected locally.
- Local dirty file beats a remote delete (kept + re-pushed with base=None);
  remote delete of an absent file still drops the journal row so a recreated
  file isn't pinned to a dead version.
- Mass-delete guard: a pull whose latest changes delete >10% of vault files or
  >50 files pauses the cycle (force flag bypasses).
- Conflict copies: `Note (conflict <device> <YYYY-MM-DD HHmm>).md`, listed by
  `stone sync conflicts`.
- One sync agent per vault per device: lockfile `.stone/cache/sync.lock`.

## Command registry

`registry::SPECS` — one catalog of ~30 commands; CLI, `stone daemon` RPC, and
`stone mcp` all dispatch through it. `rm`/`trash` are CLI-only (not exposed via
MCP). JSON envelope: `{"ok":true,"data":…}` / `{"ok":false,"error":{"code",…}}`.

## Execution modes (both headless)

1. `stone <cmd>` — one-shot, every command works offline.
2. `stone daemon run` — per-vault daemon (watcher + index + sync loop + TCP
   JSON-lines RPC on 127.0.0.1); CLI auto-uses it when running.
3. `stone mcp` — JSON-RPC over stdio, newline-delimited; safe tool subset.

## Tests

`cargo test --workspace` (all green):

- `stone-core`: engine ops (write/search/mv/props/tasks/trash), JSON envelope,
  proptest merge props (identical-merge, base-unchanged, determinism,
  idempotence) + unit diff3 cases
- `stone-sim/tests/repro`: deterministic micro-scenarios — rename-vs-edit,
  delete-vs-edit, create-create collision
- `stone-sim/tests/sim`: seeded random multi-device sims — 3 devices ×160 ops,
  4 devices ×220 ops incl. offline windows. Verifies: identical path sets,
  identical content multisets (zero lost edits), pending == 0 after converge.
  `STONE_SYNC_TRACE=1` env var traces applies/commits for debugging.
  Sim invariant note: conflict copies make file contents legitimately divergent
  when clean merges are impossible — the multiset check counts content, not
  names, so those still pass.

## Known warts / next steps

- `stone sync join` on a vault you `init`ed first produces a
  `.stone/vault (conflict …).toml` copy — both vaults init their own settings
  file. Cosmetic; resolve by preferring remote settings on join if desired.
- `.stone/` files are synced (settings) but never indexed (filtered in
  `refresh_index`).
- `verify` divergence printout includes per-device journal rows + server
  manifest head + op log tail — kept on purpose; useful for future sim bugs.
- **Not built (spec milestones M5/M6)**: Tauri GUI and mobile. The core is
  deliberately UI-free; GUI = thin client over `registry` + daemon RPC.
- Windows-gnu toolchain note: use system TLS everywhere (reqwest `default-tls`,
  tungstenite `native-tls`) — avoids ring/aws-lc-rs which need an assembler.
- Sim tests must not call reqwest::blocking inside a tokio context — `Sim`
  owns its own runtime for the server; tests are plain `#[test]`.
