# APOLLO-NG modules (TOML v2)

- `modules/*.toml` — hand-authored native modules
- `modules/apollo/*.toml` — converted APOLLO modules (source of truth; embedded at build time)

Optional local `vendor/apollo/*.txt` and `xtask/` (both gitignored) can regenerate TOML when present:

```bash
cargo run --manifest-path xtask/Cargo.toml -- convert-all
```

Validate the embedded set via the library/CLI once built (`mul modules validate`).
