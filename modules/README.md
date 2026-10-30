# APOLLO-NG modules (TOML v2)

- `modules/*.toml` — hand-authored native modules
- `modules/apollo/*.toml` — converted APOLLO modules (source of truth; embedded at build time)

Optional local `vendor/apollo/*.txt` (gitignored) can be used with `xtask convert-all` to regenerate TOML.

```bash
# Re-convert from local vendor (if present)
cargo run -p xtask -- convert-all

# Validate embedded set
cargo run -p xtask -- modules validate
```
