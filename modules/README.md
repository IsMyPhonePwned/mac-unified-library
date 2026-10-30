# APOLLO-NG modules (TOML v2)

- `modules/*.toml` — hand-authored native modules
- `modules/apollo/*.toml` — all 247 legacy APOLLO modules converted from `vendor/apollo/*.txt`

At embed time, `mul-apollo` loads every `modules/**/*.toml` (TOML wins by `id`). Vendored `.txt` files stay under `vendor/apollo/` for license provenance and as a fallback importer if a TOML is missing.

```bash
# Re-convert from legacy (overwrite modules/apollo/)
cargo run -p xtask -- convert-all

# Single file
cargo run -p xtask -- convert vendor/apollo/tcc_db.txt -o modules/apollo/tcc_db.toml

# Validate embedded set
cargo run -p xtask -- modules validate
```
