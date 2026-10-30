// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mul_apollo::{parse_legacy_module, parse_module_toml, ModuleRegistry};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate embedded modules + optional TOML path.
    Modules {
        #[command(subcommand)]
        sub: ModulesCmd,
    },
    /// Convert a legacy .txt module to a draft v2 TOML.
    Convert {
        path: PathBuf,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Convert every vendor/apollo/*.txt into modules/apollo/*.toml
    ConvertAll {
        #[arg(long, default_value = "vendor/apollo")]
        from: PathBuf,
        #[arg(long, default_value = "modules/apollo")]
        out_dir: PathBuf,
    },
    /// Benchmark upstream sdx-cli parsers/analysers (wraps scripts/bench_sysdiagnose.py).
    BenchSdx {
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        compare_mul: bool,
        #[arg(long)]
        parsers_only: bool,
        #[arg(long)]
        analysers_only: bool,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 1)]
        repeats: u32,
    },
}

#[derive(Subcommand)]
enum ModulesCmd {
    Validate,
    Count,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Modules { sub } => match sub {
            ModulesCmd::Validate => {
                let reg = ModuleRegistry::load_embedded();
                if !reg.legacy_errors().is_empty() {
                    for (n, e) in reg.legacy_errors() {
                        eprintln!("{n}: {e}");
                    }
                    bail!("{} import errors", reg.legacy_errors().len());
                }
                println!(
                    "ok: {} modules ({} legacy sources, {} toml sources)",
                    reg.module_count(),
                    ModuleRegistry::legacy_source_count(),
                    ModuleRegistry::toml_source_count(),
                );
            }
            ModulesCmd::Count => {
                println!(
                    "legacy={} toml={}",
                    ModuleRegistry::legacy_source_count(),
                    ModuleRegistry::toml_source_count()
                );
            }
        },
        Cmd::Convert { path, output } => {
            let draft = convert_one(&path)?;
            if let Some(out) = output {
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out, &draft)?;
                // Round-trip check
                parse_module_toml(&draft).with_context(|| format!("round-trip {}", out.display()))?;
                println!("wrote {}", out.display());
            } else {
                print!("{draft}");
            }
        }
        Cmd::ConvertAll { from, out_dir } => {
            let from = abs_from_workspace(&from);
            let out_dir = abs_from_workspace(&out_dir);
            std::fs::create_dir_all(&out_dir)?;
            let mut names: Vec<_> = std::fs::read_dir(&from)
                .with_context(|| format!("read {}", from.display()))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("txt"))
                .collect();
            names.sort();
            let mut ok = 0usize;
            let mut err = 0usize;
            for path in &names {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("module");
                let dest = out_dir.join(format!("{stem}.toml"));
                match convert_one(path) {
                    Ok(draft) => {
                        if let Err(e) = parse_module_toml(&draft) {
                            eprintln!("FAIL round-trip {}: {e}", path.display());
                            err += 1;
                            continue;
                        }
                        std::fs::write(&dest, draft)
                            .with_context(|| format!("write {}", dest.display()))?;
                        ok += 1;
                    }
                    Err(e) => {
                        eprintln!("FAIL {}: {e:#}", path.display());
                        err += 1;
                    }
                }
            }
            println!(
                "converted {ok}/{} → {} (errors={err})",
                names.len(),
                out_dir.display()
            );
            if err > 0 {
                bail!("{err} conversion errors");
            }
        }
        Cmd::BenchSdx {
            input,
            out,
            compare_mul,
            parsers_only,
            analysers_only,
            filter,
            repeats,
        } => {
            let script = workspace_root().join("scripts/bench_sysdiagnose.py");
            if !script.exists() {
                bail!("missing {}", script.display());
            }
            let mut cmd = std::process::Command::new("python3");
            cmd.arg(&script)
                .arg("-i")
                .arg(&input)
                .arg("--repeats")
                .arg(repeats.to_string());
            if let Some(o) = out {
                cmd.arg("--out").arg(o);
            }
            if compare_mul {
                cmd.arg("--compare-mul");
            }
            if parsers_only {
                cmd.arg("--parsers-only");
            }
            if analysers_only {
                cmd.arg("--analysers-only");
            }
            if let Some(f) = filter {
                cmd.arg("--filter").arg(f);
            }
            let status = cmd.status()?;
            if !status.success() {
                bail!("bench_sysdiagnose.py exited {}", status);
            }
        }
    }
    Ok(())
}

fn convert_one(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("module.txt");
    let m = parse_legacy_module(name, &text)?;
    Ok(mul_apollo::module_to_toml(&m))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate parent")
        .to_path_buf()
}

fn abs_from_workspace(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        workspace_root().join(p)
    }
}
