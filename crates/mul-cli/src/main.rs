// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mac_unified_library::{AnalyserId, Filter, Input, ModuleRegistry, Session};
use mul_export::{
    write_events_csv, write_events_ndjson, write_overview_html, write_overview_json,
    write_overview_markdown, write_timesketch_csv, write_timesketch_jsonl,
};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "mul", version, about = "mac-unified-library CLI")]
struct Cli {
    #[arg(long, default_value_t = 0, global = true)]
    threads: usize,
    #[arg(long, global = true)]
    mem_budget: Option<usize>,
    #[arg(long, global = true)]
    stats: bool,
    #[arg(long, global = true)]
    ioc: Vec<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Info {
        inputs: Vec<PathBuf>,
    },
    Logs {
        inputs: Vec<PathBuf>,
        #[arg(long)]
        predicate: Option<String>,
        #[arg(long, default_value = "ndjson")]
        format: String,
        #[arg(long)]
        unordered: bool,
        #[arg(long)]
        signposts: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    Overview {
        inputs: Vec<PathBuf>,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    Analyse {
        inputs: Vec<PathBuf>,
        #[arg(long)]
        analyser: Vec<String>,
        /// Optional TOML file for install_enrichment rules (see `rules/install_enrichment.toml`).
        #[arg(long)]
        install_rules: Option<PathBuf>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Run one or more `-ng` parsers (tight retention; no log/biome ingest).
    Parse {
        inputs: Vec<PathBuf>,
        #[arg(long)]
        parser: Vec<String>,
        /// Run every parser (same as omitting `--parser` with an empty list + `--all`).
        #[arg(long)]
        all: bool,
        /// Decode unified-log events for the `logarchive` parser (slower, larger output).
        #[arg(long)]
        decode_logarchive: bool,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    ListParsers,
    Timeline {
        inputs: Vec<PathBuf>,
        #[arg(long, default_value = "timesketch-jsonl")]
        format: String,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    Biome {
        inputs: Vec<PathBuf>,
        #[command(subcommand)]
        sub: BiomeCmd,
    },
    Modules {
        #[command(subcommand)]
        sub: ModulesCmd,
    },
    Apollo {
        inputs: Vec<PathBuf>,
        #[arg(long)]
        module: Vec<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum BiomeCmd {
    List,
    Dump {
        #[arg(long)]
        stream: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
enum ModulesCmd {
    List,
    Show { id: String },
    Validate { path: Option<PathBuf> },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let threads = cli.threads;
    let mem_budget = cli.mem_budget;
    let ioc = cli.ioc.clone();
    let show_stats = cli.stats;
    match cli.cmd {
        Cmd::Info { inputs } => {
            let mut session = build_session(&inputs, threads, mem_budget, &ioc)?;
            let info = session.info()?;
            println!("{}", serde_json::to_string_pretty(&info)?);
            if show_stats {
                eprintln!("{:?}", session.stats());
            }
        }
        Cmd::Logs {
            inputs,
            predicate,
            format,
            unordered,
            signposts,
            limit,
            output,
        } => {
            let _session = build_session(&inputs, threads, mem_budget, &ioc)?;
            let src_path = inputs
                .first()
                .map(|p| {
                    let nested = p.join("system_logs.logarchive");
                    if nested.exists() {
                        nested
                    } else {
                        p.clone()
                    }
                })
                .context("input required")?;
            let src = mul_unifiedlog::DirLogSource::open(&src_path)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let log = mul_unifiedlog::UnifiedLog::open(
                src,
                mul_unifiedlog::Options {
                    threads,
                    ordered: !unordered,
                    include_signposts: signposts,
                },
            )?;
            let filter = match predicate {
                Some(p) => Filter::parse_predicate(&p)?,
                None => Filter::True,
            };
            let mut out: Box<dyn Write> = if let Some(p) = output {
                Box::new(File::create(p)?)
            } else {
                Box::new(io::stdout())
            };
            let mut written = 0usize;
            let max = limit.unwrap_or(usize::MAX);
            log.query(&filter).for_each_batch(|batch| {
                for e in batch {
                    if written >= max {
                        return Ok(());
                    }
                    match format.as_str() {
                        "ndjson" => {
                            serde_json::to_writer(&mut out, e)
                                .map_err(|e| mac_unified_library::MulError::msg(e.to_string()))?;
                            writeln!(out)
                                .map_err(|e| mac_unified_library::MulError::msg(e.to_string()))?;
                        }
                        "text" => {
                            writeln!(
                                out,
                                "{} {} {} {}:{} {}",
                                e.timestamp.as_deref().unwrap_or("-"),
                                e.message_type.as_deref().unwrap_or("?"),
                                e.process_id.unwrap_or(0),
                                e.subsystem.as_deref().unwrap_or(""),
                                e.category.as_deref().unwrap_or(""),
                                e.event_message.as_deref().unwrap_or(""),
                            )
                            .map_err(|err| mac_unified_library::MulError::msg(err.to_string()))?;
                        }
                        "csv" => {
                            if written == 0 {
                                writeln!(out, "timestamp,pid,subsystem,category,message").map_err(
                                    |e| mac_unified_library::MulError::msg(e.to_string()),
                                )?;
                            }
                            writeln!(
                                out,
                                "{},{},{},{},\"{}\"",
                                e.timestamp.as_deref().unwrap_or(""),
                                e.process_id.unwrap_or(0),
                                e.subsystem.as_deref().unwrap_or(""),
                                e.category.as_deref().unwrap_or(""),
                                e.event_message
                                    .as_deref()
                                    .unwrap_or("")
                                    .replace('"', "\"\""),
                            )
                            .map_err(|err| mac_unified_library::MulError::msg(err.to_string()))?;
                        }
                        other => {
                            return Err(mac_unified_library::MulError::msg(format!(
                                "unsupported format: {other}"
                            )));
                        }
                    }
                    written += 1;
                }
                Ok(())
            })?;
            if show_stats {
                eprintln!(
                    "wrote {written} events; units={} files={}",
                    log.stats().unit_count,
                    log.stats().files
                );
            }
        }
        Cmd::Overview {
            inputs,
            format,
            output,
        } => {
            let mut session = build_session(&inputs, threads, mem_budget, &ioc)?;
            let _ = session.info()?;
            let ov = session.overview()?;
            let mut out: Box<dyn Write> = if let Some(p) = output {
                Box::new(File::create(p)?)
            } else {
                Box::new(io::stdout())
            };
            match format.as_str() {
                "json" => write_overview_json(&mut out, &ov)?,
                "md" | "markdown" => write_overview_markdown(&mut out, &ov)?,
                "html" => write_overview_html(&mut out, &ov)?,
                other => bail!("unsupported format: {other}"),
            }
            if show_stats {
                eprintln!("{:?}", session.stats());
            }
        }
        Cmd::Analyse {
            inputs,
            analyser,
            install_rules,
            output,
        } => {
            let mut session = build_session(&inputs, threads, mem_budget, &ioc)?;
            if let Some(path) = install_rules {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("read install rules {}", path.display()))?;
                session.set_install_enrichment_rules_toml(Some(text));
            }
            let _ = session.info()?;
            let ids: Vec<AnalyserId> = if analyser.is_empty() {
                AnalyserId::compat_ids().to_vec()
            } else {
                analyser
                    .iter()
                    .filter_map(|s| parse_analyser(s))
                    .collect()
            };
            let map = session.analyse(&ids)?;
            let text = serde_json::to_string_pretty(&map)?;
            if let Some(p) = output {
                std::fs::write(p, text)?;
            } else {
                println!("{text}");
            }
        }
        Cmd::Parse {
            inputs,
            parser,
            all,
            decode_logarchive,
            output,
        } => {
            let mut session = build_session(&inputs, threads, mem_budget, &ioc)?;
            if !all && parser.is_empty() {
                bail!("pass --parser NAME (repeatable) or --all");
            }
            // Empty names ⇒ all parsers (see Session::parse_parsers).
            let names: Vec<String> = if all { Vec::new() } else { parser };
            let report = session.parse_parsers(&names, decode_logarchive)?;
            let parser_count = report.values.len();
            let error_count = report.errors.len();
            let wall_ms = report.wall_ms;
            let timings_ms = report.timings_ms;
            let mut envelope = serde_json::Map::new();
            // Move parser JSON into the envelope (no extra ~70MB clone of powerlogs).
            for (k, v) in report.values {
                let ms = timings_ms.get(&k).copied().unwrap_or(0.0);
                let mut entry = serde_json::Map::new();
                entry.insert("ok".into(), serde_json::Value::Bool(true));
                entry.insert("duration_ms".into(), serde_json::json!(ms));
                entry.insert("data".into(), v);
                envelope.insert(k, serde_json::Value::Object(entry));
            }
            for (k, e) in report.errors {
                let ms = timings_ms.get(&k).copied().unwrap_or(0.0);
                envelope.insert(
                    k,
                    serde_json::json!({
                        "ok": false,
                        "duration_ms": ms,
                        "error": e,
                    }),
                );
            }
            envelope.insert(
                "_meta".into(),
                serde_json::json!({
                    "wall_ms": wall_ms,
                    "parser_count": parser_count,
                    "error_count": error_count,
                }),
            );
            let root = serde_json::Value::Object(envelope);
            // Stream to disk/stdout — avoid holding a second pretty-printed String in RSS.
            // BufWriter is mandatory: bare File makes serde issue one write(2) per token
            // (~18s sys on a ~90MB pretty powerlogs envelope).
            if let Some(p) = output {
                let f = File::create(&p)
                    .with_context(|| format!("create {}", p.display()))?;
                let mut w = BufWriter::with_capacity(1 << 20, f);
                serde_json::to_writer_pretty(&mut w, &root)?;
                w.flush()?;
            } else {
                let mut w = BufWriter::with_capacity(1 << 20, io::stdout().lock());
                serde_json::to_writer_pretty(&mut w, &root)?;
                w.flush()?;
                println!();
            }
            if show_stats {
                eprintln!(
                    "wall_ms={:.1} parsers={} errors={}",
                    wall_ms, parser_count, error_count
                );
                let mut timings: Vec<_> = timings_ms.iter().collect();
                timings.sort_by(|a, b| {
                    b.1.partial_cmp(a.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                for (name, ms) in timings.into_iter().take(20) {
                    eprintln!("  {name}: {ms:.2} ms");
                }
            }
            if error_count > 0 {
                bail!("{error_count} parser(s) failed");
            }
        }
        Cmd::ListParsers => {
            for name in mac_unified_library::Session::list_parsers() {
                println!("{name}");
            }
        }
        Cmd::Timeline {
            inputs,
            format,
            output,
        } => {
            let mut session = build_session(&inputs, threads, mem_budget, &ioc)?;
            let _ = session.info()?;
            let events = session.timeline_events()?.to_vec();
            let mut out: Box<dyn Write> = if let Some(p) = output {
                Box::new(File::create(p)?)
            } else {
                Box::new(io::stdout())
            };
            match format.as_str() {
                "timesketch-jsonl" => write_timesketch_jsonl(&mut out, &events)?,
                "timesketch-csv" => write_timesketch_csv(&mut out, &events)?,
                "ndjson" => write_events_ndjson(&mut out, &events)?,
                "csv" => write_events_csv(&mut out, &events)?,
                other => bail!("unsupported format: {other}"),
            }
        }
        Cmd::Biome { inputs, sub } => {
            let session = build_session(&inputs, threads, mem_budget, &ioc)?;
            match sub {
                BiomeCmd::List => {
                    for p in session.list_biome() {
                        println!("{}", p.display());
                    }
                }
                BiomeCmd::Dump { stream, limit } => {
                    let paths = session.list_biome();
                    let filtered: Vec<_> = paths
                        .into_iter()
                        .filter(|p| {
                            stream
                                .as_ref()
                                .map(|s| p.to_string_lossy().contains(s))
                                .unwrap_or(true)
                        })
                        .take(limit)
                        .collect();
                    for p in filtered {
                        match std::fs::read(&p) {
                            Ok(bytes) => match mul_apollo::segb::parse(&bytes) {
                                Ok(f) => {
                                    println!(
                                        "{} version={:?} entries={}",
                                        p.display(),
                                        f.version,
                                        f.entries.len()
                                    );
                                }
                                Err(e) => eprintln!("{}: parse error {e}", p.display()),
                            },
                            Err(e) => eprintln!("{}: {e}", p.display()),
                        }
                    }
                }
            }
        }
        Cmd::Modules { sub } => match sub {
            ModulesCmd::List => {
                let reg = ModuleRegistry::global();
                for m in reg.modules() {
                    println!("{}\t{}", m.id, m.activity);
                }
                eprintln!(
                    "# {} modules ({} legacy sources)",
                    reg.module_count(),
                    ModuleRegistry::legacy_source_count()
                );
            }
            ModulesCmd::Show { id } => {
                let reg = ModuleRegistry::global();
                let m = reg
                    .get(&id)
                    .with_context(|| format!("module not found: {id}"))?;
                println!("{}", serde_json::to_string_pretty(m)?);
            }
            ModulesCmd::Validate { path } => {
                if let Some(p) = path {
                    let text = std::fs::read_to_string(&p)?;
                    let m = mul_apollo::parse_module_toml(&text)?;
                    println!("ok: {} ({} variants)", m.id, m.variants.len());
                } else {
                    let reg = ModuleRegistry::global();
                    if reg.legacy_errors().is_empty() {
                        println!("ok: {} modules", reg.module_count());
                    } else {
                        for (n, e) in reg.legacy_errors() {
                            eprintln!("{n}: {e}");
                        }
                        bail!("legacy import errors");
                    }
                }
            }
        },
        Cmd::Apollo {
            inputs: _,
            module,
            db,
        } => {
            let session = Session::builder()
                .input(Input::detect(".").unwrap())
                .threads(threads)
                .build()?;
            let db = db.context("--db PATH required for apollo run")?;
            for id in module {
                let (status, rows) = session.apollo_run_module_on_path(&id, &db)?;
                println!("{id}: {status:?} rows={}", rows.len());
            }
        }
    }
    Ok(())
}

fn build_session(
    inputs: &[PathBuf],
    threads: usize,
    mem_budget: Option<usize>,
    ioc: &[PathBuf],
) -> Result<Session> {
    if inputs.is_empty() {
        bail!("at least one input required");
    }
    let mut b = Session::builder().threads(threads);
    if let Some(m) = mem_budget {
        b = b.mem_budget(m);
    }
    for i in ioc {
        b = b.ioc_file(i.display().to_string());
    }
    for p in inputs {
        b = b.input(Input::detect(p)?);
    }
    Ok(b.build()?)
}

fn parse_analyser(s: &str) -> Option<AnalyserId> {
    AnalyserId::parse(s)
}
