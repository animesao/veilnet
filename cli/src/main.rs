mod ipc_client;
mod strategies;
mod zapret_import;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipc_client::Client;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "veilctl",
    version,
    about = "veilnet control CLI - manage the veilnet DPI bypass daemon",
    after_help = "veilnet: TC + eBPF based DPI bypass for Linux"
)]
struct Cli {
    /// Path to the daemon unix socket
    #[arg(long, default_value = "/run/veilnet/veilnet.sock")]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status (interface, attached, rules count)
    Status,
    /// Reload config and re-sync rules to BPF maps
    Reload,
    /// Attach veilnet to an interface
    Attach {
        /// Interface name (e.g. eth0, or 'auto' to auto-detect)
        iface: String,
    },
    /// Detach veilnet from an interface
    Detach {
        /// Interface name
        iface: String,
    },
    /// Show loaded BPF maps, programs and stats
    Info,
    /// List available built-in strategies
    Strategies,
    /// Show details of one strategy
    Strategy {
        /// Strategy id, e.g. 'multisplit'
        id: String,
    },
    /// Generate a config rule for a strategy
    Gen {
        /// Strategy id
        id: String,
        /// CIDRs to match, comma separated
        #[arg(short, long, default_value = "0.0.0.0/0")]
        cidr: String,
    },
    /// Import strategies from a zapret-discord-youtube .bat file
    Import {
        /// Path to the .bat file or a directory with .bat files
        path: PathBuf,
        /// Output directory for imported configs
        #[arg(short, long, default_value = "/etc/veilnet/imported")]
        out: PathBuf,
    },
    /// Show resolved interface
    Iface,
    /// Show packet counters from the daemon
    Stats,
    /// Ping the daemon
    Ping,
    /// Show version
    Version,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("veilctl: error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new(&cli.socket);

    match cli.command {
        Commands::Status => {
            let resp = client.request("status")?;
            println!("{resp}");
        }

        Commands::Reload => {
            let resp = client.request("reload")?;
            println!("{resp}");
        }

        Commands::Attach { iface } => {
            let resp = client.request(&format!("attach {iface}"))?;
            println!("{resp}");
        }

        Commands::Detach { iface } => {
            let resp = client.request(&format!("detach {iface}"))?;
            println!("{resp}");
        }

        Commands::Info => {
            let resp = client.request("info")?;
            println!("{resp}");
        }

        Commands::Strategies => {
            println!("Built-in strategies:\n");
            for s in strategies::STRATEGIES {
                println!("  {:<22} {}", s.id, s.name);
                println!("  {:<22} {}", "", s.description);
                println!();
            }
        }

        Commands::Strategy { id } => {
            let s = strategies::find(&id)
                .with_context(|| format!("Unknown strategy '{id}', see 'veilctl strategies'"))?;
            println!("id:         {}", s.id);
            println!("name:       {}", s.name);
            println!("description: {}", s.description);
            println!("modes:      {}", s.modes.join(","));
            println!("split_pos:  {}", s.split_pos);
            println!("seqovl:     {}", s.seqovl);
            println!("repeats:    {}", s.repeats);
            println!("tcp_fooling: {}", s.tcp_fooling);
            println!("udp:        {}", s.udp);
        }

        Commands::Gen { id, cidr } => {
            let s = strategies::find(&id)
                .with_context(|| format!("Unknown strategy '{id}', see 'veilctl strategies'"))?;
            print!("{}", s.to_toml_rule(&cidr));
        }

        Commands::Import { path, out } => {
            import_command(path, out)?;
        }

        Commands::Iface => {
            let resp = client.request("iface")?;
            println!("{resp}");
        }

        Commands::Stats => {
            let resp = client.request("stats")?;
            println!("{resp}");
        }

        Commands::Ping => {
            if client.ping() {
                println!("veilnetd is reachable");
            } else {
                println!("veilnetd is NOT reachable");
                std::process::exit(1);
            }
        }

        Commands::Version => {
            println!("veilctl {}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn import_command(path: PathBuf, out: PathBuf) -> Result<()> {
    let mut bat_files = Vec::new();

    if path.is_file() {
        bat_files.push(path.clone());
    } else if path.is_dir() {
        let mut found: Vec<_> = std::fs::read_dir(&path)
            .with_context(|| format!("Failed to read dir {}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                let is_bat = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("bat"))
                    .unwrap_or(false);
                let not_service = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| !n.eq_ignore_ascii_case("service.bat"))
                    .unwrap_or(false);
                is_bat && not_service
            })
            .collect();
        found.sort();
        bat_files = found;
    } else {
        anyhow::bail!("Path not found: {}", path.display());
    }

    if bat_files.is_empty() {
        anyhow::bail!("No .bat strategy files found in {}", path.display());
    }

    std::fs::create_dir_all(&out)
        .with_context(|| format!("Failed to create {}", out.display()))?;

    println!("Importing {} strategy files to {}...\n", bat_files.len(), out.display());

    let mut ok = 0;
    for f in &bat_files {
        match zapret_import::parse_bat(f) {
            Ok(s) => {
                let out_path = out.join(format!("{}.toml", slug(&s.name)));
                let content = format!(
                    "# veilnet imported strategy\n# source: {}\n\n{}\n",
                    f.display(),
                    s.to_toml()
                );
                std::fs::write(&out_path, content)
                    .with_context(|| format!("Failed to write {}", out_path.display()))?;
                println!(
                    "  {} -> {} ({} filter blocks)",
                    f.file_name().unwrap_or_default().to_string_lossy(),
                    out_path.display(),
                    s.blocks.len()
                );
                ok += 1;
            }
            Err(e) => {
                eprintln!(
                    "  SKIP {}: {}",
                    f.file_name().unwrap_or_default().to_string_lossy(),
                    e
                );
            }
        }
    }

    println!("\nImported {ok}/{} strategies.", bat_files.len());
    println!("Imported configs are reference translations; review before enabling.");
    Ok(())
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
