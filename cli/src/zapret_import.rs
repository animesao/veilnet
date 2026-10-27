use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// A single winws filter block parsed from a .bat strategy file.
/// Blocks are separated by `--new` in the original winws invocation.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilterBlock {
    /// Protocol: "tcp" or "udp"
    pub proto: Option<String>,
    /// Ports/ranges, e.g. "80,443,2053-2096"
    pub ports: Option<String>,
    /// Combined desync modes, e.g. "fake,fakedsplit"
    pub desync: Option<String>,
    /// All raw key=value args of this block
    pub args: Vec<(String, String)>,
}

/// A complete strategy parsed from a zapret .bat file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZapretStrategy {
    pub name: String,
    /// Port windows for winws (firewall hooks), tcp part
    pub wf_tcp: Option<String>,
    pub wf_udp: Option<String>,
    pub blocks: Vec<FilterBlock>,
}

fn clean_win_path(v: &str) -> String {
    v.trim_matches('"')
        .replace("%~dp0bin\\", "")
        .replace("%~dp0lists\\", "")
}

/// Parse a zapret .bat file and extract the winws.exe invocation.
pub fn parse_bat(path: &Path) -> Result<ZapretStrategy> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("strategy")
        .to_string();

    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Join continuation lines: lines ending with '^' continue the command
    let mut joined = String::new();
    for line in raw.lines() {
        let l = line.trim_end();
        if let Some(stripped) = l.strip_suffix('^') {
            joined.push_str(stripped.trim_end());
            joined.push(' ');
        } else {
            joined.push_str(l);
            joined.push('\n');
        }
    }

    // Find the winws.exe line
    let cmd_line = joined
        .lines()
        .find(|l| l.contains("winws.exe"))
        .context("No winws.exe invocation found in bat file")?;

    // Cut everything before the winws.exe token, strip leftover closing quote
    let args_part = cmd_line
        .split_once("winws.exe")
        .map(|(_, rest)| rest.trim_start().trim_start_matches('"'))
        .unwrap_or("");

    // Tokenize respecting quotes
    let tokens = tokenize(args_part)?;

    let mut wf_tcp = None;
    let mut wf_udp = None;
    let mut blocks: Vec<FilterBlock> = vec![FilterBlock::default()];
    let mut i = 0;

    while i < tokens.len() {
        let tok = &tokens[i];

        if tok == "--new" {
            blocks.push(FilterBlock::default());
            i += 1;
            continue;
        }

        if let Some(arg_name) = tok.strip_prefix("--") {
            // Value may be inline (--arg=value) or the next token
            let inline = arg_name.split_once('=');
            let (arg_name, inline_val) = match inline {
                Some((n, v)) => (n.to_string(), Some(clean_win_path(v))),
                None => (arg_name.to_string(), None),
            };

            // Next-token value only if no inline value
            let next_val = if inline_val.is_none() {
                tokens
                    .get(i + 1)
                    .filter(|t| !t.starts_with("--") && !t.is_empty())
                    .map(|t| clean_win_path(t))
            } else {
                None
            };

            let had_inline = inline_val.is_some();
            let had_next = next_val.is_some();

            let value = match inline_val {
                Some(v) => v,
                None => next_val.unwrap_or_default(),
            };

            match arg_name.as_str() {
                "wf-tcp" => wf_tcp = Some(value.replace("%GameFilterTCP%", "1024-65535")),
                "wf-udp" => wf_udp = Some(value.replace("%GameFilterUDP%", "1024-65535")),
                "filter-tcp" => {
                    let b = blocks.last_mut().unwrap();
                    b.proto = Some("tcp".into());
                    b.ports = Some(value.replace("%GameFilterTCP%", "1024-65535"));
                }
                "filter-udp" => {
                    let b = blocks.last_mut().unwrap();
                    b.proto = Some("udp".into());
                    b.ports = Some(value.replace("%GameFilterUDP%", "1024-65535"));
                }
                "dpi-desync" => {
                    blocks.last_mut().unwrap().desync = Some(value.clone());
                }
                _ => {}
            }

            // Store raw arg for reference
            blocks
                .last_mut()
                .unwrap()
                .args
                .push((arg_name, value));

            if had_inline {
                i += 1;
            } else if had_next {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // Drop empty trailing block if the last block is unused
    if blocks
        .last()
        .map(|b| b.proto.is_none() && b.args.is_empty())
        .unwrap_or(false)
    {
        blocks.pop();
    }

    Ok(ZapretStrategy {
        name,
        wf_tcp,
        wf_udp,
        blocks,
    })
}

fn tokenize(s: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut had_token = false;

    for c in s.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                had_token = true;
            }
            ' ' | '\t' | '\n' | '\r' if !in_quote => {
                if had_token {
                    tokens.push(cur.clone());
                    cur.clear();
                    had_token = false;
                }
            }
            '^' => {} // cmd escape char, skip
            _ => {
                cur.push(c);
                had_token = true;
            }
        }
    }
    if had_token {
        tokens.push(cur);
    }

    // Fix cmd escaping: '^!' was escaped '!'
    for t in tokens.iter_mut() {
        *t = t.replace("^!", "!");
    }

    Ok(tokens)
}

impl ZapretStrategy {
    /// Convert to a veilnet TOML rule section.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Imported from zapret: {}\n", self.name));
        out.push_str(&format!(
            "# wf-tcp={}, wf-udp={}\n",
            self.wf_tcp.as_deref().unwrap_or("-"),
            self.wf_udp.as_deref().unwrap_or("-")
        ));
        for (i, b) in self.blocks.iter().enumerate() {
            out.push_str(&format!(
                "\n# Block {}: {} {}\n",
                i + 1,
                b.proto.as_deref().unwrap_or("any"),
                b.ports.as_deref().unwrap_or("any")
            ));
            if let Some(d) = &b.desync {
                out.push_str(&format!("# desync = {}\n", d));
            }
            for (k, v) in &b.args {
                out.push_str(&format!("#   --{}={}\n", k, v));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{tokenize, parse_bat};
    use std::path::Path;

    #[test]
    fn parse_real_general_bat() {
        let p = Path::new(r"C:\Users\Anime\Desktop\1\zapret-discord-youtube\general.bat");
        if !p.exists() {
            return; // environment-dependent test
        }
        let s = parse_bat(p).unwrap();
        assert!(s.wf_tcp.is_some(), "wf_tcp missing");
        assert!(s.blocks.len() >= 5, "expected >=5 blocks, got {}", s.blocks.len());
        assert!(s.blocks[0].proto.is_some());
    }

    #[test]
    fn tokenize_with_percent_vars() {
        let toks = tokenize(
            r#"--wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% --filter-udp=443 --dpi-desync=fake"#,
        )
        .unwrap();
        assert!(toks.iter().any(|t| t.starts_with("--wf-tcp=80")), "toks: {toks:?}");
    }

    #[test]
    fn tokenize_basic() {
        let toks = tokenize("--wf-tcp=80,443 --filter-udp=443 --new").unwrap();
        assert_eq!(
            toks,
            vec!["--wf-tcp=80,443".to_string(), "--filter-udp=443".to_string(), "--new".to_string()]
        );
    }

    #[test]
    fn tokenize_quotes() {
        let toks = tokenize(r#"--hostlist="%LISTS%list-general.txt" --new"#).unwrap();
        assert_eq!(toks[0], "--hostlist=%LISTS%list-general.txt");
        assert_eq!(toks[1], "--new");
    }

    #[test]
    fn tokenize_multi_line_join() {
        // Simulates joined bat continuation lines
        let toks = tokenize(
            "--wf-tcp=80,443 --filter-udp=443 --dpi-desync=fake ^\n--filter-tcp=443 --new",
        )
        .unwrap();
        assert!(toks.contains(&"--new".to_string()));
        assert!(toks.iter().any(|t| t.starts_with("--filter-tcp")));
    }
}
