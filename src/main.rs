use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tattle::report::{self, Options};
use tattle::rules::Severity;
use tattle::{demo, html, term, time};

const HELP: &str = "\
tattle - a receipt of what your AI coding agents did to your machine

USAGE:
    tattle [OPTIONS]               read ~/.claude/projects and ~/.codex/sessions, last 7 days
    tattle demo [DIR] [OPTIONS]    write a fake home with fake logs to DIR, then read it

OPTIONS:
        --days <N>                 time window in days (default: 7)
        --all                      no time window
        --home <DIR>               use DIR as home (logs under DIR/.claude and DIR/.codex)
        --project <PATH>           only sessions whose folder is under PATH
        --json [FILE]              JSON report to FILE, or to stdout
        --html <FILE>              also write an HTML report
        --min <LEVEL>              hide flags below low|medium|high|critical (default: low)
        --color / --no-color       force colours on or off (default: on for a terminal, off with NO_COLOR)
    -h, --help                     print this help
    -V, --version                  print the version

Prompts, replies and tool output are never read. Secrets are masked. Nothing
is changed and nothing is sent over the network.
Exit code: 0 ok, 1 a critical flag was found, 2 usage error.
";

struct Args {
    demo: Option<Option<PathBuf>>,
    days: Option<u32>,
    home: Option<PathBuf>,
    project: Option<PathBuf>,
    json: Option<Option<PathBuf>>,
    html: Option<PathBuf>,
    min: Severity,
    color: Option<bool>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        demo: None,
        days: Some(7),
        home: None,
        project: None,
        json: None,
        html: None,
        min: Severity::Low,
        color: None,
    };
    let mut it = std::env::args_os().skip(1).peekable();
    let mut first = true;
    while let Some(arg) = it.next() {
        let s = arg.to_string_lossy().into_owned();
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match s.as_str() {
            "demo" if first => {
                let dir = match it.peek() {
                    Some(v) if !v.to_string_lossy().starts_with('-') => {
                        Some(PathBuf::from(it.next().unwrap()))
                    }
                    _ => None,
                };
                a.demo = Some(dir);
            }
            "--days" => {
                let n: u32 =
                    value(&s)?.to_string_lossy().parse().map_err(|_| "--days takes a whole number")?;
                if n == 0 {
                    return Err("--days must be at least 1".into());
                }
                a.days = Some(n);
            }
            "--all" => a.days = None,
            "--home" => a.home = Some(PathBuf::from(value(&s)?)),
            "--project" => a.project = Some(PathBuf::from(value(&s)?)),
            "--json" => {
                a.json = Some(match it.peek() {
                    Some(v) if !v.to_string_lossy().starts_with('-') => {
                        Some(PathBuf::from(it.next().unwrap()))
                    }
                    _ => None,
                })
            }
            "--html" => a.html = Some(PathBuf::from(value(&s)?)),
            "--min" => {
                let v = value(&s)?.to_string_lossy().into_owned();
                a.min = Severity::parse(&v).ok_or("--min takes low, medium, high or critical")?;
            }
            "--color" => a.color = Some(true),
            "--no-color" => a.color = Some(false),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("tattle {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument '{s}' (see tattle --help)")),
        }
        first = false;
    }
    if a.demo.is_some() && a.home.is_some() {
        return Err("demo writes its own home; --home cannot be used with it".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tattle: {e}");
            return ExitCode::from(2);
        }
    };
    match run(a) {
        Ok(critical) => ExitCode::from(u8::from(critical)),
        Err(e) => {
            eprintln!("tattle: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(a: Args) -> Result<bool, String> {
    let real_home = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_dir());
    let json_stdout = matches!(a.json, Some(None));
    let mut opts = Options {
        claude_dir: None,
        codex_dir: None,
        homes: Vec::new(),
        now: time::now(),
        days: a.days,
        project: None,
        min: a.min,
        use_mtime: true,
    };
    let home = if let Some(dir) = &a.demo {
        let dir = dir.clone().unwrap_or_else(|| std::env::temp_dir().join("tattle-demo"));
        demo::write_fake_home(&dir)
            .map_err(|e| format!("cannot write the demo to {}: {e}", dir.display()))?;
        let dir = std::fs::canonicalize(&dir).map_err(|e| e.to_string())?;
        if !json_stdout {
            // The only line that names a folder: the demo prints no other path.
            let mut msg = format!(
                "tattle: demo home written to {} (fake logs, fake keys)",
                report::short_path(&dir, real_home.as_deref())
            );
            for (label, path) in [("HTML report", &a.html), ("JSON report", &a.json.clone().flatten())] {
                if let Some(p) = path {
                    msg += &format!(", {label}: {}", report::short_path(p, real_home.as_deref()));
                }
            }
            eprintln!("{msg}");
        }
        opts.now = demo::now();
        opts.use_mtime = false;
        opts.claude_dir = Some(dir.join(".claude/projects"));
        opts.codex_dir = Some(dir.join(".codex/sessions"));
        opts.homes = vec![PathBuf::from(demo::USER_HOME), dir.clone()];
        PathBuf::from(demo::USER_HOME)
    } else {
        let (home, custom) = match &a.home {
            Some(h) => {
                let h = std::fs::canonicalize(h).map_err(|e| format!("--home {}: {e}", h.display()))?;
                (h, true)
            }
            None => (real_home.clone().ok_or("HOME is not set; use --home")?, false),
        };
        let env_dir =
            |var: &str| std::env::var_os(var).filter(|v| !custom && !v.is_empty()).map(PathBuf::from);
        opts.claude_dir =
            Some(env_dir("CLAUDE_CONFIG_DIR").unwrap_or_else(|| home.join(".claude")).join("projects"));
        opts.codex_dir = Some(env_dir("CODEX_HOME").unwrap_or_else(|| home.join(".codex")).join("sessions"));
        opts.homes = vec![home.clone()];
        home
    };
    if let Some(p) = &a.project {
        let p = p.to_string_lossy();
        let abs = tattle::rules::resolve(&p, &std::env::current_dir().map_err(|e| e.to_string())?, &home)
            .ok_or("--project must be a plain path")?;
        opts.project = Some(abs);
    }

    let rep = report::scan(&opts);

    if let Some(path) = &a.html {
        write_private(path, &html::render(&rep))?;
    }
    let json = || serde_json::to_string_pretty(&rep).map_err(|e| e.to_string());
    match &a.json {
        Some(None) => println!("{}", json()?),
        Some(Some(path)) => write_private(path, &(json()? + "\n"))?,
        None => {}
    }
    if !json_stdout {
        let color = a
            .color
            .unwrap_or_else(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none());
        print!("{}", term::render(&rep, &term::Style { color }));
        let files = [("HTML report", &a.html), ("JSON report", &a.json.clone().flatten())];
        let files: Vec<_> = files.into_iter().filter_map(|(l, p)| p.as_ref().map(|p| (l, p))).collect();
        if a.demo.is_none() && !files.is_empty() {
            for (label, p) in files {
                println!("  {label}: {}", report::short_path(p, real_home.as_deref()));
            }
            println!();
        }
    }
    Ok(rep.critical())
}

/// Reports hold masked commands only, but paths are still private, so files
/// are created readable by the owner only.
fn write_private(path: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())
}
