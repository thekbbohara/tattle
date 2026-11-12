//! Turn parsed sessions into the receipt: counts, flags grouped like
//! Keyleak groups keys, everything masked and `~`-shortened.

use crate::detect;
use crate::logs::{self, Agent, Session, What};
use crate::rules::{self, Ctx, Kind, Severity};
use crate::time;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct Options {
    /// `~/.claude/projects` (or `$CLAUDE_CONFIG_DIR/projects`).
    pub claude_dir: Option<PathBuf>,
    /// `~/.codex/sessions`.
    pub codex_dir: Option<PathBuf>,
    /// Home folders shown as `~`, first one used to expand `~` in commands.
    pub homes: Vec<PathBuf>,
    pub now: i64,
    /// `None` for `--all`.
    pub days: Option<u32>,
    pub project: Option<PathBuf>,
    pub min: Severity,
    /// Skip files not modified inside the window (off for the demo, whose
    /// fixed week can be in the future).
    pub use_mtime: bool,
}

#[derive(Serialize)]
pub struct Window {
    pub days: Option<u32>,
    pub from: Option<String>,
    pub to: String,
    pub label: String,
}

#[derive(Serialize, Default, Clone, Copy)]
pub struct BySeverity {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl BySeverity {
    pub fn get(&self, s: Severity) -> usize {
        match s {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
        }
    }
    fn add(&mut self, s: Severity, n: usize) {
        match s {
            Severity::Critical => self.critical += n,
            Severity::High => self.high += n,
            Severity::Medium => self.medium += n,
            Severity::Low => self.low += n,
        }
    }
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }
}

#[derive(Serialize, Clone)]
pub struct Hit {
    pub session: String,
    pub time: String,
    pub failed: bool,
}

/// Identical flags (same kind, agent, project and masked text), grouped.
#[derive(Serialize, Clone)]
pub struct Flag {
    pub kind: Kind,
    pub severity: Severity,
    pub agent: Agent,
    pub project: String,
    /// The masked command, or `<tool> <path>` for file tools.
    pub text: String,
    pub count: usize,
    pub failed: usize,
    pub first: String,
    pub last: String,
    /// How to stop it next time. Backticks mark code.
    pub fix: String,
    pub hits: Vec<Hit>,
    #[serde(skip)]
    pub first_ts: i64,
}

#[derive(Serialize, Clone)]
pub struct SessionInfo {
    pub agent: Agent,
    pub id: String,
    pub project: String,
    pub started: String,
    pub commands: usize,
    pub file_writes: usize,
    pub flags: usize,
    pub sandbox: Option<String>,
    pub approval: Option<String>,
    #[serde(skip)]
    pub started_ts: i64,
}

#[derive(Serialize, Default, Clone, Copy)]
pub struct AgentSum {
    pub sessions: usize,
    pub commands: usize,
    pub flags: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub version: &'static str,
    pub window: Window,
    pub sessions: usize,
    pub agents: usize,
    pub projects: usize,
    pub commands: usize,
    pub file_writes: usize,
    pub by_kind: BTreeMap<&'static str, usize>,
    pub by_severity: BySeverity,
    pub flags: Vec<Flag>,
    pub skipped_lines: usize,
    pub by_agent: BTreeMap<Agent, AgentSum>,
    pub session_list: Vec<SessionInfo>,
}

impl Report {
    pub fn critical(&self) -> bool {
        self.by_severity.critical > 0
    }
}

pub fn scan(o: &Options) -> Report {
    let from = o.days.map(|d| o.now - i64::from(d) * 86400);
    let parsed =
        logs::read_all(o.claude_dir.as_deref(), o.codex_dir.as_deref(), from.filter(|_| o.use_mtime));
    build(parsed.sessions, parsed.skipped, o)
}

pub fn build(sessions: Vec<Session>, skipped: usize, o: &Options) -> Report {
    let from = o.days.map(|d| o.now - i64::from(d) * 86400);
    let home = o.homes.first().cloned().unwrap_or_else(|| PathBuf::from("/"));
    let mut rep = Report {
        version: env!("CARGO_PKG_VERSION"),
        window: Window {
            days: o.days,
            from: from.map(time::iso),
            to: time::iso(o.now),
            label: match o.days {
                Some(1) => "last 24 hours".into(),
                Some(d) => format!("last {d} days"),
                None => "all time".into(),
            },
        },
        sessions: 0,
        agents: 0,
        projects: 0,
        commands: 0,
        file_writes: 0,
        by_kind: Kind::ALL.iter().map(|k| (k.id(), 0)).collect(),
        by_severity: BySeverity::default(),
        flags: Vec::new(),
        skipped_lines: skipped,
        by_agent: BTreeMap::new(),
        session_list: Vec::new(),
    };
    let mut groups: BTreeMap<(Kind, Agent, String, String), Flag> = BTreeMap::new();
    let (mut agents, mut projects) = (BTreeSet::new(), BTreeSet::new());

    for s in sessions {
        let project = PathBuf::from(&s.cwd);
        if let Some(p) = &o.project {
            if s.cwd.is_empty() || !project.starts_with(p) {
                continue;
            }
        }
        let events: Vec<_> = s.events.iter().filter(|e| from.map_or(true, |f| e.ts >= f)).collect();
        if events.is_empty() {
            continue;
        }
        let shown_project = shorten(&s.cwd, &o.homes);
        let mut info = SessionInfo {
            agent: s.agent,
            id: s.id.clone(),
            project: shown_project.clone(),
            started: String::new(),
            commands: 0,
            file_writes: 0,
            flags: 0,
            sandbox: s.sandbox.clone(),
            approval: s.approval.clone(),
            started_ts: events[0].ts,
        };
        info.started = time::iso(info.started_ts);
        for e in events {
            let cwd = e.cwd.as_deref().map(PathBuf::from).unwrap_or_else(|| project.clone());
            let ctx = Ctx {
                agent: s.agent,
                cwd: &cwd,
                project: &project,
                home: &home,
                branch: e.branch.as_deref(),
            };
            let (found, text) = match &e.what {
                What::Command(line) => {
                    info.commands += 1;
                    (rules::check_command(line, &ctx), line.clone())
                }
                What::Write { tool, path } => {
                    info.file_writes += 1;
                    (rules::check_write(path, &ctx).into_iter().collect(), format!("{tool} {path}"))
                }
                What::Read { tool, path } => {
                    (rules::check_read(path, &ctx).into_iter().collect(), format!("{tool} {path}"))
                }
            };
            let found: Vec<_> = found.into_iter().filter(|f| f.severity >= o.min).collect();
            if found.is_empty() {
                continue;
            }
            let text = display(&text, &o.homes);
            for f in found {
                info.flags += 1;
                rep.by_severity.add(f.severity, 1);
                *rep.by_kind.entry(f.kind.id()).or_default() += 1;
                let key = (f.kind, s.agent, shown_project.clone(), text.clone());
                let g = groups.entry(key).or_insert_with(|| Flag {
                    kind: f.kind,
                    severity: f.severity,
                    agent: s.agent,
                    project: shown_project.clone(),
                    text: text.clone(),
                    count: 0,
                    failed: 0,
                    first: String::new(),
                    last: String::new(),
                    fix: f.fix.clone(),
                    hits: Vec::new(),
                    first_ts: e.ts,
                });
                if f.severity > g.severity {
                    g.severity = f.severity;
                    g.fix = f.fix;
                }
                g.count += 1;
                g.failed += usize::from(e.failed);
                g.first_ts = g.first_ts.min(e.ts);
                g.hits.push(Hit { session: s.id.clone(), time: time::iso(e.ts), failed: e.failed });
            }
        }
        rep.sessions += 1;
        rep.commands += info.commands;
        rep.file_writes += info.file_writes;
        agents.insert(s.agent);
        projects.insert(shown_project);
        let a = rep.by_agent.entry(s.agent).or_default();
        a.sessions += 1;
        a.commands += info.commands;
        a.flags += info.flags;
        rep.session_list.push(info);
    }

    rep.agents = agents.len();
    rep.projects = projects.len();
    rep.flags = groups
        .into_values()
        .map(|mut g| {
            g.hits.sort_by(|a, b| a.time.cmp(&b.time));
            g.first = g.hits.first().map(|h| h.time.clone()).unwrap_or_default();
            g.last = g.hits.last().map(|h| h.time.clone()).unwrap_or_default();
            g
        })
        .collect();
    rep.flags.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(a.first_ts.cmp(&b.first_ts)).then(a.text.cmp(&b.text))
    });
    rep.session_list.sort_by_key(|s| s.started_ts);
    rep
}

/// A command or path as Tattle shows it: secrets masked, home as `~`, one line.
pub fn display(text: &str, homes: &[PathBuf]) -> String {
    let mut masked = String::with_capacity(text.len());
    let mut at = 0;
    for h in detect::find(text, false) {
        if h.start < at {
            continue;
        }
        masked.push_str(&text[at..h.start]);
        masked.push_str(&detect::mask(&detect::DETECTORS[h.detector], &text[h.start..h.end]));
        at = h.end;
    }
    masked.push_str(&text[at..]);
    let one_line = masked.trim().lines().map(str::trim_end).collect::<Vec<_>>().join(" ↵ ");
    shorten(&one_line, homes)
}

/// Replace each home folder in `s` with `~`, at path boundaries only.
pub fn shorten(s: &str, homes: &[PathBuf]) -> String {
    let mut homes: Vec<String> = homes
        .iter()
        .map(|h| h.to_string_lossy().trim_end_matches('/').to_string())
        .filter(|h| h.len() > 1)
        .collect();
    homes.sort_by_key(|h| std::cmp::Reverse(h.len()));
    let mut out = s.to_string();
    for h in homes {
        let mut res = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(p) = rest.find(&h) {
            let after = rest[p + h.len()..].chars().next();
            let before = rest[..p].chars().next_back();
            let boundary_after =
                after.map_or(true, |c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')));
            let boundary_before =
                before.map_or(true, |c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')));
            res.push_str(&rest[..p]);
            res.push_str(if boundary_after && boundary_before { "~" } else { &h });
            rest = &rest[p + h.len()..];
        }
        res.push_str(rest);
        out = res;
    }
    out
}

/// A path for CLI messages: relative when inside the working folder, else
/// `~`-shortened, so screen recordings never show the user's folder names.
pub fn short_path(p: &Path, home: Option<&Path>) -> String {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let cwd = std::env::current_dir().ok().filter(|c| c.parent().is_some());
    match cwd.as_deref().and_then(|c| abs.strip_prefix(c).ok()) {
        Some(r) if r.as_os_str().is_empty() => ".".into(),
        Some(r) => r.display().to_string(),
        None => {
            shorten(&abs.display().to_string(), &home.map(Path::to_path_buf).into_iter().collect::<Vec<_>>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_shown_as_tilde_at_boundaries() {
        let homes = [PathBuf::from("/home/me")];
        assert_eq!(shorten("cat /home/me/.npmrc > /home/me", &homes), "cat ~/.npmrc > ~");
        assert_eq!(shorten("/home/mex/a /x/home/me/b", &homes), "/home/mex/a /x/home/me/b");
        assert_eq!(display("cd /home/me/code\nls", &homes), "cd ~/code ↵ ls");
    }
}
