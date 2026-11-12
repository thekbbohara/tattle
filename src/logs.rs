//! Tolerant readers for Claude Code and Codex session logs.
//!
//! Only commands, file paths, tool names, error flags and session metadata
//! are deserialised. Prompt, reply, tool output, diff and file content fields
//! are never declared here, so serde skips them without keeping them.
//! Unknown lines and fields are skipped; unreadable lines are counted.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::io::BufRead;
use std::path::Path;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    ClaudeCode,
    Codex,
}

impl Agent {
    pub fn label(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Codex => "Codex",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    /// A shell line, as the agent ran it.
    Command(String),
    /// A file written by an agent tool. `tool` is `Write`, `Edit`, `FileChange` ...
    Write { tool: String, path: String },
    /// A file read by an agent tool (only used for the secret-read rule).
    Read { tool: String, path: String },
}

#[derive(Debug, Clone)]
pub struct Event {
    pub ts: i64,
    pub what: What,
    pub failed: bool,
    /// Working folder of this command when the log records it.
    pub cwd: Option<String>,
    pub branch: Option<String>,
    id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub agent: Agent,
    pub id: String,
    /// The session's working folder: its project root.
    pub cwd: String,
    pub started: Option<i64>,
    pub sandbox: Option<String>,
    pub approval: Option<String>,
    pub events: Vec<Event>,
}

/// Lines that could not be used: not JSON, unknown `type`, or missing the
/// fields Tattle needs.
#[derive(Default)]
pub struct Parsed {
    pub sessions: Vec<Session>,
    pub skipped: usize,
}

/// Any JSON value; `Some` only when it is a string.
fn lenient_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) => Some(s),
        _ => None,
    })
}

fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(Value::deserialize(d)?.as_bool())
}

fn lenient_i64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    Ok(Value::deserialize(d)?.as_i64())
}

/// Read lines of `r`, giving each non-blank line to `f`. Invalid UTF-8 is
/// replaced, never fatal.
fn for_lines(mut r: impl BufRead, mut f: impl FnMut(&str)) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf);
                let line = line.trim();
                if !line.is_empty() {
                    f(line);
                }
            }
        }
    }
}

// ---------------------------------------------------------------- Claude Code

#[derive(Deserialize)]
struct ClaudeLine {
    #[serde(rename = "type", default, deserialize_with = "lenient_str")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    cwd: Option<String>,
    #[serde(rename = "sessionId", default, deserialize_with = "lenient_str")]
    session_id: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    timestamp: Option<String>,
    #[serde(rename = "gitBranch", default, deserialize_with = "lenient_str")]
    git_branch: Option<String>,
    #[serde(default)]
    message: Option<ClaudeMessage>,
}

#[derive(Deserialize)]
struct ClaudeMessage {
    #[serde(default)]
    content: Option<Content>,
}

/// User prompts are plain strings: matched by `Other` and dropped unread.
#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Items(Vec<Item>),
    Other(serde::de::IgnoredAny),
}

#[derive(Deserialize)]
struct Item {
    #[serde(rename = "type", default, deserialize_with = "lenient_str")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    id: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    name: Option<String>,
    #[serde(default)]
    input: Option<ToolInput>,
    #[serde(default, deserialize_with = "lenient_str")]
    tool_use_id: Option<String>,
    #[serde(default, deserialize_with = "lenient_bool")]
    is_error: Option<bool>,
}

#[derive(Deserialize, Default)]
struct ToolInput {
    #[serde(default, deserialize_with = "lenient_str")]
    command: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    file_path: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    notebook_path: Option<String>,
}

/// Claude Code line types that carry nothing Tattle uses.
const CLAUDE_OTHER: &[&str] = &[
    "system",
    "summary",
    "attachment",
    "progress",
    "file-history-snapshot",
    "file-history-delta",
    "queue-operation",
    "last-prompt",
    "mode",
    "permission-mode",
    "ai-title",
    "custom-title",
    "cost-state",
    "atis-latch",
    "tag",
    "result",
];

fn known_claude_other(kind: &str) -> bool {
    CLAUDE_OTHER.contains(&kind) || kind.starts_with("api-request")
}

/// Parse one Claude Code session log (`~/.claude/projects/<dir>/<id>.jsonl`).
pub fn parse_claude(r: impl BufRead, fallback_id: &str, skipped: &mut usize) -> Option<Session> {
    let mut s = Session {
        agent: Agent::ClaudeCode,
        id: fallback_id.to_string(),
        cwd: String::new(),
        started: None,
        sandbox: None,
        approval: None,
        events: Vec::new(),
    };
    let mut have_id = false;
    let mut failed_ids: HashSet<String> = HashSet::new();
    let (mut last_ts, mut last_cwd, mut last_branch) = (None::<i64>, None::<String>, None::<String>);
    for_lines(r, |line| {
        let Ok(l) = serde_json::from_str::<ClaudeLine>(line) else {
            *skipped += 1;
            return;
        };
        let kind = l.kind.as_deref().unwrap_or("");
        if kind != "assistant" && kind != "user" {
            if !known_claude_other(kind) {
                *skipped += 1;
            }
            return;
        }
        if let Some(t) = l.timestamp.as_deref().and_then(crate::time::parse) {
            last_ts = Some(t);
            s.started.get_or_insert(t);
        }
        if let Some(c) = l.cwd.filter(|c| !c.is_empty()) {
            if s.cwd.is_empty() {
                s.cwd = c.clone();
            }
            last_cwd = Some(c);
        }
        if l.git_branch.as_deref().is_some_and(|b| !b.is_empty()) {
            last_branch = l.git_branch;
        }
        if let (false, Some(id)) = (have_id, l.session_id) {
            s.id = id;
            have_id = true;
        }
        let items = match l.message.and_then(|m| m.content) {
            Some(Content::Items(v)) => v,
            _ => return,
        };
        let mut bad = false;
        for it in items {
            match (kind, it.kind.as_deref()) {
                ("user", Some("tool_result")) => {
                    if let (Some(true), Some(id)) = (it.is_error, it.tool_use_id) {
                        failed_ids.insert(id);
                    }
                }
                ("assistant", Some("tool_use")) => {
                    let name = it.name.unwrap_or_default();
                    let input = it.input.unwrap_or_default();
                    let what = match name.as_str() {
                        "Bash" => input.command.map(What::Command),
                        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => input
                            .file_path
                            .or(input.notebook_path)
                            .map(|path| What::Write { tool: name.clone(), path }),
                        "Read" => input.file_path.map(|path| What::Read { tool: name.clone(), path }),
                        _ => continue,
                    };
                    match (what, last_ts) {
                        (Some(what), Some(ts)) if last_cwd.is_some() => s.events.push(Event {
                            ts,
                            what,
                            failed: false,
                            cwd: last_cwd.clone(),
                            branch: last_branch.clone(),
                            id: it.id,
                        }),
                        _ => bad = true,
                    }
                }
                _ => {}
            }
        }
        if bad {
            *skipped += 1;
        }
    });
    for e in &mut s.events {
        e.failed = e.id.as_ref().is_some_and(|id| failed_ids.contains(id));
    }
    (!s.events.is_empty() || !s.cwd.is_empty()).then_some(s)
}

// ---------------------------------------------------------------- Codex

#[derive(Deserialize)]
struct CodexLine {
    #[serde(rename = "type", default, deserialize_with = "lenient_str")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    timestamp: Option<String>,
    #[serde(default)]
    payload: Option<Payload>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(rename = "type", default, deserialize_with = "lenient_str")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    id: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    cwd: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    timestamp: Option<String>,
    #[serde(default)]
    sandbox_policy: Option<Value>,
    #[serde(default, deserialize_with = "lenient_str")]
    approval_policy: Option<String>,
    #[serde(default)]
    item: Option<CodexItem>,
    // Older `response_item` tool calls.
    #[serde(default, deserialize_with = "lenient_str")]
    name: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    arguments: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    input: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    call_id: Option<String>,
}

#[derive(Deserialize)]
struct CodexItem {
    #[serde(rename = "type", default, deserialize_with = "lenient_str")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    id: Option<String>,
    #[serde(default)]
    command: Option<Value>,
    #[serde(default, deserialize_with = "lenient_str")]
    cwd: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    exit_code: Option<i64>,
    #[serde(default, deserialize_with = "lenient_str")]
    status: Option<String>,
    #[serde(default)]
    changes: Option<Changes>,
}

/// `changes` keyed by path (diffs and content are not declared, so skipped).
#[derive(Deserialize)]
#[serde(untagged)]
enum Changes {
    Map(BTreeMap<String, Change>),
    List(Vec<Change>),
    Other(serde::de::IgnoredAny),
}

#[derive(Deserialize)]
struct Change {
    #[serde(default, deserialize_with = "lenient_str")]
    path: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    move_path: Option<String>,
}

#[derive(Deserialize)]
struct ShellArgs {
    #[serde(default)]
    command: Option<Value>,
    #[serde(default, deserialize_with = "lenient_str")]
    cmd: Option<String>,
    #[serde(default, deserialize_with = "lenient_str")]
    workdir: Option<String>,
}

const CODEX_TYPES: &[&str] = &[
    "session_meta",
    "turn_context",
    "event_msg",
    "response_item",
    "compacted",
    "world_state",
    "token_usage_record",
];

/// Older Codex shell tools in `response_item.function_call`.
const CODEX_SHELL_FNS: &[&str] = &["shell", "container.exec", "local_shell", "shell_command", "exec_command"];

/// `["bash", "-lc", "<script>"]` gives the script; other arrays are joined.
fn command_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => {
            let words: Vec<String> = a.iter().filter_map(|w| w.as_str().map(str::to_string)).collect();
            if words.is_empty() {
                return None;
            }
            let shell = matches!(crate::rules::basename(&words[0]), "bash" | "sh" | "zsh" | "dash");
            if shell && words.len() == 3 && words[1].starts_with('-') && words[1].contains('c') {
                Some(words[2].clone())
            } else {
                Some(crate::shell::join(&words))
            }
        }
        _ => None,
    }
}

/// Paths named in an `apply_patch` envelope (`*** Update File: x`). Only
/// those header lines are looked at.
fn patch_paths(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|l| {
            ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "]
                .iter()
                .find_map(|p| l.strip_prefix(p))
        })
        .map(|p| p.trim().to_string())
        .collect()
}

/// Parse one Codex rollout log (`~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`).
pub fn parse_codex(r: impl BufRead, fallback_id: &str, skipped: &mut usize) -> Option<Session> {
    let mut s = Session {
        agent: Agent::Codex,
        id: fallback_id.to_string(),
        cwd: String::new(),
        started: None,
        sandbox: None,
        approval: None,
        events: Vec::new(),
    };
    let mut item_ids: HashSet<String> = HashSet::new();
    let mut fallback: Vec<Event> = Vec::new();
    let mut last_ts = None::<i64>;
    for_lines(r, |line| {
        let Ok(l) = serde_json::from_str::<CodexLine>(line) else {
            *skipped += 1;
            return;
        };
        let kind = l.kind.as_deref().unwrap_or("");
        if !CODEX_TYPES.contains(&kind) {
            *skipped += 1;
            return;
        }
        if let Some(t) = l.timestamp.as_deref().and_then(crate::time::parse) {
            last_ts = Some(t);
        }
        let Some(p) = l.payload else {
            *skipped += 1;
            return;
        };
        let ts = last_ts;
        let event = |what: What, cwd: Option<String>, failed: bool, id: Option<String>| {
            ts.map(|ts| Event { ts, what, failed, cwd, branch: None, id })
        };
        match (kind, p.kind.as_deref()) {
            ("session_meta", _) => {
                if let Some(id) = p.id {
                    s.id = id;
                }
                if let Some(c) = p.cwd {
                    s.cwd = c;
                }
                s.started = p.timestamp.as_deref().and_then(crate::time::parse).or(ts);
            }
            ("turn_context", _) => {
                if s.cwd.is_empty() {
                    s.cwd = p.cwd.unwrap_or_default();
                }
                let sandbox = match p.sandbox_policy {
                    Some(Value::String(v)) => Some(v),
                    Some(Value::Object(o)) => o.get("type").and_then(Value::as_str).map(str::to_string),
                    _ => None,
                };
                s.sandbox = sandbox.or(s.sandbox.take());
                s.approval = p.approval_policy.or(s.approval.take());
            }
            ("event_msg", Some("item_completed")) => {
                let Some(it) = p.item else { return };
                let id = it.id.clone();
                let mut bad = false;
                match it.kind.as_deref() {
                    Some("CommandExecution") => {
                        let failed =
                            it.exit_code.is_some_and(|c| c != 0) || it.status.as_deref() == Some("failed");
                        match it.command.as_ref().and_then(command_text) {
                            Some(cmd) => match event(What::Command(cmd), it.cwd, failed, id.clone()) {
                                Some(e) => s.events.push(e),
                                None => bad = true,
                            },
                            None => bad = true,
                        }
                    }
                    Some("FileChange") => {
                        let paths: Vec<String> = match it.changes {
                            Some(Changes::Map(m)) => m
                                .into_iter()
                                .flat_map(|(k, c)| std::iter::once(k).chain(c.move_path))
                                .collect(),
                            Some(Changes::List(v)) => {
                                v.into_iter().flat_map(|c| c.path.into_iter().chain(c.move_path)).collect()
                            }
                            _ => Vec::new(),
                        };
                        bad = paths.is_empty();
                        for path in paths {
                            let what = What::Write { tool: "FileChange".into(), path };
                            match event(what, it.cwd.clone(), false, id.clone()) {
                                Some(e) => s.events.push(e),
                                None => bad = true,
                            }
                        }
                    }
                    _ => return,
                }
                item_ids.extend(id);
                if bad {
                    *skipped += 1;
                }
            }
            ("response_item", Some("function_call")) => {
                let name = p.name.unwrap_or_default();
                if !CODEX_SHELL_FNS.contains(&name.as_str()) {
                    return;
                }
                let args = p.arguments.as_deref().and_then(|a| serde_json::from_str::<ShellArgs>(a).ok());
                let Some(args) = args else {
                    *skipped += 1;
                    return;
                };
                let cmd = args.command.as_ref().and_then(command_text).or(args.cmd);
                match cmd.and_then(|c| event(What::Command(c), args.workdir, false, p.call_id)) {
                    Some(e) => fallback.push(e),
                    None => *skipped += 1,
                }
            }
            ("response_item", Some("custom_tool_call")) if p.name.as_deref() == Some("apply_patch") => {
                for path in patch_paths(p.input.as_deref().unwrap_or("")) {
                    let what = What::Write { tool: "apply_patch".into(), path };
                    fallback.extend(event(what, None, false, p.call_id.clone()));
                }
            }
            _ => {}
        }
    });
    // Newer logs record each tool call twice: as a `response_item` call and as
    // an `item_completed` item, and the two ids do not always match. The items
    // are the record; the old-style calls count only in files with no items,
    // once per `call_id`.
    if item_ids.is_empty() {
        let mut seen = HashSet::new();
        s.events.extend(
            fallback.into_iter().filter(|e| e.id.as_ref().map_or(true, |id| seen.insert(id.clone()))),
        );
    }
    s.events.sort_by_key(|e| e.ts);
    (!s.events.is_empty() || !s.cwd.is_empty()).then_some(s)
}

// ---------------------------------------------------------------- folders

fn jsonl_files(dir: &Path, depth: usize, name_ok: &dyn Fn(&str) -> bool, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() && depth > 0 {
            jsonl_files(&p, depth - 1, name_ok, out);
        } else if ft.is_file() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".jsonl") && name_ok(&name) {
                out.push(p);
            }
        }
    }
}

fn modified(p: &Path) -> Option<i64> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(m.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64)
}

/// Read every session under `claude` (a `projects` folder) and `codex` (a
/// `sessions` folder). Files last changed before `since` are not opened.
pub fn read_all(claude: Option<&Path>, codex: Option<&Path>, since: Option<i64>) -> Parsed {
    let mut out = Parsed::default();
    let fresh = |p: &Path| since.map_or(true, |s| modified(p).map_or(true, |m| m >= s));
    let stem = |p: &Path| p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    if let Some(dir) = claude {
        let mut files = Vec::new();
        jsonl_files(dir, 3, &|_| true, &mut files);
        for f in files.iter().filter(|f| fresh(f)) {
            if let Ok(file) = std::fs::File::open(f) {
                let r = std::io::BufReader::new(file);
                out.sessions.extend(parse_claude(r, &stem(f), &mut out.skipped));
            }
        }
    }
    if let Some(dir) = codex {
        let mut files = Vec::new();
        jsonl_files(dir, 4, &|n| n.starts_with("rollout-"), &mut files);
        for f in files.iter().filter(|f| fresh(f)) {
            if let Ok(file) = std::fs::File::open(f) {
                let r = std::io::BufReader::new(file);
                out.sessions.extend(parse_codex(r, &stem(f), &mut out.skipped));
            }
        }
    }
    out
}
