//! End-to-end tests on the demo generator's fake homes. Never real logs.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use tattle::demo;

/// A fresh, empty folder, removed when dropped.
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tattle-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Tmp(fs::canonicalize(dir).unwrap())
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Run tattle with a fake `HOME` and no agent env vars, so a test can never
/// reach the real logs of the machine it runs on.
fn tattle(args: &[&str], fake_home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tattle"))
        .args(args)
        .env("HOME", fake_home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

struct Demo {
    _tmp: Tmp,
    dir: PathBuf,
    json: Value,
    term: String,
    stderr: String,
    html: String,
    code: Option<i32>,
}

fn run_demo() -> Demo {
    let tmp = Tmp::new();
    let dir = tmp.0.join("demo");
    let html = tmp.0.join("report.html");
    let j = tattle(&["demo", dir.to_str().unwrap(), "--json"], &tmp.0);
    let t = tattle(&["demo", dir.to_str().unwrap(), "--html", html.to_str().unwrap()], &tmp.0);
    assert_eq!(j.status.code(), t.status.code());
    Demo {
        json: serde_json::from_slice(&j.stdout).unwrap(),
        term: String::from_utf8(t.stdout).unwrap(),
        stderr: String::from_utf8(t.stderr).unwrap(),
        html: fs::read_to_string(&html).unwrap(),
        code: t.status.code(),
        dir,
        _tmp: tmp,
    }
}

fn flags<'a>(d: &'a Demo, kind: &str) -> Vec<&'a Value> {
    d.json["flags"].as_array().unwrap().iter().filter(|f| f["kind"] == kind).collect()
}

fn total(fs: &[&Value]) -> u64 {
    fs.iter().map(|f| f["count"].as_u64().unwrap()).sum()
}

// ---------------------------------------------------------------- demo numbers (the reel depends on them)

#[test]
fn demo_sessions_agents_projects_window() {
    let d = run_demo();
    assert_eq!(d.json["sessions"], 9);
    assert_eq!(d.json["agents"], 2);
    assert_eq!(d.json["projects"], 4);
    assert_eq!(d.json["window"]["label"], "last 7 days");
    assert_eq!(d.json["by_agent"]["claude-code"]["sessions"], 6);
    assert_eq!(d.json["by_agent"]["codex"]["sessions"], 3);
    let mut projects: Vec<&str> =
        d.json["session_list"].as_array().unwrap().iter().map(|s| s["project"].as_str().unwrap()).collect();
    projects.sort();
    projects.dedup();
    assert_eq!(projects, ["~/code/blog", "~/code/invoice-api", "~/code/telegram-bot", "~/dotfiles"]);
    assert_eq!(d.json["skipped_lines"], 0);
}

#[test]
fn demo_has_1412_commands() {
    let d = run_demo();
    assert_eq!(d.json["commands"], 1412);
    let per: Vec<u64> =
        d.json["session_list"].as_array().unwrap().iter().map(|s| s["commands"].as_u64().unwrap()).collect();
    let mut sorted = per.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(sorted, [212, 188, 174, 160, 151, 141, 139, 126, 121]);
    assert!(d.term.contains("COMMANDS"));
    assert!(d.html.contains("data-n=\"1412\">1,412<"));
}

#[test]
fn demo_severity_chips() {
    let d = run_demo();
    let s = &d.json["by_severity"];
    assert_eq!(
        (s["critical"].as_u64(), s["high"].as_u64(), s["medium"].as_u64(), s["low"].as_u64()),
        (Some(2), Some(10), Some(5), Some(14))
    );
    assert!(d.term.contains("● 2 critical   ● 10 high   ● 5 medium   ● 14 low"));
    for chip in ["2 critical", "10 high", "5 medium", "14 low"] {
        assert!(d.html.contains(&format!("<i></i>{chip}</span>")), "{chip}");
    }
}

#[test]
fn demo_criticals_force_push_and_curl_pipe() {
    let d = run_demo();
    assert_eq!(d.json["by_kind"]["force_push"], 1);
    assert_eq!(d.json["by_kind"]["pipe_to_shell"], 1);
    let fp = flags(&d, "force_push");
    assert_eq!(fp[0]["text"], "git push --force origin main");
    assert_eq!(fp[0]["severity"], "critical");
    assert_eq!(fp[0]["project"], "~/code/blog");
    assert_eq!(fp[0]["agent"], "claude-code");
    assert_eq!(
        fp[0]["fix"],
        "Add `\"Bash(git push --force:*)\"` to `permissions.deny` in `.claude/settings.json`"
    );
    assert!(d.term.contains("Add \"Bash(git push --force:*)\" to permissions.deny in .claude/settings.json"));
    let pipe = flags(&d, "pipe_to_shell");
    assert_eq!(pipe[0]["text"], "curl -fsSL https://get.example.dev/install.sh | sh");
    assert_eq!(
        (pipe[0]["agent"].as_str(), pipe[0]["project"].as_str()),
        (Some("codex"), Some("~/code/invoice-api"))
    );
    // Criticals come first in every output.
    let first: Vec<&str> =
        d.json["flags"].as_array().unwrap()[..2].iter().map(|f| f["kind"].as_str().unwrap()).collect();
    assert_eq!(first, ["force_push", "pipe_to_shell"]);
}

#[test]
fn demo_nine_deletes() {
    let d = run_demo();
    assert_eq!(d.json["by_kind"]["delete"], 9);
    let del = flags(&d, "delete");
    assert!(del.iter().all(|f| f["severity"] == "high"), "no rebuildable deletes in the demo");
    let count = |prefix: &str| {
        total(
            &del.iter()
                .copied()
                .filter(|f| f["text"].as_str().unwrap().starts_with(prefix))
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        (count("rm -rf"), count("git reset --hard"), count("git clean -fdx"), count("find ")),
        (5, 2, 1, 1)
    );
}

#[test]
fn demo_one_failed_sudo() {
    let d = run_demo();
    assert_eq!(d.json["by_kind"]["sudo"], 1);
    let s = flags(&d, "sudo");
    assert_eq!(s[0]["text"], "sudo apt install ffmpeg");
    assert_eq!((s[0]["severity"].as_str(), s[0]["failed"].as_u64()), (Some("high"), Some(1)));
    assert!(d.term.contains("sudo · ~/code/telegram-bot · Codex · Sat 31 Oct 11:44 · failed"));
}

#[test]
fn demo_mediums_writes_outside_and_secrets() {
    let d = run_demo();
    let mut outside: Vec<&str> =
        flags(&d, "outside_project").iter().map(|f| f["text"].as_str().unwrap()).collect();
    outside.sort();
    assert_eq!(outside, ["Edit ~/.bashrc", "FileChange ~/.npmrc", "echo 'target/' >> ~/.config/git/ignore"]);
    let secrets = flags(&d, "secret_access");
    assert_eq!(total(&secrets), 2);
    assert!(secrets.iter().any(|f| f["text"] == "cat .env" && f["project"] == "~/code/telegram-bot"));
    let bearer = secrets.iter().find(|f| f["text"].as_str().unwrap().starts_with("curl")).unwrap();
    assert!(bearer["text"].as_str().unwrap().contains("Bearer sk-proj-…"), "{}", bearer["text"]);
    assert!(secrets.iter().chain(&flags(&d, "outside_project")).all(|f| f["severity"] == "medium"));
}

#[test]
fn demo_fourteen_low_installs() {
    let d = run_demo();
    let inst = flags(&d, "install");
    let count = |prefix: &str| {
        total(
            &inst
                .iter()
                .copied()
                .filter(|f| f["text"].as_str().unwrap().starts_with(prefix))
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!((count("npm install"), count("pip install"), count("cargo add")), (6, 5, 3));
    assert!(inst.iter().all(|f| f["severity"] == "low"));
}

// ---------------------------------------------------------------- privacy

#[test]
fn fake_keys_never_appear_unmasked() {
    let d = run_demo();
    let json = d.json.to_string();
    let keys = demo::fake_keys();
    assert!(keys.len() >= 4);
    // The keys really are in the logs (in commands, prompts and tool output).
    let logs = all_log_text(&d.dir);
    for k in &keys {
        assert!(logs.contains(k.as_str()), "fixture lost a key");
        for (name, out) in [("terminal", &d.term), ("html", &d.html), ("json", &json), ("stderr", &d.stderr)]
        {
            assert!(!out.contains(k.as_str()), "{name} shows a key unmasked");
            assert!(!out.contains(&k[k.len() - 12..]), "{name} shows the end of a key");
        }
    }
}

#[test]
fn prompts_and_tool_output_are_never_shown() {
    let d = run_demo();
    let logs = all_log_text(&d.dir);
    let json = d.json.to_string();
    for marker in [demo::PROMPT_MARKER, demo::OUTPUT_MARKER] {
        assert!(logs.contains(marker), "fixture lost {marker}");
        for out in [&d.term, &d.html, &json, &d.stderr] {
            assert!(!out.contains(marker), "{marker} leaked");
        }
    }
    // The .env contents read by `cat .env` stay out too.
    assert!(!d.term.contains("TELEGRAM_BOT_TOKEN") && !d.html.contains("TELEGRAM_BOT_TOKEN"));
}

#[test]
fn demo_prints_no_path_outside_its_folder() {
    let d = run_demo();
    let dir = d.dir.to_str().unwrap();
    assert!(d.dir.ends_with("demo"));
    let json = d.json.to_string();
    for (name, out) in [("terminal", d.term.as_str()), ("html", &d.html), ("json", &json)] {
        assert!(!out.contains("/home/"), "{name} shows a home path");
        assert!(!out.contains(dir), "{name} shows the demo folder");
        let tmp = std::env::temp_dir();
        assert!(!out.contains(tmp.to_str().unwrap().trim_end_matches('/')), "{name} shows a temp path");
    }
    // Only the first line names the demo folder.
    let lines: Vec<&str> = d.stderr.lines().collect();
    assert_eq!(lines.len(), 1);
    // HOME is the test's temp folder here, so the demo folder shows as `~/demo`.
    assert!(lines[0].starts_with("tattle: demo home written to ~/demo (fake logs, fake keys), HTML report: "));
}

fn all_log_text(dir: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out.push_str(&fs::read_to_string(p).unwrap());
            }
        }
    }
    out
}

// ---------------------------------------------------------------- parsing

#[test]
fn claude_parser_tolerates_bad_lines() {
    let tmp = Tmp::new();
    demo::write_logs(&tmp.0, demo::USER_HOME).unwrap();
    let f = first_file(&tmp.0.join(".claude/projects"));
    let good = fs::read_to_string(&f).unwrap();
    let call = good.lines().find(|l| l.contains("\"tool_use\"")).unwrap();
    let broken = [
        "not json at all",
        &call[..call.len() / 2],                             // truncated
        r#"{"type":"brand-new-line-type","sessionId":"x"}"#, // unknown type
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t","name":"Bash","input":{}}]}}"#, // missing fields
        r#"[1,2,3]"#,
        r#"{"type":"assistant","timestamp":7,"message":{"content":"text"}}"#, // odd field types: kept, harmless
    ];
    let mut skipped = 0;
    let base = tattle::logs::parse_claude(good.as_bytes(), "s", &mut skipped).unwrap();
    assert_eq!(skipped, 0);
    let mixed = format!("{}\n{good}{}", broken.join("\n"), &call[..40]);
    let s = tattle::logs::parse_claude(mixed.as_bytes(), "s", &mut skipped).unwrap();
    assert_eq!(skipped, 6, "5 bad lines + the truncated last line");
    assert_eq!(s.events.len(), base.events.len());
    // Invalid UTF-8 and empty input never panic.
    tattle::logs::parse_claude(&b"\xff\xfe{\n\n"[..], "s", &mut skipped);
    assert!(tattle::logs::parse_claude(&b""[..], "s", &mut 0).is_none());
}

#[test]
fn codex_parser_tolerates_bad_lines_and_reads_old_format() {
    let mut skipped = 0;
    let old = [
        r#"{"timestamp":"2026-10-28T10:00:00Z","type":"session_meta","payload":{"id":"old","cwd":"/home/me/p","timestamp":"2026-10-28T10:00:00Z"}}"#,
        r#"{"timestamp":"2026-10-28T10:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":[\"bash\",\"-lc\",\"rm -rf build && git push -f\"]}"}}"#,
        r#"{"timestamp":"2026-10-28T10:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":[\"bash\",\"-lc\",\"rm -rf build && git push -f\"]}"}}"#,
        r#"{"timestamp":"2026-10-28T10:00:02Z","type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","call_id":"c2","input":"*** Begin Patch\n*** Update File: /home/me/.zshrc\n@@\n-a\n+b\n*** End Patch"}}"#,
        r#"{"timestamp":"2026-10-28T10:00:03Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c3","arguments":"{not json"}}"#,
        r#"{"timestamp":"2026-10-28T10:00:04Z","type":"mystery","payload":{}}"#,
        r#"{"timestamp":"2026-10-28T10:00:05Z","type":"event_msg"}"#,
        r#"{"timestamp":"2026-10-28T10:00:06Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"i"#,
    ]
    .join("\n");
    let s = tattle::logs::parse_codex(old.as_bytes(), "x", &mut skipped).unwrap();
    assert_eq!(skipped, 4);
    assert_eq!(s.id, "old");
    use tattle::logs::What;
    assert_eq!(s.events.len(), 2, "duplicate call_id counted once");
    assert_eq!(s.events[0].what, What::Command("rm -rf build && git push -f".into()));
    assert_eq!(s.events[1].what, What::Write { tool: "apply_patch".into(), path: "/home/me/.zshrc".into() });

    // Newer logs log every call twice; only the items count.
    let tmp = Tmp::new();
    demo::write_logs(&tmp.0, demo::USER_HOME).unwrap();
    let f = first_file(&tmp.0.join(".codex/sessions"));
    let text = fs::read_to_string(f).unwrap();
    let mut sk = 0;
    let s = tattle::logs::parse_codex(text.as_bytes(), "x", &mut sk).unwrap();
    let cmds = s.events.iter().filter(|e| matches!(e.what, What::Command(_))).count();
    assert_eq!(cmds, text.matches("\"CommandExecution\"").count());
    assert_eq!(sk, 0);
    assert!(s.sandbox.is_some() && s.approval.is_some());
}

fn first_file(dir: &Path) -> PathBuf {
    let mut stack = vec![dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap().flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                files.push(e.path());
            }
        }
    }
    files.sort();
    files.remove(0)
}

// ---------------------------------------------------------------- CLI

#[test]
fn home_flag_reads_logs_there_and_shows_it_as_tilde() {
    let tmp = Tmp::new();
    let home = tmp.0.join("someone");
    demo::write_logs(&home, home.to_str().unwrap()).unwrap();
    let out = tattle(&["--home", home.to_str().unwrap(), "--all", "--json"], &tmp.0);
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["commands"], 1412);
    let text = json.to_string();
    assert!(!text.contains(home.to_str().unwrap()), "home must print as ~");
    assert!(text.contains("\"~/code/blog\"") && text.contains("Edit ~/.bashrc"));
    // The default 7-day window ends today, long before the demo week.
    let recent = tattle(&["--home", home.to_str().unwrap(), "--json"], &tmp.0);
    let recent: Value = serde_json::from_slice(&recent.stdout).unwrap();
    assert!(recent["commands"].as_u64().unwrap() <= 1412);
}

#[test]
fn exit_code_one_only_with_a_critical_flag() {
    let d = run_demo();
    assert_eq!(d.code, Some(1));
    let tmp = Tmp::new();
    demo::write_logs(&tmp.0, demo::USER_HOME).unwrap();
    // Without the two critical sessions' projects, nothing is critical.
    let calm =
        tattle(&["--home", tmp.0.to_str().unwrap(), "--all", "--project", "/home/me/dotfiles"], &tmp.0);
    assert_eq!(calm.status.code(), Some(0), "{}", String::from_utf8_lossy(&calm.stderr));
    let min = tattle(&["--home", tmp.0.to_str().unwrap(), "--all", "--min", "high", "--json"], &tmp.0);
    assert_eq!(min.status.code(), Some(1));
    let j: Value = serde_json::from_slice(&min.stdout).unwrap();
    assert_eq!(j["by_severity"]["low"], 0);
    assert_eq!(j["by_severity"]["critical"], 2);
}

#[test]
fn usage_errors_exit_two() {
    let tmp = Tmp::new();
    for args in
        [&["--bogus"][..], &["--days", "x"], &["--min", "huge"], &["--html"], &["demo", "d", "--home", "h"]]
    {
        assert_eq!(tattle(args, &tmp.0).status.code(), Some(2), "{args:?}");
    }
    // Missing logs are not an error: an empty receipt.
    let empty = tattle(&["--home", tmp.0.to_str().unwrap()], &tmp.0);
    assert_eq!(empty.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&empty.stdout).contains("No Claude Code or Codex sessions"));
}

#[test]
fn demo_refuses_a_folder_with_real_agent_logs() {
    let tmp = Tmp::new();
    fs::create_dir_all(tmp.0.join(".claude/projects/x")).unwrap();
    fs::write(tmp.0.join(".claude/projects/x/keep.jsonl"), "{}\n").unwrap();
    let out = tattle(&["demo", tmp.0.to_str().unwrap()], &tmp.0);
    assert_eq!(out.status.code(), Some(2));
    assert!(tmp.0.join(".claude/projects/x/keep.jsonl").exists(), "nothing of the user's is touched");
    // A demo folder can be written again: same numbers.
    let dir = tmp.0.join("again");
    for _ in 0..2 {
        let out = tattle(&["demo", dir.to_str().unwrap(), "--json"], &tmp.0);
        let j: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(j["commands"], 1412);
    }
}

#[test]
fn html_is_self_contained_with_still_mode() {
    let d = run_demo();
    for banned in ["<link", "src=", "http://", "@import", "url("] {
        assert!(!d.html.contains(banned), "{banned}");
    }
    assert!(d.html.contains("location.hash === '#still'"));
    assert!(d.html.contains("How to stop it"));
    assert!(d.html.contains("<code>&quot;Bash(git push --force:*)&quot;</code>"));
    let banned_text = ['\u{2014}'];
    assert!(!d.html.contains(banned_text[0]) && !d.term.contains(banned_text[0]));
}
