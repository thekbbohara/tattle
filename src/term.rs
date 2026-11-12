//! Coloured terminal receipt, in Keyleak's style.

use crate::report::{Flag, Report};
use crate::rules::{Kind, Severity};
use crate::time;
use std::fmt::Write;

pub struct Style {
    pub color: bool,
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[38;5;196m";
const ORANGE: &str = "\x1b[38;5;208m";
const YELLOW: &str = "\x1b[38;5;220m";
const BLUE: &str = "\x1b[38;5;75m";
const GREEN: &str = "\x1b[38;5;48m";
const GREY: &str = "\x1b[38;5;245m";
/// Tattle amber, #FFB020.
const AMBER: &str = "\x1b[38;2;255;176;32m";
const BG_AMBER: &str = "\x1b[48;2;255;176;32m\x1b[38;5;16m";

/// Commands longer than this are cut with `…` (the JSON and HTML keep all).
const MAX_TEXT: usize = 96;

/// 3x5 pixel digits; each pixel is drawn two cells wide.
const DIGITS: [[&str; 5]; 10] = [
    ["###", "# #", "# #", "# #", "###"],
    [" # ", "## ", " # ", " # ", "###"],
    ["###", "  #", "###", "#  ", "###"],
    ["###", "  #", "###", "  #", "###"],
    ["# #", "# #", "###", "  #", "  #"],
    ["###", "#  ", "###", "  #", "###"],
    ["###", "#  ", "###", "# #", "###"],
    ["###", "  #", "  #", "  #", "  #"],
    ["###", "# #", "###", "# #", "###"],
    ["###", "# #", "###", "  #", "###"],
];
const COMMA: [&str; 5] = [" ", " ", " ", "#", "#"];

fn big_number(n: usize) -> [String; 5] {
    let mut rows: [String; 5] = Default::default();
    for (i, ch) in group(n).chars().enumerate() {
        let g = match ch.to_digit(10) {
            Some(d) => &DIGITS[d as usize],
            None => &COMMA,
        };
        for (r, row) in rows.iter_mut().enumerate() {
            if i > 0 {
                row.push_str("  ");
            }
            for px in g[r].chars() {
                row.push_str(if px == '#' { "██" } else { "  " });
            }
        }
    }
    rows
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => RED,
        Severity::High => ORANGE,
        Severity::Medium => YELLOW,
        Severity::Low => BLUE,
    }
}

pub fn plural(n: usize, word: &str) -> String {
    format!("{} {word}{}", group(n), if n == 1 { "" } else { "s" })
}

pub fn render(rep: &Report, st: &Style) -> String {
    let c = |code: &'static str| if st.color { code } else { "" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "\n  {}{} TATTLE {}  {}{} · {} · {} · {} · offline, read-only{}\n",
        c(BOLD),
        c(BG_AMBER),
        c(RESET),
        c(GREY),
        plural(rep.sessions, "session"),
        plural(rep.agents, "agent"),
        plural(rep.projects, "project"),
        rep.window.label,
        c(RESET)
    );
    if rep.sessions == 0 {
        let _ = writeln!(o, "  No Claude Code or Codex sessions in this window.\n");
        footer(&mut o, rep, &c);
        return o;
    }

    let rows = big_number(rep.commands);
    let side = [
        String::new(),
        format!("{}{}{}", c(BOLD), if rep.commands == 1 { "COMMAND" } else { "COMMANDS" }, c(RESET)),
        format!("{}run by your agents{}", c(GREY), c(RESET)),
        format!("{}+ {}{}", c(GREY), plural(rep.file_writes, "file write"), c(RESET)),
        String::new(),
    ];
    for (r, row) in rows.iter().enumerate() {
        let _ = writeln!(o, "  {}{}{}{}   {}", c(BOLD), c(AMBER), row, c(RESET), side[r]);
    }
    o.push('\n');

    if rep.by_severity.total() == 0 {
        let _ = writeln!(o, "  {}{}✔ Nothing risky found.{}\n", c(BOLD), c(GREEN), c(RESET));
    } else {
        let chips: Vec<String> = Severity::ALL
            .iter()
            .filter(|&&s| rep.by_severity.get(s) > 0)
            .map(|&s| {
                let n = rep.by_severity.get(s);
                format!("{}{}● {} {}{}", c(BOLD), c(sev_color(s)), n, s.label().to_lowercase(), c(RESET))
            })
            .collect();
        let _ = writeln!(o, "  {}\n", chips.join("   "));
        for f in &rep.flags {
            flag(&mut o, f, &c);
        }
    }

    sessions(&mut o, rep, &c);
    let kinds: Vec<String> = Kind::ALL
        .iter()
        .filter_map(|k| rep.by_kind.get(k.id()).filter(|&&n| n > 0).map(|n| format!("{} {n}", k.label())))
        .collect();
    let agents: Vec<String> = rep
        .by_agent
        .iter()
        .map(|(a, s)| {
            format!("{} {}, {}", a.label(), plural(s.sessions, "session"), plural(s.commands, "command"))
        })
        .collect();
    if !kinds.is_empty() {
        let _ = writeln!(o, "  {}By kind{}   {}", c(BOLD), c(RESET), kinds.join(" · "));
    }
    let _ = writeln!(o, "  {}By agent{}  {}", c(BOLD), c(RESET), agents.join(" · "));
    footer(&mut o, rep, &c);
    o
}

fn flag(o: &mut String, f: &Flag, c: &dyn Fn(&'static str) -> &'static str) {
    let col = c(sev_color(f.severity));
    let count = if f.count > 1 { format!("  {}×{}{}", c(GREY), f.count, c(RESET)) } else { String::new() };
    let _ = writeln!(
        o,
        "  {}{}{:<8}{}  {}{}{}{}",
        c(BOLD),
        col,
        f.severity.label(),
        c(RESET),
        c(BOLD),
        cut(&f.text, MAX_TEXT),
        c(RESET),
        count
    );
    let failed = match f.failed {
        0 => String::new(),
        n if n == f.count => format!(" · {}{}failed{}", c(BOLD), col, c(RESET)),
        n => format!(" · {}{}{n} failed{}", c(BOLD), col, c(RESET)),
    };
    let _ = writeln!(
        o,
        "            {}{} · {} · {} · {}{}{}",
        c(GREY),
        f.kind.label(),
        f.project,
        f.agent.label(),
        time::short(f.first_ts),
        c(RESET),
        failed
    );
    let _ = writeln!(o, "            {}Stop it{}  {}\n", c(GREEN), c(RESET), code(&f.fix, c));
}

fn sessions(o: &mut String, rep: &Report, c: &dyn Fn(&'static str) -> &'static str) {
    let _ = writeln!(o, "  {}Sessions{}", c(BOLD), c(RESET));
    let w_agent = rep.session_list.iter().map(|s| s.agent.label().len()).max().unwrap_or(0);
    let w_proj = rep.session_list.iter().map(|s| s.project.chars().count()).max().unwrap_or(0);
    for s in &rep.session_list {
        let policy = match (&s.sandbox, &s.approval) {
            (None, None) => String::new(),
            (sb, ap) => format!(
                "  {}sandbox {} · approval {}{}",
                c(DIM),
                sb.as_deref().unwrap_or("?"),
                ap.as_deref().unwrap_or("?"),
                c(RESET)
            ),
        };
        let _ = writeln!(
            o,
            "    {:<wa$}  {}{:<wp$}{}  {}{}{}  {:>12}{}",
            s.agent.label(),
            c(BLUE),
            s.project,
            c(RESET),
            c(GREY),
            time::short(s.started_ts),
            c(RESET),
            plural(s.commands, "command"),
            policy,
            wa = w_agent,
            wp = w_proj
        );
    }
    o.push('\n');
}

fn footer(o: &mut String, rep: &Report, c: &dyn Fn(&'static str) -> &'static str) {
    let _ = writeln!(
        o,
        "\n  {}Read-only and offline. Prompts, replies and tool output are never read; secrets are masked.\n  Times in UTC. {} skipped (unreadable or unknown format).{}\n",
        c(DIM),
        plural(rep.skipped_lines, "log line"),
        c(RESET)
    );
}

/// Backtick spans in fix text, drawn bold instead of quoted.
fn code(s: &str, c: &dyn Fn(&'static str) -> &'static str) -> String {
    s.split('`')
        .enumerate()
        .map(|(i, part)| if i % 2 == 1 { format!("{}{part}{}", c(BOLD), c(RESET)) } else { part.to_string() })
        .collect()
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max - 1).collect::<String>() + "…"
    }
}

pub fn group(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn grouping_and_digits() {
        assert_eq!(super::group(1412), "1,412");
        assert_eq!(super::group(12), "12");
        assert_eq!(super::big_number(1412)[4], "██████  ██      ██  ██████  ██████");
        assert_eq!(super::cut("abcdef", 4), "abc…");
    }
}
