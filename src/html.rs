//! Self-contained HTML receipt: no external fonts, scripts or images, so it
//! opens offline and makes no network requests. Phone-first, Keyleak's
//! layout and count-up; `#still` shows the final frame at once.

use crate::report::Report;
use crate::rules::{Kind, Severity};
use crate::term::{group, plural};
use crate::time;
use std::fmt::Write;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(ch),
        }
    }
    o
}

/// Backtick spans in fix text as inline code.
fn rich(s: &str) -> String {
    esc(s)
        .split('`')
        .enumerate()
        .map(|(i, part)| if i % 2 == 1 { format!("<code>{part}</code>") } else { part.to_string() })
        .collect()
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
    }
}

pub fn render(rep: &Report) -> String {
    let mut cards = String::new();
    for f in &rep.flags {
        let failed = match f.failed {
            0 => String::new(),
            n if n == f.count => " · <b class=\"failed\">failed</b>".into(),
            n => format!(" · <b class=\"failed\">{n} failed</b>"),
        };
        let _ = write!(
            cards,
            r#"<article class="card {sc}">
  <header><span class="badge">{sev}</span><h2>{kind}</h2><span class="count">×{n}</span></header>
  <code class="cmd">{text}</code>
  <div class="meta"><span class="proj">{project}</span><span>{agent} · {time}{failed}</span></div>
  <div class="fix"><h3>How to stop it</h3><p>{fix}</p></div>
</article>
"#,
            sc = sev_class(f.severity),
            sev = f.severity.label(),
            kind = esc(f.kind.label()),
            n = f.count,
            text = esc(&f.text),
            project = esc(&f.project),
            agent = f.agent.label(),
            time = time::short(f.first_ts),
            fix = rich(&f.fix),
        );
    }

    let mut chips = String::new();
    for s in Severity::ALL {
        let n = rep.by_severity.get(s);
        if n > 0 {
            let _ = write!(
                chips,
                "<span class=\"chip {}\"><i></i>{n} {}</span>",
                sev_class(s),
                s.label().to_lowercase()
            );
        }
    }
    let kinds: String = Kind::ALL
        .iter()
        .filter_map(|k| {
            rep.by_kind
                .get(k.id())
                .filter(|&&n| n > 0)
                .map(|n| format!("<span>{} <b>{n}</b></span>", k.label()))
        })
        .collect();
    let agents: String = rep
        .by_agent
        .iter()
        .map(|(a, s)| {
            format!(
                "<span>{} <b>{}</b> · {}</span>",
                a.label(),
                group(s.commands),
                plural(s.sessions, "session")
            )
        })
        .collect();
    let mut sessions = String::new();
    for s in &rep.session_list {
        let policy = match (&s.sandbox, &s.approval) {
            (None, None) => String::new(),
            (sb, ap) => format!(
                "<small>sandbox {} · approval {}</small>",
                esc(sb.as_deref().unwrap_or("?")),
                esc(ap.as_deref().unwrap_or("?"))
            ),
        };
        let _ = write!(
            sessions,
            "<li><span class=\"who\">{}</span><span class=\"proj\">{}</span><span class=\"when\">{}</span><b>{}</b>{policy}</li>",
            s.agent.label(),
            esc(&s.project),
            time::short(s.started_ts),
            plural(s.commands, "command"),
        );
    }

    let n = rep.commands;
    let flagged = rep.by_severity.total();
    let sub = format!(
        "{} across {}, {}. {}.",
        plural(rep.sessions, "session"),
        plural(rep.projects, "project"),
        esc(&rep.window.label),
        if flagged == 0 {
            "Nothing risky found".to_string()
        } else {
            format!("{flagged} flagged, ranked by risk")
        }
    );
    TEMPLATE
        .replace("{{N}}", &n.to_string())
        .replace("{{NG}}", &group(n))
        .replace("{{HEADLINE}}", if n == 1 { "command your agents ran" } else { "commands your agents ran" })
        .replace("{{SUB}}", &sub)
        .replace(
            "{{TOP}}",
            &format!(
                "{} · {} · {} · {}",
                plural(rep.sessions, "session"),
                plural(rep.agents, "agent"),
                plural(rep.projects, "project"),
                esc(&rep.window.label)
            ),
        )
        .replace("{{WRITES}}", &plural(rep.file_writes, "file write"))
        .replace("{{SKIPPED}}", &plural(rep.skipped_lines, "log line"))
        .replace("{{VERSION}}", rep.version)
        .replace("{{CHIPS}}", &chips)
        .replace("{{KINDS}}", if kinds.is_empty() { "<span>none</span>" } else { &kinds })
        .replace("{{AGENTS}}", &agents)
        .replace("{{SESSIONS}}", &sessions)
        .replace("{{CARDS}}", &cards)
}

const TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Tattle report</title>
<style>
:root {
  --bg: #0a0b0e; --panel: #12141a; --line: #23262f; --text: #e8e9ed; --dim: #8b8f9c;
  --amber: #ffb020; --crit: #ff3b4e; --high: #ff8a3d; --med: #ffcc4d; --low: #5aa9ff; --ok: #33d69f;
  --mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; color: var(--text); font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
main { max-width: 760px; margin: 0 auto; padding: 32px 20px 56px; }
.top { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; color: var(--dim); font-size: 13px; }
.logo { background: var(--amber); color: #0a0b0e; font-weight: 800; letter-spacing: .08em; padding: 3px 8px; border-radius: 6px; font-size: 12px; }
.hero { padding: 28px 0 24px; border-bottom: 1px solid var(--line); }
.big { font-size: clamp(96px, 32vw, 196px); line-height: .9; font-weight: 900; letter-spacing: -.045em; color: var(--amber); text-shadow: 0 0 60px rgba(255,176,32,.38); font-variant-numeric: tabular-nums; white-space: nowrap; }
.headline { font-size: clamp(26px, 6.4vw, 40px); font-weight: 800; letter-spacing: -.02em; line-height: 1.15; margin-top: 10px; }
.sub { color: var(--dim); margin-top: 6px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 18px; }
.chip { display: inline-flex; align-items: center; gap: 7px; padding: 5px 10px; border-radius: 999px; background: var(--panel); border: 1px solid var(--line); font-weight: 600; font-size: 13px; white-space: nowrap; }
.chip i { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.chip.crit { color: var(--crit); } .chip.high { color: var(--high); } .chip.med { color: var(--med); } .chip.low { color: var(--low); }
.sums { display: grid; grid-template-columns: 84px 1fr; gap: 6px 14px; margin: 20px 0 4px; font-size: 14px; }
.sums dt { color: var(--dim); }
.sums dd { margin: 0; display: flex; flex-wrap: wrap; gap: 2px 14px; }
.sums b { color: var(--text); font-variant-numeric: tabular-nums; }
.sums span { color: var(--dim); }
.card { background: var(--panel); border: 1px solid var(--line); box-shadow: inset 4px 0 0 var(--c); border-radius: 14px; padding: 16px 18px 16px 20px; margin-top: 14px; opacity: 0; transform: translateY(10px); animation: in .45s ease forwards; }
.card.crit { --c: var(--crit); } .card.high { --c: var(--high); } .card.med { --c: var(--med); } .card.low { --c: var(--low); }
@keyframes in { to { opacity: 1; transform: none; } }
.card header { display: flex; align-items: center; gap: 10px; }
.card h2 { font-size: 16px; margin: 0; font-weight: 700; flex: 1; min-width: 0; }
.badge { font-size: 11px; font-weight: 800; letter-spacing: .08em; padding: 3px 8px; border-radius: 6px; color: #0a0b0e; background: var(--c); }
.count { font-weight: 800; font-size: 17px; color: var(--c); font-variant-numeric: tabular-nums; }
.cmd { display: block; margin-top: 10px; font: 600 14px/1.45 var(--mono); color: var(--c); background: #0c0d11; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
.meta { display: flex; flex-wrap: wrap; gap: 2px 14px; margin-top: 8px; font-size: 13px; color: var(--dim); }
.meta > span { white-space: nowrap; }
.proj { font-family: var(--mono); color: var(--low); }
.meta .proj { font-size: 12.5px; }
.failed { color: var(--c); font-weight: 700; }
.fix { margin-top: 14px; padding-top: 12px; border-top: 1px dashed var(--line); }
.fix h3 { margin: 0 0 4px; font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--ok); }
.fix p { margin: 0; font-size: 14px; }
.fix code { display: inline-block; max-width: 100%; font: 12.5px/1.5 var(--mono); background: rgba(255,255,255,.06); padding: 0 5px; border-radius: 4px; overflow-wrap: anywhere; vertical-align: bottom; }
h4 { margin: 36px 0 8px; font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--dim); }
.sessions { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--line); font-size: 13px; }
.sessions li { display: grid; grid-template-columns: 92px 1fr auto; gap: 2px 10px; padding: 9px 0; border-bottom: 1px solid var(--line); }
.sessions .who { color: var(--text); font-weight: 600; }
.sessions .when { color: var(--dim); text-align: right; }
.sessions b { grid-column: 2; font-weight: 500; color: var(--dim); font-variant-numeric: tabular-nums; }
.sessions small { grid-column: 2 / 4; color: var(--dim); font-size: 12px; }
footer { margin-top: 32px; color: var(--dim); font-size: 12.5px; text-align: center; line-height: 1.6; }
@media (max-width: 520px) { main { padding: 24px 16px 44px; } .card { padding: 14px 14px 14px 18px; } }
.still .card { animation: none; opacity: 1; transform: none; }
@media (prefers-reduced-motion: reduce) { .card { animation: none; opacity: 1; transform: none; } }
</style>
</head>
<body>
<main>
  <div class="top"><span class="logo">TATTLE</span><span>{{TOP}} · offline, read-only</span></div>
  <section class="hero">
    <div class="big" id="n" data-n="{{N}}">{{NG}}</div>
    <div class="headline">{{HEADLINE}}</div>
    <div class="sub">{{SUB}} Plus {{WRITES}}.</div>
    <div class="chips">{{CHIPS}}</div>
    <dl class="sums"><dt>By kind</dt><dd>{{KINDS}}</dd><dt>By agent</dt><dd>{{AGENTS}}</dd></dl>
  </section>
  {{CARDS}}
  <h4>Sessions</h4>
  <ul class="sessions">{{SESSIONS}}</ul>
  <footer>Read-only and offline. Prompts, replies and tool output are never read; secrets are masked.<br>Times in UTC · {{SKIPPED}} skipped · Tattle {{VERSION}} · MIT</footer>
</main>
<script>
(function () {
  var el = document.getElementById('n'), n = +el.dataset.n;
  function fmt(v) { return v.toLocaleString('en-US'); }
  // #still: final frame right away (screenshots, printing).
  if (location.hash === '#still') { document.body.classList.add('still'); return; }
  if (!n || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var t0 = null, dur = Math.min(1800, 400 + n * 40);
  function step(t) {
    t0 = t0 || t;
    var p = Math.min(1, (t - t0) / dur);
    el.textContent = fmt(Math.round(n * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(step);
  }
  el.textContent = '0';
  requestAnimationFrame(step);
  document.querySelectorAll('.card').forEach(function (c, i) { c.style.animationDelay = (0.2 + i * 0.06) + 's'; });
})();
</script>
</body>
</html>
"#;
