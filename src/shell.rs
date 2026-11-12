//! A light, quote-aware shell splitter. Not a shell grammar: enough to cut
//! `a && rm -rf x; echo $(sudo id)` into simple commands and to find their
//! redirection targets. The receipt always shows the original line.

/// One simple command: words after quote removal, plus its redirections.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Simple {
    pub words: Vec<String>,
    /// Targets of `>`, `>>`, `>|`, `&>` (fd duplications like `2>&1` are not).
    pub writes: Vec<String>,
    /// Sources of `<`.
    pub reads: Vec<String>,
    /// Fed by `|` from the previous command at the same depth.
    pub piped: bool,
    /// Nesting level: 0 at top level, +1 inside `$(...)`, backticks, `<(...)`.
    pub depth: usize,
}

enum Redir {
    Write,
    Read,
    Heredoc(bool),
    Skip,
}

/// Split `script` into simple commands, in the order they appear. Commands
/// inside `$(...)` come before the command that uses their output.
pub fn split(script: &str) -> Vec<Simple> {
    let chars: Vec<char> = script.chars().collect();
    let mut p = Parser { c: &chars, out: Vec::new() };
    p.run(&mut 0, None, 0);
    p.out
}

struct Parser<'a> {
    c: &'a [char],
    out: Vec<Simple>,
}

struct State {
    cur: Simple,
    word: Option<String>,
    redir: Option<Redir>,
    heredocs: Vec<(String, bool)>,
    depth: usize,
}

impl State {
    fn word(&mut self) -> &mut String {
        self.word.get_or_insert_with(String::new)
    }

    fn end_word(&mut self) {
        let Some(w) = self.word.take() else { return };
        match self.redir.take() {
            Some(Redir::Write) => self.cur.writes.push(w),
            Some(Redir::Read) => self.cur.reads.push(w),
            Some(Redir::Heredoc(strip)) => self.heredocs.push((w, strip)),
            Some(Redir::Skip) => {}
            None => self.cur.words.push(w),
        }
    }

    /// The current word is a file descriptor number (`2>`): drop it.
    fn end_word_before_redirect(&mut self) {
        if self.word.as_deref().is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit())) {
            self.word = None;
        } else {
            self.end_word();
        }
    }

    fn end_cmd(&mut self, out: &mut Vec<Simple>, piped_next: bool) {
        self.end_word();
        self.redir = None;
        let next = Simple { piped: piped_next, depth: self.depth, ..Default::default() };
        let cur = std::mem::replace(&mut self.cur, next);
        if !cur.words.is_empty() || !cur.writes.is_empty() || !cur.reads.is_empty() {
            out.push(cur);
        }
    }
}

impl Parser<'_> {
    /// Parse until `close` (or the end), pushing simple commands to `out`.
    fn run(&mut self, i: &mut usize, close: Option<char>, depth: usize) {
        let c = self.c;
        let mut st = State {
            cur: Simple { depth, ..Default::default() },
            word: None,
            redir: None,
            heredocs: Vec::new(),
            depth,
        };
        while *i < c.len() {
            let ch = c[*i];
            let next = c.get(*i + 1).copied();
            if Some(ch) == close {
                *i += 1;
                st.end_cmd(&mut self.out, false);
                return;
            }
            match ch {
                ' ' | '\t' | '\r' => {
                    st.end_word();
                    *i += 1;
                }
                '\n' => {
                    st.end_cmd(&mut self.out, false);
                    *i += 1;
                    self.skip_heredocs(i, &mut st.heredocs);
                }
                ';' => {
                    st.end_cmd(&mut self.out, false);
                    *i += 1;
                }
                '&' => match next {
                    Some('>') => {
                        st.end_word();
                        *i += 2;
                        if c.get(*i) == Some(&'>') {
                            *i += 1;
                        }
                        st.redir = Some(Redir::Write);
                    }
                    Some('&') => {
                        st.end_cmd(&mut self.out, false);
                        *i += 2;
                    }
                    _ => {
                        st.end_cmd(&mut self.out, false);
                        *i += 1;
                    }
                },
                '|' => match next {
                    Some('|') => {
                        st.end_cmd(&mut self.out, false);
                        *i += 2;
                    }
                    Some('&') => {
                        st.end_cmd(&mut self.out, true);
                        *i += 2;
                    }
                    _ => {
                        st.end_cmd(&mut self.out, true);
                        *i += 1;
                    }
                },
                '>' => {
                    st.end_word_before_redirect();
                    *i += 1;
                    match c.get(*i) {
                        Some('>' | '|') => {
                            *i += 1;
                            st.redir = Some(Redir::Write);
                        }
                        Some('&') => {
                            *i += 1;
                            if !self.skip_fd(i) {
                                st.redir = Some(Redir::Write);
                            }
                        }
                        Some('(') => self.substitute(i, &mut st, 1),
                        _ => st.redir = Some(Redir::Write),
                    }
                }
                '<' => {
                    st.end_word_before_redirect();
                    *i += 1;
                    match c.get(*i) {
                        Some('<') => {
                            *i += 1;
                            if c.get(*i) == Some(&'<') {
                                *i += 1;
                                st.redir = Some(Redir::Skip);
                            } else {
                                let strip = c.get(*i) == Some(&'-');
                                *i += usize::from(strip);
                                st.redir = Some(Redir::Heredoc(strip));
                            }
                        }
                        Some('&') => {
                            *i += 1;
                            self.skip_fd(i);
                        }
                        Some('(') => self.substitute(i, &mut st, 1),
                        Some('>') => {
                            *i += 1;
                            st.redir = Some(Redir::Write);
                        }
                        _ => st.redir = Some(Redir::Read),
                    }
                }
                '(' if st.word.is_none() => {
                    st.end_cmd(&mut self.out, false);
                    *i += 1;
                    self.run(i, Some(')'), depth);
                }
                '#' if st.word.is_none() => {
                    while *i < c.len() && c[*i] != '\n' {
                        *i += 1;
                    }
                }
                '\\' => {
                    if let Some(n) = next.filter(|&n| n != '\n') {
                        st.word().push(n);
                    }
                    *i += 2;
                }
                '\'' => {
                    *i += 1;
                    let w = st.word();
                    while *i < c.len() && c[*i] != '\'' {
                        w.push(c[*i]);
                        *i += 1;
                    }
                    *i += 1;
                }
                '"' => {
                    *i += 1;
                    self.double_quoted(i, &mut st);
                }
                '$' if next == Some('(') => self.dollar_paren(i, &mut st),
                '$' if next == Some('{') => {
                    let w = st.word.get_or_insert_with(String::new);
                    while *i < c.len() {
                        w.push(c[*i]);
                        *i += 1;
                        if c[*i - 1] == '}' {
                            break;
                        }
                    }
                }
                '`' => self.substitute(i, &mut st, 0),
                _ => {
                    st.word().push(ch);
                    *i += 1;
                }
            }
        }
        st.end_cmd(&mut self.out, false);
    }

    fn double_quoted(&mut self, i: &mut usize, st: &mut State) {
        let c = self.c;
        st.word();
        while *i < c.len() && c[*i] != '"' {
            match c[*i] {
                '\\' => {
                    match c.get(*i + 1) {
                        Some('\n') => {}
                        Some(&n @ ('"' | '\\' | '$' | '`')) => st.word().push(n),
                        Some(&n) => {
                            st.word().push('\\');
                            st.word().push(n);
                        }
                        None => {}
                    }
                    *i += 2;
                }
                '$' if c.get(*i + 1) == Some(&'(') => self.dollar_paren(i, st),
                '`' => self.substitute(i, st, 0),
                ch => {
                    st.word().push(ch);
                    *i += 1;
                }
            }
        }
        *i += 1;
    }

    /// `$(...)` runs a command; `$((...))` is arithmetic and is kept as text.
    fn dollar_paren(&mut self, i: &mut usize, st: &mut State) {
        let c = self.c;
        if c.get(*i + 2) == Some(&'(') {
            let start = *i;
            let mut open = 0;
            while *i < c.len() {
                match c[*i] {
                    '(' => open += 1,
                    ')' => open -= 1,
                    _ => {}
                }
                *i += 1;
                if open == 0 && c[*i - 1] == ')' {
                    break;
                }
            }
            st.word().extend(&c[start..*i]);
        } else {
            *i += 1;
            self.substitute(i, st, 1);
        }
    }

    /// Parse a nested command list starting at `c[*i]` (backtick, or the `(`
    /// after `$`, `<` or `>`) and keep its raw text in the current word.
    fn substitute(&mut self, i: &mut usize, st: &mut State, back: usize) {
        let start = *i - back;
        let close = if self.c[*i] == '`' { '`' } else { ')' };
        *i += 1;
        self.run(i, Some(close), st.depth + 1);
        let end = (*i).min(self.c.len());
        st.word().extend(&self.c[start..end]);
    }

    /// Skip a `>&2` / `<&-` file descriptor. False if it is a file name.
    fn skip_fd(&mut self, i: &mut usize) -> bool {
        let start = *i;
        while self.c.get(*i).is_some_and(|x| x.is_ascii_digit() || *x == '-') {
            *i += 1;
        }
        *i > start
    }

    fn skip_heredocs(&mut self, i: &mut usize, heredocs: &mut Vec<(String, bool)>) {
        for (delim, strip) in heredocs.drain(..) {
            while *i < self.c.len() {
                let start = *i;
                while *i < self.c.len() && self.c[*i] != '\n' {
                    *i += 1;
                }
                let line: String = self.c[start..*i].iter().collect();
                *i += 1;
                let line = if strip { line.trim_start_matches('\t') } else { &line };
                if line.trim_end_matches('\r') == delim {
                    break;
                }
            }
        }
    }
}

/// Quote words for display when a log stores a command as an argv array.
pub fn join(argv: &[String]) -> String {
    argv.iter()
        .map(|w| {
            let plain =
                !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,~".contains(&b));
            if plain {
                w.clone()
            } else {
                format!("'{}'", w.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<Vec<String>> {
        split(s).into_iter().map(|c| c.words).collect()
    }

    #[test]
    fn operators_quotes_and_substitution() {
        assert_eq!(
            words("a && rm -rf x; echo $(sudo id)"),
            vec![vec!["a"], vec!["rm", "-rf", "x"], vec!["sudo", "id"], vec!["echo", "$(sudo id)"]]
        );
        assert_eq!(
            words(r#"git commit -m "fix: a && b; c" || echo 'it''s'"#),
            vec![vec!["git", "commit", "-m", "fix: a && b; c"], vec!["echo", "its"]]
        );
        let p = split("curl -fsSL https://x.dev/i.sh | sh");
        assert_eq!(p.len(), 2);
        assert!(!p[0].piped && p[1].piped);
        assert_eq!(
            words("echo \"$(whoami) `hostname`\""),
            vec![vec!["whoami"], vec!["hostname"], vec!["echo", "$(whoami) `hostname`"]]
        );
        assert_eq!(words("echo $((1 + 2)) # rm -rf /"), vec![vec!["echo", "$((1 + 2))"]]);
    }

    #[test]
    fn redirections_and_heredocs() {
        let c = split("echo hi >> ~/.bashrc 2>/dev/null; sort < in.txt > out.txt 2>&1");
        assert_eq!(c[0].words, vec!["echo", "hi"]);
        assert_eq!(c[0].writes, vec!["~/.bashrc", "/dev/null"]);
        assert_eq!(c[1].reads, vec!["in.txt"]);
        assert_eq!(c[1].writes, vec!["out.txt"]);
        let h = split("cat > notes.md <<'EOF'\nrm -rf /\nsudo reboot\nEOF\nls");
        assert_eq!(h.iter().map(|c| c.words.clone()).collect::<Vec<_>>(), vec![vec!["cat"], vec!["ls"]]);
        assert_eq!(h[0].writes, vec!["notes.md"]);
        assert!(split("").is_empty() && split("  ;; \n").is_empty());
        // Unbalanced input never panics.
        for s in ["echo \"open", "echo $(oops", "a ) b", "x `y", "a <<", "\\"] {
            split(s);
        }
    }
}
