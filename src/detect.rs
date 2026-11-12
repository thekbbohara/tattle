//! Secret detectors. Each detector is one regex; capture group 1 (when present)
//! is the secret, otherwise the whole match is.
//!
//! Vendored from Keyleak (`src/detect.rs`, v0.1.0), so Tattle masks what
//! Keyleak masks. One addition: the `jwt` detector (agent logs often carry
//! JWTs in URLs and headers). Sync both copies together.

use regex::Regex;
use std::sync::OnceLock;

pub struct Detector {
    pub id: &'static str,
    pub name: &'static str,
    pub provider: &'static str,
    pattern: &'static str,
    /// Where to revoke or rotate the key. A link, never an action.
    pub rotate: &'static str,
    /// How many leading characters are safe to show (a public prefix like
    /// `sk-proj-`). `None` picks the prefix up to the first `-`/`_` separator.
    show_prefix: Option<usize>,
    /// -1 lowers the risk (test keys, key IDs without their secret).
    pub risk_adjust: i8,
    /// Generic detectors need extra checks on the value to keep noise down.
    generic: bool,
}

const fn d(
    id: &'static str,
    name: &'static str,
    provider: &'static str,
    pattern: &'static str,
    rotate: &'static str,
) -> Detector {
    Detector { id, name, provider, pattern, rotate, show_prefix: None, risk_adjust: 0, generic: false }
}

const OPENAI: &str = "https://platform.openai.com/api-keys";
const ANTHROPIC: &str = "https://console.anthropic.com/settings/keys";
const GOOGLE: &str = "https://console.cloud.google.com/apis/credentials";
const AWS: &str = "https://console.aws.amazon.com/iam/home#/security_credentials";
const GITHUB: &str = "https://github.com/settings/tokens";
const SLACK: &str = "https://api.slack.com/apps";
const STRIPE: &str = "https://dashboard.stripe.com/apikeys";

pub static DETECTORS: &[Detector] = &[
    d(
        "openai",
        "OpenAI API key",
        "OpenAI",
        r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
        OPENAI,
    ),
    d(
        "anthropic",
        "Anthropic API key",
        "Anthropic",
        r"\bsk-ant-(?:api|admin|oat|ort)\d{2}-[A-Za-z0-9_-]{32,}",
        ANTHROPIC,
    ),
    d(
        "openrouter",
        "OpenRouter API key",
        "OpenRouter",
        r"\bsk-or-v1-[a-f0-9]{64}\b",
        "https://openrouter.ai/settings/keys",
    ),
    Detector {
        show_prefix: Some(4),
        ..d(
            "google",
            "Google / Gemini API key",
            "Google",
            r"\bAIza[0-9A-Za-z_-]{35}",
            "https://aistudio.google.com/apikey  or  https://console.cloud.google.com/apis/credentials",
        )
    },
    d("google-oauth", "Google OAuth client secret", "Google", r"\bGOCSPX-[A-Za-z0-9_-]{28}", GOOGLE),
    Detector {
        show_prefix: Some(4),
        risk_adjust: -1,
        ..d("aws-key-id", "AWS access key ID", "AWS", r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b", AWS)
    },
    Detector {
        show_prefix: Some(0),
        ..d(
            "aws-secret",
            "AWS secret access key",
            "AWS",
            r#"(?i)aws_?secret_?(?:access_?)?key["']?[ \t]*(?:=|:|[ \t])[ \t]*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"#,
            AWS,
        )
    },
    d("github", "GitHub token", "GitHub", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", GITHUB),
    d(
        "github-pat",
        "GitHub fine-grained token",
        "GitHub",
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        "https://github.com/settings/personal-access-tokens",
    ),
    d(
        "gitlab",
        "GitLab token",
        "GitLab",
        r"\bgl(?:pat|dt|rt|ptt|cbt|oas)-[A-Za-z0-9_.-]{20,}",
        "https://gitlab.com/-/user_settings/personal_access_tokens",
    ),
    d("slack", "Slack token", "Slack", r"\bxox[abposr]-[0-9]{6,}-[A-Za-z0-9-]{10,}", SLACK),
    d("slack-app", "Slack app token", "Slack", r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]{32,}", SLACK),
    Detector {
        show_prefix: Some(24),
        ..d(
            "slack-webhook",
            "Slack webhook URL",
            "Slack",
            r"https://hooks\.slack\.com/(?:services|workflows|triggers)/T[A-Z0-9]{6,}/[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",
            SLACK,
        )
    },
    Detector {
        show_prefix: Some(8),
        ..d("stripe", "Stripe live secret key", "Stripe", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b", STRIPE)
    },
    Detector {
        show_prefix: Some(8),
        risk_adjust: -1,
        ..d(
            "stripe-test",
            "Stripe test secret key",
            "Stripe",
            r"\b[sr]k_test_[A-Za-z0-9]{20,}\b",
            "https://dashboard.stripe.com/test/apikeys",
        )
    },
    d(
        "stripe-webhook",
        "Stripe webhook secret",
        "Stripe",
        r"\bwhsec_[A-Za-z0-9]{32,}",
        "https://dashboard.stripe.com/webhooks",
    ),
    Detector {
        show_prefix: Some(0),
        ..d(
            "telegram",
            "Telegram bot token",
            "Telegram",
            r"(?:^|[^0-9A-Za-z_])([0-9]{8,10}:AA[A-Za-z0-9_-]{33})(?:[^A-Za-z0-9_-]|$)",
            "https://t.me/BotFather  (send /revoke)",
        )
    },
    d(
        "huggingface",
        "Hugging Face token",
        "Hugging Face",
        r"\bhf_[A-Za-z0-9]{34,40}\b",
        "https://huggingface.co/settings/tokens",
    ),
    Detector {
        show_prefix: Some(0),
        ..d(
            "deepgram",
            "Deepgram API key",
            "Deepgram",
            r#"(?i)deepgram\w*["']?[ \t]*[:=][ \t]*["']?([a-f0-9]{40})\b"#,
            "https://console.deepgram.com/",
        )
    },
    Detector {
        show_prefix: Some(0),
        ..d(
            "deepgram-curl",
            "Deepgram API key",
            "Deepgram",
            r"(?i)api\.deepgram\.com.{0,300}?\bToken[ \t]+([a-f0-9]{40})\b",
            "https://console.deepgram.com/",
        )
    },
    d(
        "npm",
        "npm access token",
        "npm",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "https://www.npmjs.com/settings/~/tokens",
    ),
    d(
        "pypi",
        "PyPI API token",
        "PyPI",
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
        "https://pypi.org/manage/account/token/",
    ),
    d("groq", "Groq API key", "Groq", r"\bgsk_[A-Za-z0-9]{52}\b", "https://console.groq.com/keys"),
    d("xai", "xAI API key", "xAI", r"\bxai-[A-Za-z0-9]{80}\b", "https://console.x.ai/"),
    d(
        "replicate",
        "Replicate API token",
        "Replicate",
        r"\br8_[A-Za-z0-9]{37}\b",
        "https://replicate.com/account/api-tokens",
    ),
    Detector {
        show_prefix: Some(3),
        ..d(
            "sendgrid",
            "SendGrid API key",
            "SendGrid",
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            "https://app.sendgrid.com/settings/api_keys",
        )
    },
    Detector {
        show_prefix: Some(3),
        ..d(
            "jwt",
            "JSON Web Token",
            "Other",
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}",
            "Revoke the session or token on the service that issued it",
        )
    },
    Detector {
        show_prefix: Some(11),
        ..d(
            "private-key",
            "Private key",
            "SSH / TLS",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            "Generate a new key pair and replace the public key everywhere it is installed",
        )
    },
    Detector {
        show_prefix: Some(0),
        generic: true,
        ..d(
            "url-password",
            "Password in a URL",
            "Other",
            r#"://[A-Za-z0-9._%~+-]{1,64}:([^\s:/@'"`]{6,128})@[A-Za-z0-9.-]"#,
            "Change the password on the service in the URL",
        )
    },
    Detector {
        show_prefix: Some(0),
        generic: true,
        ..d(
            "netrc",
            "Password in .netrc",
            "Other",
            r"(?:^|\s)machine\s+\S+(?:\s+login\s+\S+)?\s+password\s+(\S{6,})",
            "Change the password on the machine named in .netrc",
        )
    },
    Detector {
        show_prefix: Some(0),
        generic: true,
        ..d(
            "bearer",
            "Bearer token",
            "Other",
            r"(?i)\bbearer[ \t]+([A-Za-z0-9_\-.=+/]{24,})",
            "Revoke it on the service it was sent to",
        )
    },
    Detector {
        show_prefix: Some(0),
        generic: true,
        ..d(
            "generic",
            "Secret in a KEY=/TOKEN= assignment",
            "Other",
            r#"(?i)(?:api[_.-]?key|apikey|secret|token|passwd|password|access[_.-]?key|auth[_.-]?key|private[_.-]?key|credentials?|[_.-]key|[_.-]pat)[a-z0-9_.-]{0,20}["']?[ \t]*(?:=|:=|:)[ \t]*["']?([A-Za-z0-9_\-+/=.~!@#%^&*]{12,200})"#,
            "Rotate it on the service it belongs to",
        )
    },
];

fn compiled() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| DETECTORS.iter().map(|d| Regex::new(d.pattern).expect("detector regex")).collect())
}

/// One raw hit inside a file.
pub struct Hit {
    pub detector: usize,
    /// Byte range of the secret in the scanned text.
    pub start: usize,
    pub end: usize,
}

/// Find all secrets in `text`. Specific detectors win over generic ones on
/// overlapping spans, so a key is reported once under its real provider.
///
/// `strict` is for files that are not classic secret spots (app data, agent
/// logs, source code): generic `NAME=value` hits there need an env-style or
/// clearly secret name, which keeps cache keys and tracking tokens out.
pub fn find(text: &str, strict: bool) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    for (i, re) in compiled().iter().enumerate() {
        let det = &DETECTORS[i];
        for caps in re.captures_iter(text) {
            let m = caps.get(1).unwrap_or_else(|| caps.get(0).unwrap());
            if hits.iter().any(|h| h.start < m.end() && m.start() < h.end) {
                continue;
            }
            let value = m.as_str();
            if looks_like_placeholder(value) {
                continue;
            }
            if det.generic {
                // The regex starts at the keyword (fast); the name is completed here.
                let name = (det.id == "generic").then(|| assignment_name(text, caps.get(0).unwrap()));
                if !name.map_or(true, |n| secret_name(n, strict)) || !plausible_value(value) {
                    continue;
                }
            }
            if near(text, m.start(), m.end()).contains("keyleak:allow") {
                continue;
            }
            hits.push(Hit { detector: i, start: m.start(), end: m.end() });
        }
    }
    hits.sort_by_key(|h| h.start);
    hits
}

/// The variable name around a generic match: `MY_API_KEY` in `MY_API_KEY=...`.
fn assignment_name<'t>(text: &'t str, whole: regex::Match<'t>) -> &'t str {
    let is_name = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-');
    let bytes = text.as_bytes();
    let mut start = whole.start();
    while start > 0 && whole.start() - start < 40 && is_name(bytes[start - 1]) {
        start -= 1;
    }
    let end = whole.start() + whole.as_str().bytes().take_while(|&b| is_name(b)).count();
    // A JSON escape like `\u0026` or `\n` glued to the name is not part of it.
    let name = &text[start..end];
    name.rsplit_once(['\\']).map_or(name, |(_, n)| n)
}

/// The rest of the line around a span, at most 200 bytes each side, so huge
/// one-line JSON files stay fast.
pub fn near(text: &str, start: usize, end: usize) -> &str {
    let mut s = start.saturating_sub(200);
    while !text.is_char_boundary(s) {
        s += 1;
    }
    let mut e = (end + 200).min(text.len());
    while !text.is_char_boundary(e) {
        e -= 1;
    }
    let s = text[s..start].rfind('\n').map_or(s, |p| s + p + 1);
    let e = text[end..e].find('\n').map_or(e, |p| end + p);
    &text[s..e]
}

/// Values that are documentation placeholders, not secrets.
fn looks_like_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    const WORDS: &str = "example placeholder your_ your- yourkey changeme xxxxxx dummy sample redacted insert replace < > **** ... … fake_";
    WORDS.split(' ').any(|w| l.contains(w)) || v.chars().collect::<std::collections::HashSet<_>>().len() <= 3
}

/// Name parts that mean "not the secret itself": IDs, paths, sizes, cache and
/// pagination keys, references to other variables.
const NOT_SECRET: &str = "PUBLIC PUBLISHABLE _ID -ID .ID _FILE _PATH _DIR _URL _URI _ENDPOINT _HOST _TYPE _NAME _LENGTH \
    _LEN _SIZE _COUNT _MAX _LIMIT _EXPIR _TTL _ENABLED _HEADER _FORMAT _MODE _CMD _COMMAND TOKENIZER MAX_TOKEN \
    _FINGERPRINT KEYBOARD KEYMAP _ALGO _ENV ENV_ _VAR CACHE TRACKING OBJECT_KEY RESULT IDEMPOTENCY LOAD_TOKEN \
    REDIR CHANGETOKEN CHANGE_TOKEN LOGGING PROMPT PAGE_ _PAGE NEXT_TOKEN NEXTTOKEN NEXT_PAGE CONTINUATION CURSOR PAGINATION SYNC_TOKEN REQUEST \
    TRACE CORRELATION ETAG SORT_ PARTITION PRIMARY_KEY FOREIGN ROW_KEY HASH _LOCK LOCK_ _DATE DATE_ X-AMZ- NATIVE_PASSWORD \
    _FIELD _PARAM _LABEL _HINT _PLACEHOLDER _POLICY _RULE _REGEX _PATTERN _SCOPE _ISSUER _AUDIENCE";

/// Names that clearly hold a secret even in strict files (normalised: no
/// separators, lowercase): `apiKey`, `client_secret`, `BOT_TOKEN` ...
const SECRET_SUFFIX: &str = "apikey apitoken secretkey secret clientsecret accesstoken authtoken bottoken \
    refreshtoken password passwd privatekey accesskey secretaccesskey authkey";

fn secret_name(name: &str, strict: bool) -> bool {
    if name.is_empty() {
        return false;
    }
    let up = name.to_ascii_uppercase();
    if NOT_SECRET.split_whitespace().any(|w| up.contains(w)) || up.ends_with("ID") || up.ends_with("KEYS") {
        return false;
    }
    if !strict {
        return true;
    }
    // Env-style names (OPENAI_API_KEY, DISCORD_BOT_TOKEN) or clearly secret ones.
    let env_style = name.len() >= 5
        && name.contains('_')
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    let norm: String =
        name.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
    env_style || SECRET_SUFFIX.split_whitespace().any(|s| norm.ends_with(s))
}

/// Extra checks on values of generic detectors (assignments, URLs, bearer tokens).
fn plausible_value(v: &str) -> bool {
    let first = v.chars().next().unwrap_or(' ');
    if matches!(first, '/' | '~' | '.' | '$' | '{' | '%' | '<' | '*' | '&' | '@') || v.contains("://") {
        return false;
    }
    if v.starts_with("pk_") || v.contains("${") || v.contains("$(") {
        return false;
    }
    let has_digit = v.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = v.bytes().any(|b| b.is_ascii_alphabetic());
    if !has_alpha {
        return false;
    }
    let e = entropy(v);
    // Short URL passwords pass on mixed charset; long tokens need randomness.
    if v.len() < 16 {
        return has_digit && e >= 2.5;
    }
    // Dotted words (module.paths) and snake_case identifiers are code, not keys.
    if !has_digit && v.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'.' || b == b'-') {
        return false;
    }
    e >= 3.3
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Mask a secret for display: public prefix, an ellipsis, the last 4 chars.
/// Short secrets show only their last 2 chars. Never the whole value.
pub fn mask(det: &Detector, secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if det.id == "private-key" {
        return "-----BEGIN …PRIVATE KEY-----".into();
    }
    let tail = if chars.len() >= 16 { 4 } else { 2 };
    // Public prefixes are short lowercase words: `sk-proj-`, `sk-ant-api03-`, `ghp_`.
    let auto = || {
        let mut end = 0;
        let mut seg = 0;
        for (i, &c) in chars.iter().enumerate().take(14) {
            if c == '-' || c == '_' {
                let word = &chars[i - seg..i];
                if seg == 0 || seg > 6 || !word.iter().any(|c| c.is_ascii_lowercase()) {
                    break;
                }
                end = i + 1;
                seg = 0;
            } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
                seg += 1;
            } else {
                break;
            }
        }
        end
    };
    let mut prefix = det.show_prefix.unwrap_or_else(auto);
    // Always hide at least half of the secret.
    prefix = prefix.min(chars.len().saturating_sub(tail) / 2);
    let head: String = chars[..prefix].iter().collect();
    let end: String = chars[chars.len() - tail.min(chars.len())..].iter().collect();
    format!("{head}…{end}")
}

/// A stable short ID for a secret, used to group repeats and in ignore files.
/// 32 bits of FNV-1a: enough to tell keys apart, useless for guessing them.
pub fn fingerprint(det: &Detector, secret: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in det.provider.bytes().chain(secret.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (h >> 32) as u32 ^ h as u32)
}

/// Seconds each detector's regex takes on `text`, slowest first (for tuning).
pub fn profile(text: &str) -> Vec<(&'static str, f64)> {
    let mut v: Vec<_> = compiled()
        .iter()
        .zip(DETECTORS)
        .map(|(re, d)| {
            let t = std::time::Instant::now();
            let n = re.find_iter(text).count();
            std::hint::black_box(n);
            (d.id, t.elapsed().as_secs_f64())
        })
        .collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::fake;

    fn ids(text: &str) -> Vec<&'static str> {
        find(text, false).iter().map(|h| DETECTORS[h.detector].id).collect()
    }

    #[test]
    fn provider_keys_are_found() {
        let cases = [
            (format!("export OPENAI_API_KEY={}", fake("sk-proj-", 60, 1)), "openai"),
            (format!("key: {}", fake("sk-ant-api03-", 90, 2)), "anthropic"),
            (fake("AIza", 35, 3), "google"),
            (format!("id={}", fake_upper("AKIA", 16, 4)), "aws-key-id"),
            (format!("token {}", fake("ghp_", 36, 5)), "github"),
            (fake("glpat-", 20, 6), "gitlab"),
            (fake("hf_", 34, 7), "huggingface"),
            (fake("gsk_", 52, 8), "groq"),
            (fake("npm_", 36, 9), "npm"),
            (fake(&["sk", "_live_"].concat(), 24, 10), "stripe"),
            (fake(&["sk", "_test_"].concat(), 24, 11), "stripe-test"),
        ];
        for (text, want) in &cases {
            assert_eq!(ids(text), vec![*want], "{want}");
        }
    }

    fn fake_upper(prefix: &str, n: usize, seed: u64) -> String {
        fake(prefix, n, seed).to_ascii_uppercase()
    }

    #[test]
    fn aws_secret_and_telegram_and_deepgram() {
        let aws =
            format!("aws_secret_access_key = {}", crate::demo::fake_charset("", 40, 12, crate::demo::B64));
        assert_eq!(ids(&aws), vec!["aws-secret"]);
        let tg =
            format!("TELEGRAM={}", crate::demo::fake_charset("123456789:AA", 33, 13, crate::demo::ALNUM));
        assert!(ids(&tg).contains(&"telegram"));
        let dg = format!("DEEPGRAM_API_KEY={}", crate::demo::fake_charset("", 40, 14, crate::demo::HEX));
        assert_eq!(ids(&dg), vec!["deepgram"]);
        let curl = format!(
            "curl https://api.deepgram.com/v1/listen -H 'Authorization: Token {}'",
            crate::demo::fake_charset("", 40, 15, crate::demo::HEX)
        );
        assert_eq!(ids(&curl), vec!["deepgram-curl"]);
    }

    #[test]
    fn generic_assignments_need_randomness() {
        assert_eq!(ids(&format!("MY_SERVICE_TOKEN={}", fake("", 20, 40))), vec!["generic"]);
        assert_eq!(ids(&format!(r#""apiKey": "{}""#, fake("", 20, 41))), vec!["generic"]);
        // Not secrets: paths, words, variables, IDs, placeholders, short values.
        for text in [
            "SSH_KEY_PATH=/home/me/.ssh/id_ed25519",
            "TOKENIZERS_PARALLELISM=false",
            "API_KEY=$OPENAI_API_KEY",
            "API_KEY=${OPENAI_API_KEY}",
            "CLIENT_ID=8f14e45fceea167a5a36dedd4bea2543",
            "API_KEY=your_api_key_here",
            "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx",
            "secret = some.module.path_name",
            "password: hunter2",
            "max_tokens: 4096000000000000",
            "API_KEY=<paste-your-key>",
        ] {
            assert!(ids(text).is_empty(), "false positive: {text}");
        }
    }

    #[test]
    fn urls_and_private_keys() {
        assert_eq!(
            ids(&format!("postgres://app:{}@db.internal:5432/app", fake("", 10, 42))),
            vec!["url-password"]
        );
        assert!(ids("https://user:password@example.com").is_empty());
        assert_eq!(ids(&["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat()), vec!["private-key"]);
    }

    #[test]
    fn specific_beats_generic_and_allow_comment() {
        let line = format!("GITHUB_TOKEN={}", fake("ghp_", 36, 20));
        assert_eq!(ids(&line), vec!["github"]);
        assert!(ids(&format!("{line}  # keyleak:allow")).is_empty());
        // An empty value never borrows the next line.
        assert!(ids("API_TOKEN=\nZq8vR2kLm9Tx4Bn7Wc1Y\n").is_empty());
    }

    #[test]
    fn jwts_are_found_and_masked() {
        let jwt = format!("{}.{}.{}", fake("eyJ", 30, 50), fake("eyJ", 60, 51), fake("", 43, 52));
        let text = format!("curl 'https://api.example.dev/v1/file?token={jwt}'");
        assert_eq!(ids(&text), vec!["jwt"]);
        let det = DETECTORS.iter().find(|d| d.id == "jwt").unwrap();
        let m = mask(det, &jwt);
        assert!(m.starts_with("eyJ…") && m.chars().count() == 8, "{m}");
    }

    #[test]
    fn masks_never_show_the_secret() {
        let key = fake("sk-proj-", 60, 30);
        let m = mask(&DETECTORS[0], &key);
        assert!(m.starts_with("sk-proj-…"));
        assert_eq!(m.chars().count(), "sk-proj-…".chars().count() + 4);
        let url = DETECTORS.iter().find(|d| d.id == "url-password").unwrap();
        let short = mask(url, "Xk9wQ2mP7z");
        assert_eq!(short, "…7z");
        let ant = DETECTORS.iter().find(|d| d.id == "anthropic").unwrap();
        assert!(mask(ant, &fake("sk-ant-api03-", 90, 31)).starts_with("sk-ant-api03-…"));
        let gh = DETECTORS.iter().find(|d| d.id == "github").unwrap();
        assert!(mask(gh, &fake("ghp_", 36, 32)).starts_with("ghp_…"));
    }
}
