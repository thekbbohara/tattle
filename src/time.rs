//! Minimal UTC time helpers, so there is no date crate: RFC 3339 in, short
//! labels out.

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Seconds since the Unix epoch for `YYYY-MM-DDTHH:MM:SS[.frac][Z|±HH:MM]`.
pub fn parse(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(rest.len().checked_sub(2)?..)?.parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn split(t: i64) -> (i64, i64, i64, i64, i64, i64, usize) {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, secs / 3600, secs / 60 % 60, secs % 60, (days + 4).rem_euclid(7) as usize)
}

/// `2026-10-27T16:42:05Z`
pub fn iso(t: i64) -> String {
    let (y, m, d, h, mi, s, _) = split(t);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `Tue 27 Oct 16:42` (UTC)
pub fn short(t: i64) -> String {
    let (_, m, d, h, mi, _, wd) = split(t);
    format!("{} {d} {} {h:02}:{mi:02}", DAYS[wd], MONTHS[m as usize - 1])
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_labels() {
        let t = parse("2026-11-02T00:00:00Z").unwrap();
        assert_eq!(t, 1_793_577_600);
        assert_eq!(parse("2026-10-27T16:42:05.123Z"), parse("2026-10-27T18:42:05+02:00"));
        assert_eq!(iso(parse("2026-10-27T16:42:05.9Z").unwrap()), "2026-10-27T16:42:05Z");
        assert_eq!(short(parse("2026-10-26T09:05:00Z").unwrap()), "Mon 26 Oct 09:05");
        assert_eq!(short(parse("2024-02-29T23:59:00Z").unwrap()), "Thu 29 Feb 23:59");
        for bad in ["", "yesterday", "2026-13-01T00:00:00Z", "2026-10-27 16:42", "2026-10-27T16:42:05X"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
