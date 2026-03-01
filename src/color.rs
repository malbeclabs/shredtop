//! Terminal color helpers — zero-dependency ANSI escape codes.
//!
//! Colors are suppressed automatically when stdout is not a TTY or the
//! `NO_COLOR` environment variable is set (https://no-color.org/).

use std::io::IsTerminal;
use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Returns `true` if ANSI color codes should be emitted.
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
    })
}

fn wrap(code: &str, s: &str) -> String {
    if enabled() {
        format!("\x1b[{}m{}\x1b[0m", code, s)
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String       { wrap("1",    s) }
pub fn dim(s: &str) -> String        { wrap("2",    s) }
pub fn green(s: &str) -> String      { wrap("32",   s) }
pub fn yellow(s: &str) -> String     { wrap("33",   s) }
pub fn red(s: &str) -> String        { wrap("31",   s) }
pub fn cyan(s: &str) -> String       { wrap("36",   s) }
pub fn bold_cyan(s: &str) -> String  { wrap("1;36", s) }
pub fn bold_green(s: &str) -> String { wrap("1;32", s) }

/// Count visible characters in a string, ignoring ANSI escape sequences.
pub fn visible_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut in_esc = false;
    for c in s.chars() {
        match c {
            '\x1b' => in_esc = true,
            'm' if in_esc => in_esc = false,
            _ if in_esc => {}
            _ => len += 1,
        }
    }
    len
}

/// Right-pad `s` to `width` visible characters (left-align).
pub fn rpad(s: &str, width: usize) -> String {
    let vlen = visible_len(s);
    if vlen >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - vlen))
    }
}

/// Left-pad `s` to `width` visible characters (right-align).
#[allow(dead_code)]
pub fn lpad(s: &str, width: usize) -> String {
    let vlen = visible_len(s);
    if vlen >= width {
        s.to_string()
    } else {
        format!("{}{}", " ".repeat(width - vlen), s)
    }
}
