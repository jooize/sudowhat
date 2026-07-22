//! display.rs — the pure, host-testable heart of the Linux audit plugin.
//!
//! It parses sudo's `key=value` context arrays and assembles the exact terminal
//! block the macOS audit plugin emits (plugin/sudowhat_audit.m):
//!
//!   sudowhat: user: <target user>
//!   sudowhat: directory: <invoking cwd>       (omitted when cwd is absent)
//!   sudowhat: command: <command as typed>
//!
//! The escaping/quoting is delegated to `escape_core` — the same crate the macOS
//! plugin links as a staticlib — so the output is byte-for-byte identical on both
//! platforms, and the anti-spoofing guarantees (control/bidi/zero-width/homoglyph
//! neutralised, literal `\` doubled) are inherited, not re-implemented here.
//!
//! Everything in this file is pure (no I/O, no FFI, no unsafe): lib.rs converts
//! the raw C string arrays into Rust slices and hands them here, and tty.rs does
//! the actual /dev/tty write. That split keeps the interesting logic testable on
//! the macOS dev host with no Linux linker.

/// Value for `key` in a slice of NUL-stripped `"key=value"` entries, or `None`.
/// Twin of the ObjC `find_kv`: it matches the WHOLE key up to `'='`, so a lookup
/// of `"uid"` never matches `"uidextra=1"`, and it returns the first match.
pub fn find_kv<'a>(arr: &[&'a str], key: &str) -> Option<&'a str> {
    for entry in arr {
        if let Some(rest) = entry.strip_prefix(key)
            && let Some(val) = rest.strip_prefix('=')
        {
            return Some(val);
        }
    }
    None
}

/// Parse a uid the way the ObjC `strtoul(uidStr, NULL, 10)` does: consume leading
/// decimal digits, stop at the first non-digit, and yield 0 when there are none.
/// A non-numeric value therefore reads as uid 0 → treated as root → no display,
/// which is the same fail-soft outcome as the macOS root exemption.
pub fn parse_uid(s: &str) -> u64 {
    let mut n: u64 = 0;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            n = n.saturating_mul(10).saturating_add((b - b'0') as u64);
        } else {
            break;
        }
    }
    n
}

/// Whether ANSI emphasis is permitted for the display, mirroring the macOS
/// `sw_audit_color_allowed`: off when `NO_COLOR` is present at any value
/// (no-color.org) or `TERM` is absent / empty / "dumb". Cosmetic only — the
/// authoritative final gate is the `isatty()` check in tty.rs, so a redirect or
/// a non-tty always renders plain regardless of this.
pub fn color_allowed(envp: &[&str]) -> bool {
    if find_kv(envp, "NO_COLOR").is_some() {
        return false;
    }
    match find_kv(envp, "TERM") {
        None => false,
        Some(t) if t.is_empty() || t == "dumb" => false,
        Some(_) => true,
    }
}

/// Escape a single value through the shared core (control/homoglyph/bidi/
/// zero-width → visible ASCII escapes). Used for the user and directory lines,
/// which are not shell tokens.
fn escape(s: &str) -> String {
    let mut out = String::new();
    escape_core::escape_control(s, &mut out);
    out
}

/// Build the as-typed command line from `argv` = `submit_argv[submit_optind..]`
/// (so `argv[0]` is the command word). We pass `argv[0]` as the "path" so
/// `escape_core::full_command_line`'s argv0-dedup collapses it to a single
/// leading token — the command exactly as the user typed it, every token
/// shell-quoted and control-char escaped. `None` when there is no command word.
fn command_line(argv: &[&str]) -> Option<String> {
    if argv.is_empty() {
        return None;
    }
    let mut out = String::new();
    escape_core::full_command_line(argv[0], argv, &mut out);
    Some(out)
}

/// Assemble the full display block, or `None` when there is nothing to show (no
/// command word — e.g. `sudo -v`). `color` toggles the bold label emphasis; the
/// caller derives it from [`color_allowed`], and tty.rs's `isatty()` is still the
/// final say. Byte-for-byte identical to plugin/sudowhat_audit.m's block.
///
/// - `settings`  — sudo's `settings[]` (holds `runas_user` only when `-u` given).
/// - `user_info` — sudo's `user_info[]` (holds the invoking `cwd`).
/// - `argv`      — `submit_argv[submit_optind..]`, the command as typed.
pub fn build_block(
    settings: &[&str],
    user_info: &[&str],
    argv: &[&str],
    color: bool,
) -> Option<String> {
    // The command as typed is the star of the display; without one there is
    // nothing to preview, so show nothing.
    let command = command_line(argv)?;
    if command.is_empty() {
        return None;
    }

    // Target user: sudo puts runas_user in settings[] only when -u was given;
    // otherwise the default target is root.
    let user_line = match find_kv(settings, "runas_user") {
        Some(r) if !r.is_empty() => escape(r),
        _ => "root".to_string(),
    };

    // Directory shown is the invoking cwd where execve will run — the honest
    // pre-resolution value from user_info (command_info["cwd"] does not exist
    // yet at audit open()). Absent → omit the Directory line.
    let dir_line = match find_kv(user_info, "cwd") {
        Some(c) if !c.is_empty() => Some(escape(c)),
        _ => None,
    };

    // Bold the label words purely for readability (our own fixed bytes, never
    // user input). Restores the emphasis the pre-v0.10.0 macOS path applied.
    let (lb, lo) = if color { ("\x1b[1m", "\x1b[0m") } else { ("", "") };

    let mut block = String::new();
    block.push_str(&format!("sudowhat: {lb}user:{lo} {user_line}\n"));
    if let Some(d) = &dir_line {
        block.push_str(&format!("sudowhat: {lb}directory:{lo} {d}\n"));
    }
    block.push_str(&format!("sudowhat: {lb}command:{lo} {command}\n"));
    Some(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_kv_matches_whole_key() {
        let arr = ["uid=1000", "cwd=/home/alice", "runas_user=postgres"];
        assert_eq!(find_kv(&arr, "uid"), Some("1000"));
        assert_eq!(find_kv(&arr, "cwd"), Some("/home/alice"));
        assert_eq!(find_kv(&arr, "runas_user"), Some("postgres"));
        // must not prefix-match a longer key
        assert_eq!(find_kv(&["uidextra=1"], "uid"), None);
        // empty value is a real match, not absence
        assert_eq!(find_kv(&["cwd="], "cwd"), Some(""));
        assert_eq!(find_kv(&[], "uid"), None);
    }

    #[test]
    fn parse_uid_like_strtoul() {
        assert_eq!(parse_uid("0"), 0);
        assert_eq!(parse_uid("1000"), 1000);
        assert_eq!(parse_uid("501abc"), 501); // leading digits only
        assert_eq!(parse_uid("abc"), 0); // no digits → 0 (root, exempt)
        assert_eq!(parse_uid(""), 0);
    }

    #[test]
    fn color_allowed_gates() {
        assert!(color_allowed(&["TERM=xterm-256color"]));
        assert!(!color_allowed(&["TERM=dumb"]));
        assert!(!color_allowed(&["TERM="]));
        assert!(!color_allowed(&[])); // no TERM at all
        assert!(!color_allowed(&["NO_COLOR=", "TERM=xterm"])); // NO_COLOR wins
        assert!(!color_allowed(&["NO_COLOR=1", "TERM=xterm"]));
    }

    #[test]
    fn plain_command_block() {
        let b = build_block(
            &[],
            &["uid=1000", "cwd=/home/alice"],
            &["/bin/echo", "hi"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\n\
             sudowhat: directory: /home/alice\n\
             sudowhat: command: /bin/echo hi\n"
        );
    }

    #[test]
    fn leading_token_shown_once() {
        // `sudo id` → submit_argv[optind..] is ["id"]; we pass path = argv[0], so
        // the argv0-dedup collapses it to a single leading token, not "id id".
        let b = build_block(&[], &["uid=1000", "cwd=/x"], &["id"], false).unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\nsudowhat: directory: /x\nsudowhat: command: id\n"
        );
        // A genuinely repeated argument (`sudo cp a a`) is preserved — the dedup
        // drops only ONE leading duplicate.
        let b2 = build_block(&[], &["uid=1000", "cwd=/x"], &["/bin/cp", "a", "a"], false).unwrap();
        assert_eq!(
            b2,
            "sudowhat: user: root\nsudowhat: directory: /x\nsudowhat: command: /bin/cp a a\n"
        );
    }

    #[test]
    fn runas_user_and_absent_cwd() {
        // runas_user present → user line escaped; no cwd → directory omitted.
        let b = build_block(&["runas_user=postgres"], &["uid=1000"], &["psql"], false).unwrap();
        assert_eq!(
            b,
            "sudowhat: user: postgres\nsudowhat: command: psql\n"
        );
    }

    #[test]
    fn quoted_argument() {
        let b = build_block(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", "a b"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\nsudowhat: directory: /x\nsudowhat: command: /bin/echo 'a b'\n"
        );
    }

    #[test]
    fn control_char_is_escaped_literally() {
        // a real newline in an argument must render as the two chars \n, never a
        // raw byte that could inject terminal output.
        let b = build_block(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", "a\nb"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\nsudowhat: directory: /x\nsudowhat: command: /bin/echo 'a\\nb'\n"
        );
        // exactly one real newline per display line, and only at the ends
        assert_eq!(b.matches('\n').count(), 3);
    }

    #[test]
    fn unicode_bidi_spoof_is_escaped() {
        // U+202E RIGHT-TO-LEFT OVERRIDE (Trojan Source) is neutralised to the
        // visible ASCII escape backslash-u-2-0-2-e.
        let b = build_block(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", "\u{202e}evil"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\nsudowhat: directory: /x\nsudowhat: command: /bin/echo '\\u202eevil'\n"
        );
        // no raw bidi override byte survives into the output
        assert!(!b.contains('\u{202e}'));
    }

    #[test]
    fn spoofed_directory_is_escaped() {
        // a homoglyph ellipsis in the cwd is neutralised on the directory line.
        let b = build_block(
            &[],
            &["uid=1000", "cwd=/home/\u{2026}"],
            &["/bin/id"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: user: root\nsudowhat: directory: /home/\\u2026\nsudowhat: command: /bin/id\n"
        );
    }

    #[test]
    fn color_bolds_labels() {
        let b = build_block(&[], &["uid=1000", "cwd=/x"], &["/bin/echo", "hi"], true).unwrap();
        assert_eq!(
            b,
            "sudowhat: \x1b[1muser:\x1b[0m root\n\
             sudowhat: \x1b[1mdirectory:\x1b[0m /x\n\
             sudowhat: \x1b[1mcommand:\x1b[0m /bin/echo hi\n"
        );
    }

    #[test]
    fn no_command_word_is_none() {
        assert!(build_block(&[], &["uid=1000", "cwd=/x"], &[], false).is_none());
    }
}
