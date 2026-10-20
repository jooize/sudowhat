//! display.rs — the pure, host-testable heart of the Linux audit plugin.
//!
//! It parses sudo's `key=value` context arrays and assembles the exact terminal
//! block the macOS audit plugin emits (plugin/sudowhat_audit.m):
//!
//!   sudowhat: run as: <target user>
//!   sudowhat: directory: <invoking cwd>       (omitted when cwd is absent)
//!   sudowhat: input: <command as typed>
//!
//! The escaping/quoting is delegated to `escape_core` — the same crate the macOS
//! plugin links as a staticlib — so the output is byte-for-byte identical on both
//! platforms, and the anti-spoofing guarantees (every hidden character shown as
//! its escape, a backslash escaped only where it would begin one) are
//! inherited, not re-implemented here.
//!
//! Everything in this file is pure (no I/O, no FFI, no unsafe): lib.rs converts
//! the raw C string arrays into byte slices and hands them here, and tty.rs does
//! the actual /dev/tty write. That split keeps the interesting logic testable on
//! the macOS dev host with no Linux linker.
//!
//! Every value stays the raw bytes sudo handed over until escape_core renders
//! it, so a byte that is not valid UTF-8 shows as `\xHH`, exactly as on macOS,
//! never as a replacement glyph that hides which byte was there.

/// Value for `key` in a slice of NUL-stripped `"key=value"` entries, or `None`.
/// Twin of the ObjC `find_kv`: it matches the WHOLE key up to `'='`, so a lookup
/// of `"uid"` never matches `"uidextra=1"`, and it returns the first match.
pub fn find_kv<'a>(arr: &[&'a [u8]], key: &str) -> Option<&'a [u8]> {
    for entry in arr {
        if let Some(rest) = entry.strip_prefix(key.as_bytes())
            && let Some(val) = rest.strip_prefix(b"=")
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
pub fn parse_uid(s: &[u8]) -> u64 {
    let mut n: u64 = 0;
    for &b in s {
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
pub fn color_allowed(envp: &[&[u8]]) -> bool {
    if find_kv(envp, "NO_COLOR").is_some() {
        return false;
    }
    match find_kv(envp, "TERM") {
        None => false,
        Some(t) if t.is_empty() || t == b"dumb" => false,
        Some(_) => true,
    }
}

/// Escape a single value through the shared core (every hidden character →
/// its visible escape, every byte that is not valid UTF-8 → `\xHH`). Used for
/// the user and directory lines, which are not shell tokens.
fn escape(s: &[u8]) -> String {
    let mut out = String::new();
    escape_core::escape_bytes(s, &mut out);
    out
}

/// Build the as-typed command line from `argv` = `submit_argv[submit_optind..]`
/// (so `argv[0]` is the command word). We pass `argv[0]` as the "path" so
/// `escape_core::full_command_line_bytes`'s argv0-dedup collapses it to a single
/// leading token — the command exactly as the user typed it, every token
/// shell-quoted and control-char escaped. `None` when there is no command word.
fn command_line(argv: &[&[u8]]) -> Option<String> {
    if argv.is_empty() {
        return None;
    }
    let mut out = String::new();
    escape_core::full_command_line_bytes(argv[0], argv, &mut out);
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
    settings: &[&[u8]],
    user_info: &[&[u8]],
    argv: &[&[u8]],
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
    block.push_str(&format!("sudowhat: {lb}run as:{lo} {user_line}\n"));
    if let Some(d) = &dir_line {
        block.push_str(&format!("sudowhat: {lb}directory:{lo} {d}\n"));
    }
    block.push_str(&format!("sudowhat: {lb}input:{lo} {command}\n"));
    Some(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    // sudo's arrays as the byte slices lib.rs hands over, from &str for the
    // valid-UTF-8 cases; the invalid-byte tests build their slices directly.
    fn b<'a>(v: &[&'a str]) -> Vec<&'a [u8]> {
        v.iter().map(|s| s.as_bytes()).collect()
    }
    fn bb(settings: &[&str], user_info: &[&str], argv: &[&str], color: bool) -> Option<String> {
        build_block(&b(settings), &b(user_info), &b(argv), color)
    }

    #[test]
    fn find_kv_matches_whole_key() {
        let arr = b(&["uid=1000", "cwd=/home/alice", "runas_user=postgres"]);
        assert_eq!(find_kv(&arr, "uid"), Some(&b"1000"[..]));
        assert_eq!(find_kv(&arr, "cwd"), Some(&b"/home/alice"[..]));
        assert_eq!(find_kv(&arr, "runas_user"), Some(&b"postgres"[..]));
        // must not prefix-match a longer key
        assert_eq!(find_kv(&b(&["uidextra=1"]), "uid"), None);
        // empty value is a real match, not absence
        assert_eq!(find_kv(&b(&["cwd="]), "cwd"), Some(&b""[..]));
        assert_eq!(find_kv(&[], "uid"), None);
        // a value that is not valid UTF-8 is found as its bytes
        assert_eq!(find_kv(&[&b"cwd=/x\xff"[..]], "cwd"), Some(&b"/x\xff"[..]));
    }

    #[test]
    fn parse_uid_like_strtoul() {
        assert_eq!(parse_uid(b"0"), 0);
        assert_eq!(parse_uid(b"1000"), 1000);
        assert_eq!(parse_uid(b"501abc"), 501); // leading digits only
        assert_eq!(parse_uid(b"abc"), 0); // no digits → 0 (root, exempt)
        assert_eq!(parse_uid(b""), 0);
        assert_eq!(parse_uid(b"501\xff"), 501); // stops at a byte that is not a digit
    }

    #[test]
    fn color_allowed_gates() {
        assert!(color_allowed(&b(&["TERM=xterm-256color"])));
        assert!(!color_allowed(&b(&["TERM=dumb"])));
        assert!(!color_allowed(&b(&["TERM="])));
        assert!(!color_allowed(&[])); // no TERM at all
        assert!(!color_allowed(&b(&["NO_COLOR=", "TERM=xterm"]))); // NO_COLOR wins
        assert!(!color_allowed(&b(&["NO_COLOR=1", "TERM=xterm"])));
    }

    #[test]
    fn plain_command_block() {
        let b = bb(
            &[],
            &["uid=1000", "cwd=/home/alice"],
            &["/bin/echo", "hi"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: run as: root\n\
             sudowhat: directory: /home/alice\n\
             sudowhat: input: /bin/echo hi\n"
        );
    }

    #[test]
    fn leading_token_shown_once() {
        // `sudo id` → submit_argv[optind..] is ["id"]; we pass path = argv[0], so
        // the argv0-dedup collapses it to a single leading token, not "id id".
        let b = bb(&[], &["uid=1000", "cwd=/x"], &["id"], false).unwrap();
        assert_eq!(
            b,
            "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: id\n"
        );
        // A genuinely repeated argument (`sudo cp a a`) is preserved — the dedup
        // drops only ONE leading duplicate.
        let b2 = bb(&[], &["uid=1000", "cwd=/x"], &["/bin/cp", "a", "a"], false).unwrap();
        assert_eq!(
            b2,
            "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: /bin/cp a a\n"
        );
    }

    #[test]
    fn runas_user_and_absent_cwd() {
        // runas_user present → user line escaped; no cwd → directory omitted.
        let b = bb(&["runas_user=postgres"], &["uid=1000"], &["psql"], false).unwrap();
        assert_eq!(
            b,
            "sudowhat: run as: postgres\nsudowhat: input: psql\n"
        );
    }

    #[test]
    fn quoted_argument() {
        let b = bb(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", "a b"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: /bin/echo 'a b'\n"
        );
    }

    // Hidden characters and expected escapes are built in code, never typed as
    // a literal escape: `ch(0x202E)` is the character itself, `esc_of("202E")`
    // the escape the display shows for it.
    fn ch(u: u32) -> String {
        char::from_u32(u).expect("a scalar value").to_string()
    }
    fn esc_of(hex: &str) -> String {
        format!("{}u{{{}}}", '\\', hex)
    }

    #[test]
    fn control_char_is_escaped_literally() {
        // a real line feed in an argument renders as its escape, never a raw
        // byte that could inject terminal output.
        let b = bb(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", "a\nb"],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            format!(
                "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: /bin/echo 'a{}b'\n",
                esc_of("A")
            )
        );
        // exactly one real newline per display line, and only at the ends
        assert_eq!(b.matches('\n').count(), 3);
    }

    #[test]
    fn unicode_bidi_spoof_is_escaped() {
        // U+202E RIGHT-TO-LEFT OVERRIDE (Trojan Source) shows as its escape.
        let evil = format!("{}evil", ch(0x202E));
        let b = bb(
            &[],
            &["uid=1000", "cwd=/x"],
            &["/bin/echo", &evil],
            false,
        )
        .unwrap();
        assert_eq!(
            b,
            format!(
                "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: /bin/echo '{}evil'\n",
                esc_of("202E")
            )
        );
        // no raw bidi override survives into the output
        assert!(!b.contains(&ch(0x202E)));
    }

    #[test]
    fn spoofed_directory_is_escaped() {
        // a zero-width space in the cwd shows on the directory line.
        let cwd = format!("cwd=/home/a{}b", ch(0x200B));
        let b = bb(&[], &["uid=1000", &cwd], &["/bin/id"], false).unwrap();
        assert_eq!(
            b,
            format!(
                "sudowhat: run as: root\nsudowhat: directory: /home/a{}b\nsudowhat: input: /bin/id\n",
                esc_of("200B")
            )
        );
    }

    #[test]
    fn color_bolds_labels() {
        let b = bb(&[], &["uid=1000", "cwd=/x"], &["/bin/echo", "hi"], true).unwrap();
        assert_eq!(
            b,
            "sudowhat: \x1b[1mrun as:\x1b[0m root\n\
             sudowhat: \x1b[1mdirectory:\x1b[0m /x\n\
             sudowhat: \x1b[1minput:\x1b[0m /bin/echo hi\n"
        );
    }

    #[test]
    fn invalid_utf8_shows_as_byte_escapes() {
        // `sudo cp $'x\xff' /etc/y`: the token keeps its place and shows the
        // byte as \xFF, as the macOS plugins do, never as U+FFFD (which hides
        // which byte was there) and never dropped.
        let argv: [&[u8]; 3] = [b"cp", b"x\xff", b"/etc/y"];
        let blk = build_block(&[], &b(&["uid=1000", "cwd=/x"]), &argv, false).unwrap();
        assert_eq!(
            blk,
            "sudowhat: run as: root\nsudowhat: directory: /x\nsudowhat: input: cp 'x\\xFF' /etc/y\n"
        );
        assert!(!blk.contains(char::REPLACEMENT_CHARACTER));

        // The same for the directory and the target user, which are escaped,
        // not quoted. Valid sequences decode first: only the failing byte is
        // escaped.
        let settings: [&[u8]; 1] = [b"runas_user=u\xfe"];
        let user_info: [&[u8]; 2] = [b"uid=1000", b"cwd=/home/caf\xc3\xa9\xff"];
        let blk = build_block(&settings, &user_info, &[&b"/bin/id"[..]], false).unwrap();
        assert_eq!(
            blk,
            "sudowhat: run as: u\\xFE\n\
             sudowhat: directory: /home/café\\xFF\n\
             sudowhat: input: /bin/id\n"
        );
    }

    #[test]
    fn no_command_word_is_none() {
        assert!(bb(&[], &["uid=1000", "cwd=/x"], &[], false).is_none());
    }
}
