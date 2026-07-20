//! escape_core — the stateless anti-spoofing string core for sudowhat.
//!
//! This is a byte-for-byte Rust port of the stateless logic in
//! `plugin/PromptFormatter.m` (`escapeControlChars:`, `quoteToken:`,
//! `fullCommandLineForCommandPath:argv:`). It exists so the sudo *audit* plugin
//! — which handles untrusted `argv` where C buffer bugs live — can render the
//! command for terminal display in memory-safe code, and so the same core ports
//! to a pure-Rust Linux plugin later (no Apple frameworks).
//!
//! Equivalence with the ObjC original is a hard requirement, checked by
//! `tests/test_escape_core.m` against the same vectors. Keep the two in sync:
//! any change here must keep that guard green.
//!
//! Threat note: the input is attacker-influenced (`sudo <anything>`). The escape
//! rules neutralise C0/C1 controls, DEL, bidi overrides (Trojan Source /
//! CVE-2021-42574), zero-width joiners, ellipsis/dot-leader homoglyphs, and
//! runs of 3+ ASCII dots (which mimic `…`), and double literal backslashes so a
//! plain-text `\n` cannot spoof a real-newline escape. The output is pure ASCII
//! for every anomalous byte, so writing it to a terminal injects no control
//! sequence.
//!
//! FFI contract: `#[no_mangle] extern "C"` functions write into a caller buffer
//! and never unwind (`panic = "abort"` in release). Invalid UTF-8 in the input
//! is replaced with U+FFFD (lossy) rather than rejected — a display path should
//! degrade to a visible replacement glyph, never hide the command.

use std::os::raw::c_int;
use std::slice;

/// Output written successfully (buffer held the whole result plus a NUL).
pub const SW_ESCAPE_OK: c_int = 0;
/// Output buffer too small; `*needed` holds the required byte length (excluding
/// the NUL). Nothing was written. Callers may reallocate `*needed + 1` and retry.
pub const SW_ESCAPE_TRUNCATED: c_int = 1;

// -------------------------------------------------------------------------
// Core logic (pure, testable, panic-free). Operates on Unicode scalar values;
// for BMP scalars this matches the ObjC `unichar` iteration exactly, and astral
// scalars pass through as their UTF-8 bytes (the ObjC surrogate pair recombines
// to the same bytes), so the two renderings agree byte-for-byte on valid input.
// -------------------------------------------------------------------------

/// The conservative safe set: a token whose escaped form contains only these
/// bytes is emitted unquoted. Mirrors `+[SudoWhatPromptFormatter safeSet]`.
fn is_safe(c: char) -> bool {
    matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9'
        | '+' | '_' | '.' | '/' | ':' | '=' | '@' | '%' | ',' | '-')
}

/// Escape control / homoglyph / bidi / zero-width characters to visible `\xNN`
/// or `\uNNNN` text. Port of `-[SudoWhatPromptFormatter escapeControlChars:]`.
pub fn escape_control(input: &str, out: &mut String) {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        let c = chars[i];

        // Run of 3+ ASCII '.' impersonates U+2026 '…' in proportional fonts —
        // escape every dot in the run. Single '.' and '..' (parent dir) pass.
        if c == '.' {
            let mut j = i + 1;
            while j < len && chars[j] == '.' {
                j += 1;
            }
            let run = j - i;
            if run >= 3 {
                for _ in 0..run {
                    out.push_str("\\u002e");
                }
                i = j;
                continue;
            }
            // run of 1 or 2: fall through to the literal emit below.
        }

        match c {
            // Escape literal backslashes so a plain-text `\n` can't spoof the
            // escape for a real 0x0a newline.
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            _ => {
                let u = c as u32;
                if u < 0x20 || u == 0x7f {
                    // C0 controls and DEL not already handled above.
                    push_hex2(out, u);
                } else if (0x80..=0x9f).contains(&u) {
                    // C1 control range, incl. U+0085 NEL.
                    push_hex4(out, u);
                } else if u == 0x2028 || u == 0x2029 {
                    // Unicode line / paragraph separators.
                    push_hex4(out, u);
                } else if u == 0x2026 || u == 0x22ef || u == 0x2024 || u == 0x2025 {
                    // Ellipsis / dot-leader homoglyphs.
                    push_hex4(out, u);
                } else if (0x202a..=0x202e).contains(&u)
                    || (0x2066..=0x2069).contains(&u)
                    || u == 0x200e
                    || u == 0x200f
                    || u == 0x061c
                {
                    // Bidi formatting / override chars (Trojan Source).
                    push_hex4(out, u);
                } else if u == 0x200b
                    || u == 0x200c
                    || u == 0x200d
                    || u == 0x2060
                    || u == 0xfeff
                {
                    // Zero-width / invisible format chars.
                    push_hex4(out, u);
                } else {
                    out.push(c);
                }
            }
        }
        i += 1;
    }
}

/// Append `\xNN` (two lowercase hex digits) for a byte-range value.
fn push_hex2(out: &mut String, u: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\x");
    out.push(HEX[((u >> 4) & 0xf) as usize] as char);
    out.push(HEX[(u & 0xf) as usize] as char);
}

/// Append `\uNNNN` (four lowercase hex digits) for a BMP scalar value.
fn push_hex4(out: &mut String, u: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(HEX[((u >> 12) & 0xf) as usize] as char);
    out.push(HEX[((u >> 8) & 0xf) as usize] as char);
    out.push(HEX[((u >> 4) & 0xf) as usize] as char);
    out.push(HEX[(u & 0xf) as usize] as char);
}

/// Shell-quote a token if its escaped form contains anything outside the safe
/// set. Port of `-[SudoWhatPromptFormatter quoteToken:]`.
pub fn quote_token(input: &str, out: &mut String) {
    if input.is_empty() {
        out.push_str("''");
        return;
    }
    let mut escaped = String::new();
    escape_control(input, &mut escaped);

    if escaped.chars().all(is_safe) {
        out.push_str(&escaped);
        return;
    }

    out.push('\'');
    for c in escaped.chars() {
        if c == '\'' {
            // classic POSIX single-quote escape: ' -> '\''
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
}

/// NSString `lastPathComponent` for the common cases the dedup compares against:
/// strip trailing slashes, take the segment after the final '/'. An all-slash
/// string is "/". Empty is "".
fn last_path_component(p: &str) -> &str {
    if p.is_empty() {
        return "";
    }
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(idx) => &trimmed[idx + 1..],
        None => trimmed,
    }
}

/// The full command line: quoted path, then argv minus argv[0] when it dups the
/// path or its basename. Port of
/// `-[SudoWhatPromptFormatter fullCommandLineForCommandPath:argv:]`.
pub fn full_command_line(path: &str, argv: &[&str], out: &mut String) {
    let mut first = true;
    let mut emit = |tok: &str, out: &mut String| {
        if !first {
            out.push(' ');
        }
        first = false;
        quote_token(tok, out);
    };

    emit(path, out);

    let basename = last_path_component(path);
    let mut start = 0usize;
    if !argv.is_empty() {
        let a0 = argv[0];
        if a0 == path || (!basename.is_empty() && a0 == basename) {
            start = 1;
        }
    }
    for tok in &argv[start..] {
        emit(tok, out);
    }
}

// -------------------------------------------------------------------------
// FFI boundary. Every function is panic-free by construction: input reads are
// bounded by the caller-supplied length, UTF-8 is decoded lossily (never
// rejected), and output writes are gated on a capacity check.
// -------------------------------------------------------------------------

/// Decode `len` bytes at `ptr` as UTF-8, lossily. Null/zero yields "".
///
/// # Safety
/// `ptr` must be valid for `len` bytes, or null (with any `len`).
fn read_input(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: caller guarantees `ptr` is valid for `len` bytes.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// Emit `result` into the caller buffer following the contract documented on
/// the public functions. Always sets `*needed` (when non-null) to the required
/// length; writes result + NUL only when it fits.
///
/// # Safety
/// `out` must be valid for `out_cap` bytes (or null); `needed` must be a valid
/// `usize` pointer (or null).
fn write_result(result: &str, out: *mut u8, out_cap: usize, needed: *mut usize) -> c_int {
    let bytes = result.as_bytes();
    let n = bytes.len();
    if !needed.is_null() {
        // SAFETY: caller guarantees `needed` is a valid pointer or null.
        unsafe {
            *needed = n;
        }
    }
    if out.is_null() || out_cap < n + 1 {
        return SW_ESCAPE_TRUNCATED;
    }
    // SAFETY: out is non-null and out_cap >= n + 1, so the copy and the NUL
    // write both stay in bounds; source and dest do not overlap (caller buffer).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n);
        *out.add(n) = 0;
    }
    SW_ESCAPE_OK
}

/// Escape control/homoglyph/bidi/zero-width chars in the UTF-8 `input`
/// (`input_len` bytes) into `out` (`out_cap` bytes). See the buffer contract on
/// [`write_result`]. Returns [`SW_ESCAPE_OK`] or [`SW_ESCAPE_TRUNCATED`].
///
/// # Safety
/// `input` valid for `input_len` bytes (or null); `out` valid for `out_cap`
/// bytes (or null); `needed` a valid pointer (or null).
#[unsafe(no_mangle)]
pub extern "C" fn sw_escape_control(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    needed: *mut usize,
) -> c_int {
    let s = read_input(input, input_len);
    let mut result = String::new();
    escape_control(&s, &mut result);
    write_result(&result, out, out_cap, needed)
}

/// Shell-quote (and escape) a single token. Same buffer contract as
/// [`sw_escape_control`].
///
/// # Safety
/// See [`sw_escape_control`].
#[unsafe(no_mangle)]
pub extern "C" fn sw_quote_token(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    needed: *mut usize,
) -> c_int {
    let s = read_input(input, input_len);
    let mut result = String::new();
    quote_token(&s, &mut result);
    write_result(&result, out, out_cap, needed)
}

/// Build the full, untruncated command line: quoted `path` followed by the
/// `argv_count` tokens (`argv[i]` is `argv_lens[i]` bytes), with argv[0] dropped
/// when it duplicates the path or its basename. Same buffer contract as
/// [`sw_escape_control`].
///
/// # Safety
/// `path` valid for `path_len` bytes (or null). `argv` and `argv_lens` valid for
/// `argv_count` elements (or null, treated as no argv); each `argv[i]` valid for
/// `argv_lens[i]` bytes. `out`/`needed` as in [`sw_escape_control`].
#[unsafe(no_mangle)]
pub extern "C" fn sw_full_command_line(
    path: *const u8,
    path_len: usize,
    argv: *const *const u8,
    argv_lens: *const usize,
    argv_count: usize,
    out: *mut u8,
    out_cap: usize,
    needed: *mut usize,
) -> c_int {
    let p = read_input(path, path_len);

    let mut owned: Vec<String> = Vec::new();
    if !argv.is_null() && !argv_lens.is_null() {
        for i in 0..argv_count {
            // SAFETY: caller guarantees argv/argv_lens hold argv_count elements.
            let tok_ptr = unsafe { *argv.add(i) };
            let tok_len = unsafe { *argv_lens.add(i) };
            owned.push(read_input(tok_ptr, tok_len));
        }
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    let mut result = String::new();
    full_command_line(&p, &refs, &mut result);
    write_result(&result, out, out_cap, needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(s: &str) -> String {
        let mut o = String::new();
        escape_control(s, &mut o);
        o
    }
    fn q(s: &str) -> String {
        let mut o = String::new();
        quote_token(s, &mut o);
        o
    }
    fn full(path: &str, argv: &[&str]) -> String {
        let mut o = String::new();
        full_command_line(path, argv, &mut o);
        o
    }

    #[test]
    fn named_escapes() {
        assert_eq!(esc("\n"), "\\n");
        assert_eq!(esc("\r"), "\\r");
        assert_eq!(esc("\t"), "\\t");
        assert_eq!(esc("\0"), "\\0");
        assert_eq!(esc("\\"), "\\\\");
    }

    #[test]
    fn antispoof_backslash() {
        // literal backslash-n must not collide with a real newline escape
        assert_eq!(esc("\\n"), "\\\\n");
        assert_ne!(esc("\\n"), esc("\n"));
    }

    #[test]
    fn hex_c0_del() {
        assert_eq!(esc("\u{07}"), "\\x07");
        assert_eq!(esc("\u{01}"), "\\x01");
        assert_eq!(esc("\u{1b}"), "\\x1b");
        assert_eq!(esc("\u{7f}"), "\\x7f");
    }

    #[test]
    fn c1_and_separators() {
        assert_eq!(esc("\u{80}"), "\\u0080");
        assert_eq!(esc("\u{85}"), "\\u0085");
        assert_eq!(esc("\u{9f}"), "\\u009f");
        assert_eq!(esc("\u{2028}"), "\\u2028");
        assert_eq!(esc("\u{2029}"), "\\u2029");
    }

    #[test]
    fn ellipsis_homoglyphs() {
        assert_eq!(esc("\u{2026}"), "\\u2026");
        assert_eq!(esc("\u{22ef}"), "\\u22ef");
        assert_eq!(esc("\u{2024}"), "\\u2024");
        assert_eq!(esc("\u{2025}"), "\\u2025");
    }

    #[test]
    fn bidi_and_zero_width() {
        for c in ['\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}', '\u{200e}',
                  '\u{200f}', '\u{061c}'] {
            assert_eq!(esc(&c.to_string()), format!("\\u{:04x}", c as u32));
        }
        for c in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'] {
            assert_eq!(esc(&c.to_string()), format!("\\u{:04x}", c as u32));
        }
    }

    #[test]
    fn dot_runs() {
        assert_eq!(esc("."), ".");
        assert_eq!(esc(".."), "..");
        assert_eq!(esc("..."), "\\u002e\\u002e\\u002e");
        assert_eq!(esc("a...b"), "a\\u002e\\u002e\\u002eb");
        assert_eq!(esc("a..b"), "a..b");
        assert_eq!(esc("..a.."), "..a..");
        // run then normal char transition
        assert_eq!(esc("...\n"), "\\u002e\\u002e\\u002e\\n");
    }

    #[test]
    fn passthrough() {
        assert_eq!(esc("abcXYZ012"), "abcXYZ012");
        assert_eq!(esc("a b c"), "a b c");
        assert_eq!(esc("+_/.:=@%,-"), "+_/.:=@%,-");
        assert_eq!(esc("😀"), "😀");
        assert_eq!(esc("日本語"), "日本語");
        assert_eq!(esc("café"), "café");
    }

    #[test]
    fn quote_basic() {
        assert_eq!(q(""), "''");
        assert_eq!(q("/bin/echo"), "/bin/echo");
        assert_eq!(q("a b"), "'a b'");
        assert_eq!(q("a'b"), "'a'\\''b'");
        assert_eq!(q("\t"), "'\\t'");
        assert_eq!(q("\\"), "'\\\\'");
    }

    #[test]
    fn full_command() {
        assert_eq!(full("/bin/echo", &["echo", "hello"]), "/bin/echo hello");
        assert_eq!(full("/bin/echo", &["/bin/echo", "hi"]), "/bin/echo hi");
        assert_eq!(full("/bin/echo", &["notecho", "hi"]), "/bin/echo notecho hi");
        assert_eq!(full("/bin/echo", &[]), "/bin/echo");
        assert_eq!(full("/bin/echo", &["echo", "a b"]), "/bin/echo 'a b'");
        assert_eq!(full("id", &["id"]), "id");
    }

    #[test]
    fn ffi_two_call_sizing() {
        let input = b"a b";
        let mut needed = 0usize;
        // probe
        let rc = sw_quote_token(input.as_ptr(), input.len(),
                                std::ptr::null_mut(), 0, &mut needed);
        assert_eq!(rc, SW_ESCAPE_TRUNCATED);
        assert_eq!(needed, 5); // 'a b'
        // real
        let mut buf = vec![0u8; needed + 1];
        let mut n2 = 0usize;
        let rc = sw_quote_token(input.as_ptr(), input.len(),
                                buf.as_mut_ptr(), buf.len(), &mut n2);
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(&buf[..n2], b"'a b'");
        assert_eq!(buf[n2], 0);
    }

    #[test]
    fn ffi_lossy_invalid_utf8() {
        // an invalid byte becomes U+FFFD, never a panic
        let input = [b'a', 0xff, b'b'];
        let mut needed = 0usize;
        sw_escape_control(input.as_ptr(), input.len(),
                          std::ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u8; needed + 1];
        let mut n2 = 0usize;
        let rc = sw_escape_control(input.as_ptr(), input.len(),
                                   buf.as_mut_ptr(), buf.len(), &mut n2);
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(&buf[..n2], "a\u{fffd}b".as_bytes());
    }
}
