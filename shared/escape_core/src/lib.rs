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

/// The displayable token list: the command path, then argv minus argv[0] when it
/// dups the path or its basename. Raw (unescaped) tokens -- quoting happens in the
/// renderers below. Port of
/// `+[SudoWhatPromptFormatter commandPartsForPath:argv:]`, and for the same
/// reason: the plain and the coloured renderer share one token list, so the two
/// can never disagree on which tokens the line has.
fn command_tokens<'a>(path: &'a str, argv: &'a [&'a str]) -> Vec<&'a str> {
    let mut toks: Vec<&str> = Vec::with_capacity(argv.len() + 1);
    toks.push(path);

    let basename = last_path_component(path);
    let mut start = 0usize;
    if !argv.is_empty() {
        let a0 = argv[0];
        if a0 == path || (!basename.is_empty() && a0 == basename) {
            start = 1;
        }
    }
    toks.extend_from_slice(&argv[start..]);
    toks
}

/// The full command line: quoted path, then argv minus argv[0] when it dups the
/// path or its basename. Port of
/// `-[SudoWhatPromptFormatter fullCommandLineForCommandPath:argv:]`.
pub fn full_command_line(path: &str, argv: &[&str], out: &mut String) {
    for (i, tok) in command_tokens(path, argv).iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        quote_token(tok, out);
    }
}

// -------------------------------------------------------------------------
// Colouriser. Layout over an already-escaped, already-quoted line: SGR
// sequences go only AROUND existing bytes, never between or instead of them,
// so stripping the SGR yields `full_command_line`'s bytes exactly (the
// round-trip invariant the tests pin). No wrapping, no elision, no reordering
// -- one logical line that the terminal soft-wraps.
// -------------------------------------------------------------------------

/// Fixed SGR palette. Kept in one reviewed place so the only escape bytes that
/// can reach the terminal are this closed set -- the classifier below is their
/// sole producer. The anomaly colours are the ones
/// `+[SudoWhatPromptFormatter colorizeEscaped:]` already ships; the program-path
/// pair is pinned's `prog_disp` treatment (dirname plain cyan, basename bold
/// cyan), so one house palette spans both tools.
///
/// Colour asserts only what sudowhat KNOWS, which is exactly three kinds of
/// thing: a structural fact (token[0] is the program, because sudo will execve
/// it), a fact about the bytes (control chars, deceptive Unicode, invisible
/// padding -- observations about the data, never readings of it), and our own
/// chrome (the quotes we invented to render an argv array as one pasteable
/// line). Dim is reserved for that third kind and means nothing else: THESE
/// BYTES ARE OURS, NOT THE DATA'S. Anything beyond those three would be a guess
/// about someone else's command grammar, which is why there is no flag colour
/// here -- see `colored_command_line`.
const SGR_RESET: &str = "\x1b[0m";
/// deceptive Unicode escapes: \uNNNN
const SGR_UNICODE: &str = "\x1b[1;31m";
/// control-byte escapes: \n \r \t \0 \xNN
const SGR_CONTROL: &str = "\x1b[1;35m";
/// shell metacharacters the DATA contained: " ` , the escaped backslash \\, and
/// a ' that arrived through the `'\''` idiom (see `colorize_escaped`)
const SGR_META: &str = "\x1b[1;36m";
/// notable whitespace runs: grey background, so invisible padding reads as a block
const SGR_SPACE: &str = "\x1b[100m";
/// program path, directory part
const SGR_PROG_DIR: &str = "\x1b[36m";
/// program path, basename -- the one token worth reading at the head of the line
const SGR_PROG_BASE: &str = "\x1b[1;36m";
/// our own chrome: the single quotes `quote_token` added, which were never bytes
/// of an argument. Nothing reaching sudo contains a quote -- sudo hands the
/// plugin an argv ARRAY -- so every quote on screen is one we invented while
/// rendering that array as a line, EXCEPT the ones that arrived through the
/// `'\''` idiom, which are the only way a quote the argument really contained
/// can be represented.
const SGR_OURS: &str = "\x1b[2m";
/// option flags: a rendered token that starts with '-'. Bold blue -- distinct
/// from the program's bold cyan and the frame's yellow, readable where plain
/// blue is not. This is a deliberately LEXICAL mark (by user choice: colour any
/// flag, no judgement): "starts with a dash" is not a claim about which flag is
/// dangerous -- sudowhat cannot know that (-rf looks like a flag, if=/dev/zero
/// does not), and a token that needed quoting renders as '...' (leading quote,
/// not dash) so hostile input still reads as data, never borrows the flag look.
const SGR_FLAG: &str = "\x1b[1;34m";

/// Emit one plain char, arming `base` first if it is not already in effect.
fn push_plain(c: char, base: &str, armed: &mut bool, out: &mut String) {
    if !base.is_empty() && !*armed {
        out.push_str(base);
        *armed = true;
    }
    out.push(c);
}

/// Emit an anomaly span in `color`, dropping any armed role colour around it so
/// the anomaly reads the same whatever role it sits in.
fn push_span(text: &str, color: &str, armed: &mut bool, out: &mut String) {
    if *armed {
        out.push_str(SGR_RESET);
        *armed = false;
    }
    out.push_str(color);
    out.push_str(text);
    out.push_str(SGR_RESET);
}

/// Colourise one ALREADY-escaped, already-quoted span: anomaly runs take the
/// fixed palette, everything else takes `base` (empty = plain). Grew out of
/// `+[SudoWhatPromptFormatter colorizeEscaped:]`, with the role colour added
/// underneath and single quotes split by who wrote them (see the walk below);
/// that ObjC method has no production callers and is not kept in step on this
/// point. Purely additive -- stripping the SGR returns `s`.
fn colorize_escaped(s: &str, base: &str, out: &mut String) {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0usize;
    let mut armed = false;

    while i < len {
        let c = chars[i];

        // Backslash escapes emitted by escape_control. Every '\' it produces is
        // followed by one of {\ n r t 0 x u}; quote_token adds only the shell
        // idiom '\'' (a '\' before a single quote). We classify by the second
        // char and wrap the whole fixed-width sequence as one unit -- so a "\\"
        // is consumed together and its second '\' is never re-read as the start
        // of another escape. A '\' before anything else (the quote idiom, or an
        // input that cannot arise from our escapers) is emitted plain.
        if c == '\\' && i + 1 < len {
            let n = chars[i + 1];
            let (color, span) = match n {
                'u' => (SGR_UNICODE, 6),                    // \uNNNN
                'x' => (SGR_CONTROL, 4),                    // \xNN
                'n' | 'r' | 't' | '0' => (SGR_CONTROL, 2),  // \n \r \t \0
                '\\' => (SGR_META, 2),                      // literal '\'
                _ => ("", 0),
            };
            if !color.is_empty() && i + span <= len {
                let text: String = chars[i..i + span].iter().collect();
                push_span(&text, color, &mut armed, out);
                i += span;
                continue;
            }
            push_plain(c, base, &mut armed, out);   // lone '\' (the '\'' idiom)
            i += 1;
            // Quote attribution, and the ONLY place it is decided. A lone '\'
            // surviving the match above can only be the one quote_token splices
            // in front of a quote the ARGUMENT contained, so the ' right after
            // it is the data's and stays lit -- consumed here so it cannot reach
            // the branch below, which treats every ' it sees as ours. Doing it
            // inside this left-to-right walk is what makes the rule correct: the
            // walk has already eaten "\\" as one unit, so the second '\' of a
            // doubled backslash never masquerades as this one. As a regex
            // lookbehind over the finished string the same rule is WRONG --
            // input \' renders \\'\'' , whose third char is OUR closing quote
            // and IS preceded by a backslash.
            if i < len && chars[i] == '\'' {
                push_span("'", SGR_META, &mut armed, out);
                i += 1;
            }
            continue;
        }

        // A single quote reached directly, i.e. not through the idiom above, is
        // one WE added -- chrome, not content -- so it renders dim. '"' and '`'
        // are never added by us at all, so they are unconditionally the data's.
        if c == '\'' {
            push_span("'", SGR_OURS, &mut armed, out);
            i += 1;
            continue;
        }
        if c == '"' || c == '`' {
            push_span(&c.to_string(), SGR_META, &mut armed, out);
            i += 1;
            continue;
        }

        // Whitespace runs. Mark a run of spaces that is >=2 long or touches the
        // start/end of the span -- the invisible-padding cases (a trailing space
        // on a path, a hidden double space). A single interior space is a normal
        // separator and stays plain, so ordinary commands are unmarked. Note the
        // span, not the line, bounds "start/end" here: the only extra boundary a
        // per-span walk introduces is the program's dirname/basename seam, and a
        // space there gets MARKED where the line-level walk left it plain -- more
        // emphasis on invisible padding, never less.
        if c == ' ' {
            let mut j = i + 1;
            while j < len && chars[j] == ' ' {
                j += 1;
            }
            let run: String = chars[i..j].iter().collect();
            if j - i >= 2 || i == 0 || j == len {
                push_span(&run, SGR_SPACE, &mut armed, out);
            } else {
                for ch in run.chars() {
                    push_plain(ch, base, &mut armed, out);
                }
            }
            i = j;
            continue;
        }

        push_plain(c, base, &mut armed, out);
        i += 1;
    }

    if armed {
        out.push_str(SGR_RESET);
    }
}

/// The full command line as [`full_command_line`] builds it, with SGR colour
/// layered on by role: the program's directory part plain cyan and its basename
/// bold cyan, option flags bold blue, every other token plain, our own quotes
/// dim, and anomalous spans (deceptive Unicode, control-byte escapes, shell
/// metacharacters, notable whitespace) in the anomaly palette on top. One
/// logical line -- nothing is wrapped, elided or reordered, and the bytes
/// between the SGR sequences are exactly the plain line's bytes.
///
/// Option flags (a rendered token starting with '-') are coloured by user
/// choice: colour any flag, no judgement. This is a LEXICAL mark, not a claim
/// about which flag is dangerous -- "starts with a dash" is wrong after `--`
/// and blind to `dd if=...` or `tar xvf`, and sudowhat has no standing to say
/// which is which. It stays honest about hostile input because a token that
/// needed quoting renders as '...' (leading quote, not dash) and so is never
/// mistaken for a flag. Dim therefore still means exactly one thing (our own
/// quotes); the flag colour is a separate role, not a second meaning for dim.
pub fn colored_command_line(path: &str, argv: &[&str], out: &mut String) {
    for (i, tok) in command_tokens(path, argv).iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut rendered = String::new();
        quote_token(tok, &mut rendered);

        if i == 0 {
            // Split at the last '/' of the RENDERED token: escape_control emits
            // '/' for nothing but a literal '/', so this is the same separator
            // last_path_component would find, and slicing after it stays on a
            // char boundary. No '/' -> the whole token is the basename.
            match rendered.rfind('/') {
                Some(idx) => {
                    colorize_escaped(&rendered[..=idx], SGR_PROG_DIR, out);
                    colorize_escaped(&rendered[idx + 1..], SGR_PROG_BASE, out);
                }
                None => colorize_escaped(&rendered, SGR_PROG_BASE, out),
            }
        } else if rendered.starts_with('-') {
            // Option flag (lexical: the rendered token starts with '-'). A token
            // that needed quoting renders as '...' with a leading quote, so it
            // never reaches here -- hostile input stays data-coloured.
            colorize_escaped(&rendered, SGR_FLAG, out);
        } else {
            // Values carry no role colour; only the anomaly palette and our own
            // quotes mark anything inside them.
            colorize_escaped(&rendered, "", out);
        }
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

/// Decode the `argv_count` tokens of a C argv array, lossily. A null `argv` or
/// `argv_lens` yields no tokens.
///
/// # Safety
/// `argv` and `argv_lens` must be valid for `argv_count` elements (or null), and
/// each `argv[i]` valid for `argv_lens[i]` bytes.
fn read_argv(argv: *const *const u8, argv_lens: *const usize, argv_count: usize) -> Vec<String> {
    let mut owned: Vec<String> = Vec::new();
    if !argv.is_null() && !argv_lens.is_null() {
        for i in 0..argv_count {
            // SAFETY: caller guarantees argv/argv_lens hold argv_count elements.
            let tok_ptr = unsafe { *argv.add(i) };
            let tok_len = unsafe { *argv_lens.add(i) };
            owned.push(read_input(tok_ptr, tok_len));
        }
    }
    owned
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
    let owned = read_argv(argv, argv_lens, argv_count);
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    let mut result = String::new();
    full_command_line(&p, &refs, &mut result);
    write_result(&result, out, out_cap, needed)
}

/// The same line as [`sw_full_command_line`], with SGR colour layered on by role
/// (program dirname / basename, our own quotes) and the anomaly palette on
/// escaped spans. Byte-identical to that function once the SGR is stripped, and
/// still one logical line. Same buffer contract as [`sw_escape_control`].
///
/// The caller decides whether colour is permitted at all (build-time knob plus
/// the NO_COLOR / TERM / isatty gates) and must fall back to
/// [`sw_full_command_line`] if this returns anything but [`SW_ESCAPE_OK`].
///
/// # Safety
/// See [`sw_full_command_line`].
#[unsafe(no_mangle)]
pub extern "C" fn sw_full_command_line_colored(
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
    let owned = read_argv(argv, argv_lens, argv_count);
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    let mut result = String::new();
    colored_command_line(&p, &refs, &mut result);
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

    // --- colouriser -------------------------------------------------------

    fn colored(path: &str, argv: &[&str]) -> String {
        let mut o = String::new();
        colored_command_line(path, argv, &mut o);
        o
    }

    /// Remove every SGR sequence, so what is left is the bytes the terminal
    /// actually shows. Deliberately dumb (ESC '[' ... 'm') -- the colouriser
    /// emits nothing else, and a stricter parser would hide a regression that
    /// emitted something else.
    fn strip_sgr(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\x1b' {
                // consume "[...m"
                for c2 in it.by_ref() {
                    if c2 == 'm' {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    /// The cases the byte-preservation invariant is checked over: clean lines,
    /// quoting triggers, every escape family, and the hostile tokens the display
    /// exists to expose.
    fn color_cases() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("/bin/echo", vec!["echo", "hello"]),
            ("/bin/echo", vec![]),
            ("id", vec!["id"]),
            ("", vec![]),
            ("", vec![""]),
            ("/usr/bin/git", vec!["git", "status", "--porcelain"]),
            (
                "/run/current-system/sw/bin/pinned",
                vec!["pinned", "review", "--file", "/Library/App Support/x.json"],
            ),
            ("/bin/echo", vec!["echo", "a b", "a'b", "-", "--", "-x"]),
            ("/bin/echo", vec!["echo", "sudowhat: user: evil"]),
            ("/bin/echo", vec!["echo", "a\nb", "a\tb", "a\\b", "a\u{202e}b"]),
            ("/bin/echo", vec!["echo", "...", "  padded  ", ""]),
            ("/usr/bin/日本", vec!["日本", "café", "😀"]),
            ("/a b/prog name", vec!["prog name"]),
            ("/usr/bin/", vec!["-v"]),
            ("prog", vec!["prog", "-f", "v"]),
        ]
    }

    #[test]
    fn colored_preserves_bytes() {
        // The invariant: colour is layout, never content. Strip the SGR and the
        // plain line must come back byte for byte.
        for (path, argv) in color_cases() {
            let c = colored(path, &argv);
            assert_eq!(strip_sgr(&c), full(path, &argv), "path={path:?} argv={argv:?}");
        }
    }

    #[test]
    fn colored_never_emits_a_raw_control_byte() {
        // Every ESC in the output must start one of our SGR sequences, and no
        // other C0 byte may appear -- the input is attacker-influenced.
        for (path, argv) in color_cases() {
            let c = colored(path, &argv);
            let chars: Vec<char> = c.chars().collect();
            for (i, ch) in chars.iter().enumerate() {
                let u = *ch as u32;
                if u == 0x1b {
                    assert_eq!(chars.get(i + 1), Some(&'['), "ESC not starting a CSI");
                } else {
                    assert!(u >= 0x20 || u == 0x1b, "raw control byte {u:#x} in output");
                }
            }
        }
    }

    #[test]
    fn colored_program_roles() {
        // dirname plain cyan, basename bold cyan, each closed by a reset.
        assert_eq!(
            colored("/bin/echo", &["echo"]),
            "\x1b[36m/bin/\x1b[0m\x1b[1;36mecho\x1b[0m"
        );
        // no '/' at all -> the whole program token is the basename.
        assert_eq!(colored("id", &["id"]), "\x1b[1;36mid\x1b[0m");
    }

    #[test]
    fn colored_flag_and_value_roles() {
        // Flags are bold blue (by user choice: colour any flag, no judgement);
        // values stay unstyled. The flag colour is a role of its own, so dim
        // continues to mean exactly one thing: our own quotes.
        assert_eq!(
            colored("/bin/git", &["git", "--file", "x"]),
            "\x1b[36m/bin/\x1b[0m\x1b[1;36mgit\x1b[0m \x1b[1;34m--file\x1b[0m x"
        );
        // a bare "-" / "--" is lexically a flag too -- the mark is lexical, not a
        // judgement about what the token means.
        assert_eq!(colored("p", &["p", "--"]), "\x1b[1;36mp\x1b[0m \x1b[1;34m--\x1b[0m");
        // dim still appears only where our quoting does, never on a flag.
        assert!(!colored("/bin/git", &["git", "-rf", "x"]).contains("\x1b[2m"));
    }

    #[test]
    fn colored_hostile_token_reads_as_data() {
        // A token spelled like one of our own lines lands quoted, and the quotes
        // are metachar-coloured, so it cannot pass for a real sudowhat line.
        // The wrapping quotes are OURS, so they read dim -- the token's own
        // bytes stay at full weight, which is the point: the reader sees data
        // inside chrome, not a second sudowhat line.
        let c = colored("/bin/echo", &["echo", "sudowhat: user: evil"]);
        assert!(c.ends_with("\x1b[2m'\x1b[0m"), "unterminated quote: {c:?}");
        assert!(c.contains("\x1b[2m'\x1b[0msudowhat:"), "opening quote: {c:?}");
        // the whitespace run rule marks the interior spaces of the quoted token
        // only when they are runs or at an edge; single ones stay plain.
        assert_eq!(strip_sgr(&c), "/bin/echo 'sudowhat: user: evil'");
    }

    #[test]
    fn colored_anomaly_palette() {
        // control-byte, deceptive-Unicode and metachar escapes each take their
        // own colour, over whatever role colour the token carries.
        let c = colored("/bin/echo", &["echo", "a\nb"]);
        assert!(c.contains("\x1b[1;35m\\n\x1b[0m"), "control escape: {c:?}");
        let c = colored("/bin/echo", &["echo", "\u{202e}x"]);
        assert!(c.contains("\x1b[1;31m\\u202e\x1b[0m"), "unicode escape: {c:?}");
        let c = colored("/bin/echo", &["echo", "a\\b"]);
        assert!(c.contains("\x1b[1;36m\\\\\x1b[0m"), "backslash: {c:?}");
        // notable whitespace keeps its grey background inside a quoted token.
        let c = colored("p", &["p", "-x  y"]);
        assert!(c.contains("\x1b[100m  \x1b[0m"), "space run: {c:?}");
    }

    #[test]
    fn colored_anomaly_in_the_program_token() {
        // An escape inside the program path drops the role colour for its span
        // and the role resumes after it -- the bytes still round-trip.
        let c = colored("/bin/\u{202e}sh", &[]);
        assert_eq!(strip_sgr(&c), "'/bin/\\u202esh'");
        assert!(c.contains("\x1b[1;31m\\u202e\x1b[0m"), "{c:?}");
    }

    #[test]
    fn colored_empty_argv() {
        // an empty command word renders as the empty quoted token: the token
        // contributed no bytes at all, so BOTH quotes are ours and both dim.
        assert_eq!(colored("", &[]), "\x1b[2m'\x1b[0m\x1b[2m'\x1b[0m");
        assert_eq!(strip_sgr(&colored("", &[])), "''");
        assert_eq!(strip_sgr(&colored("/bin/ls", &[])), "/bin/ls");
    }

    /// Colourise ONE token exactly as `colored_command_line` does for a non-
    /// program token: quote it, then walk it with no role colour underneath.
    fn colored_token(t: &str) -> String {
        let mut rendered = String::new();
        quote_token(t, &mut rendered);
        let mut out = String::new();
        colorize_escaped(&rendered, "", &mut out);
        out
    }

    /// Count the ' characters in a colourised span by the SGR span each one sits
    /// in: (lit metachar, dim ours). Panics if a quote reaches the terminal with
    /// no attributing span at all -- that would be a quote the walk classified
    /// as neither, which is exactly the regression this oracle exists to catch.
    fn quote_attribution(span: &str) -> (usize, usize) {
        let mut lit = 0usize;
        let mut dim = 0usize;
        let mut cur = String::new();
        let mut it = span.chars();
        while let Some(c) = it.next() {
            if c == '\x1b' {
                let mut seq = String::from("\x1b");
                for c2 in it.by_ref() {
                    seq.push(c2);
                    if c2 == 'm' {
                        break;
                    }
                }
                cur = if seq == SGR_RESET { String::new() } else { seq };
                continue;
            }
            if c == '\'' {
                if cur == SGR_META {
                    lit += 1;
                } else if cur == SGR_OURS {
                    dim += 1;
                } else {
                    panic!("quote outside any attributing span ({cur:?}) in {span:?}");
                }
            }
        }
        (lit, dim)
    }

    #[test]
    fn quote_attribution_oracle() {
        // Ground truth, countable WITHOUT carrying it out of the quoter: sudo
        // hands the plugin an argv ARRAY, so nothing that reaches us contains a
        // quote we did not write ourselves. The data's quotes in a rendered
        // token are therefore exactly the ' characters escape_control leaves in
        // it; every OTHER ' on screen is chrome and must be dim. Pinning that
        // count is what makes the walk's inference as trustworthy as a span list
        // carried from quote_token, while keeping quoting and colour separate.
        //
        // The bad direction is a DATA quote rendered dim -- it would understate
        // hostile content. Under the current escapers it is unreachable (the
        // only lone '\' surviving the walk is the idiom's), and this test is
        // what keeps it unreachable.
        let cases = [
            "",                 // both quotes ours, no data at all
            "no_quotes_here",   // safe set: no quoting, so no quotes at all
            "a b",              // quoted for the space; both quotes ours
            "'",                // a lone quote
            "'a",               // quote at the head
            "a'",               // quote at the tail
            "'a'",              // a quote at each end
            "a'b",              // the plain idiom
            "'''",              // three spliced idioms in a row
            "''",               // two
            "don't",
            "it's a 'test'",
            "\\",               // one literal backslash, no quote
            "\\\\",             // two
            "\\'",              // the trap: renders \\'\'' , third char is OURS
            "\\\\'",            // and with the doubling one deeper
            "a\\'b",
            "\\n'",             // literal backslash-n before a data quote
            "\n'",              // a REAL newline before a data quote
            "'\n'",             // data quotes around a real newline
            "'\t'",
            "\u{202e}'",        // bidi override then a data quote
            "'\u{202e}",
            "caf\u{e9}'x",      // non-ASCII either side of a data quote
            "\u{1f600}'",       // astral scalar then a data quote
            "\u{65e5}\u{672c}'",
        ];
        for t in cases {
            let span = colored_token(t);
            let (lit, dim) = quote_attribution(&span);

            let expected_lit = esc(t).chars().filter(|&c| c == '\'').count();
            assert_eq!(lit, expected_lit, "data-quote count for {t:?} in {span:?}");

            // Nothing went unattributed: every ' the plain token shows was
            // counted into exactly one of the two buckets.
            let rendered = q(t);
            let total = rendered.chars().filter(|&c| c == '\'').count();
            assert_eq!(lit + dim, total, "unattributed quote for {t:?} in {span:?}");

            // And the round-trip invariant holds at token granularity too.
            assert_eq!(strip_sgr(&span), rendered, "round trip for {t:?}");
        }
    }

    #[test]
    fn colored_quote_roles() {
        // The idiom pinned to exact bytes, so a future escaping change has to
        // walk past this. 'a'\''b' is five quotes: open(ours), close(ours),
        // a plain '\', the DATA's, reopen(ours), close(ours).
        assert_eq!(
            colored_token("a'b"),
            "\x1b[2m'\x1b[0ma\x1b[2m'\x1b[0m\\\x1b[1;36m'\x1b[0m\
             \x1b[2m'\x1b[0mb\x1b[2m'\x1b[0m"
        );
        // '"' and '`' are never ours, so they are lit wherever they appear.
        let c = colored_token("a\"b`c");
        assert!(c.contains("\x1b[1;36m\"\x1b[0m"), "double quote lit: {c:?}");
        assert!(c.contains("\x1b[1;36m`\x1b[0m"), "backtick lit: {c:?}");
    }

    #[test]
    fn ffi_colored_two_call_sizing() {
        let path = b"/bin/echo";
        let a0 = b"echo";
        let argv: [*const u8; 1] = [a0.as_ptr()];
        let lens: [usize; 1] = [a0.len()];

        let mut needed = 0usize;
        let rc = sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            std::ptr::null_mut(), 0, &mut needed,
        );
        assert_eq!(rc, SW_ESCAPE_TRUNCATED);

        let mut buf = vec![0u8; needed + 1];
        let mut got = 0usize;
        let rc = sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            buf.as_mut_ptr(), buf.len(), &mut got,
        );
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(buf[got], 0);
        assert_eq!(
            std::str::from_utf8(&buf[..got]).unwrap(),
            "\x1b[36m/bin/\x1b[0m\x1b[1;36mecho\x1b[0m"
        );
    }

    #[test]
    fn ffi_colored_null_argv_and_invalid_utf8() {
        // null argv -> path-only line, no panic.
        let path = b"/bin/ls";
        let mut needed = 0usize;
        sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            std::ptr::null(), std::ptr::null(), 3,
            std::ptr::null_mut(), 0, &mut needed,
        );
        let mut buf = vec![0u8; needed + 1];
        let mut got = 0usize;
        let rc = sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            std::ptr::null(), std::ptr::null(), 3,
            buf.as_mut_ptr(), buf.len(), &mut got,
        );
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(
            std::str::from_utf8(&buf[..got]).unwrap(),
            "\x1b[36m/bin/\x1b[0m\x1b[1;36mls\x1b[0m"
        );

        // an invalid UTF-8 byte in a token becomes U+FFFD, never a panic, and
        // the coloured line still strips back to the plain one.
        let bad = [b'a', 0xff, b'b'];
        let argv: [*const u8; 1] = [bad.as_ptr()];
        let lens: [usize; 1] = [bad.len()];
        let mut needed = 0usize;
        sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            std::ptr::null_mut(), 0, &mut needed,
        );
        let mut buf = vec![0u8; needed + 1];
        let mut got = 0usize;
        let rc = sw_full_command_line_colored(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            buf.as_mut_ptr(), buf.len(), &mut got,
        );
        assert_eq!(rc, SW_ESCAPE_OK);
        let s = std::str::from_utf8(&buf[..got]).unwrap();
        assert_eq!(strip_sgr(s), "/bin/ls 'a\u{fffd}b'");
    }

    #[test]
    fn ffi_colored_matches_plain_after_stripping() {
        // The FFI pair, not just the Rust pair: the two entry points the plugin
        // picks between must agree byte for byte modulo SGR.
        let path = b"/usr/bin/git";
        let toks: [&[u8]; 3] = [b"git", b"commit", b"--amend"];
        let argv: Vec<*const u8> = toks.iter().map(|t| t.as_ptr()).collect();
        let lens: Vec<usize> = toks.iter().map(|t| t.len()).collect();

        let render = |f: unsafe extern "C" fn(
            *const u8, usize, *const *const u8, *const usize, usize,
            *mut u8, usize, *mut usize,
        ) -> c_int| {
            let mut needed = 0usize;
            unsafe {
                f(path.as_ptr(), path.len(), argv.as_ptr(), lens.as_ptr(), toks.len(),
                  std::ptr::null_mut(), 0, &mut needed);
            }
            let mut buf = vec![0u8; needed + 1];
            let mut got = 0usize;
            let rc = unsafe {
                f(path.as_ptr(), path.len(), argv.as_ptr(), lens.as_ptr(), toks.len(),
                  buf.as_mut_ptr(), buf.len(), &mut got)
            };
            assert_eq!(rc, SW_ESCAPE_OK);
            String::from_utf8(buf[..got].to_vec()).unwrap()
        };

        let plain = render(sw_full_command_line);
        let color = render(sw_full_command_line_colored);
        assert_eq!(strip_sgr(&color), plain);
        assert_ne!(color, plain);
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
