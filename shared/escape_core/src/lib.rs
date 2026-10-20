//! escape_core -- the stateless anti-spoofing string core for sudowhat.
//!
//! It renders untrusted text (argv, the target user, a directory, a PATH) for
//! display so the reader sees exactly the characters that are there, following
//! the house untrusted-text rules. It is the one renderer for every surface:
//! the terminal lines both macOS bundles print, the Touch ID sheet's values
//! (`plugin/PromptFormatter.m` lays the sheet out and calls the C ABI below for
//! every value), and the pure-Rust Linux plugin (no Apple frameworks). One
//! renderer means the sheet and the terminal cannot disagree on a token;
//! `tests/test_escape_core.m` holds the sheet's command to the terminal's line
//! byte for byte.
//!
//! The rules, in brief (the untrusted-text skill holds the full text):
//!
//! - **Hidden.** A code point on the hidden list (C0 and C1 controls, DEL,
//!   bidi controls, zero-width and other invisible format characters, the
//!   unusual spaces, variation selectors, tags) shows as `\u{HEX}`: uppercase
//!   hex, no leading zeros, the closing brace ending the escape. A terminal
//!   rendering wraps it in reverse red, the one style reserved for it.
//! - **Kept.** Every other escape shows unstyled: a byte that is not valid
//!   UTF-8 as `\xHH`, one escape per byte, after every valid sequence has been
//!   decoded (`C3 A9 FF` shows as `é\xFF`); and a literal backslash that would
//!   otherwise begin an escape -- one before `u{`, or before `x` and a hex
//!   digit -- as `\u{5C}`, its own escape. Every other backslash is drawn as
//!   itself, so an escape on screen can only ever be one.
//! - Everything else is drawn as itself. Lookalikes (`...` against U+2026) are
//!   out of scope: the display's layout answers them, not escaping.
//!
//! Threat note: the input is attacker-influenced (`sudo <anything>`). The
//! output carries no raw control byte for any input, so writing it to a
//! terminal injects no control sequence; the only escape bytes a coloured
//! rendering emits are the fixed SGR palette below.
//!
//! FFI contract: `#[no_mangle] extern "C"` functions write into a caller buffer
//! and never unwind (`panic = "abort"` in release). Input is read as raw bytes,
//! never rejected: invalid UTF-8 shows as `\xHH`, so a display path names the
//! bytes that were there instead of hiding them behind a replacement glyph.

use std::os::raw::c_int;
use std::slice;

/// Output written successfully (buffer held the whole result plus a NUL).
pub const SW_ESCAPE_OK: c_int = 0;
/// Output buffer too small; `*needed` holds the required byte length (excluding
/// the NUL). Nothing was written. Callers may reallocate `*needed + 1` and retry.
pub const SW_ESCAPE_TRUNCATED: c_int = 1;

// -------------------------------------------------------------------------
// Escaping. Operates on the raw bytes: valid UTF-8 is decoded to scalar
// values, and only the bytes that fail to decode are escaped as bytes.
// -------------------------------------------------------------------------

/// The hidden list of the untrusted-text rules, verbatim: code points that draw
/// nothing, draw as something else, or reorder the text after them. A plain
/// space (U+0020) is not on it.
fn is_hidden(u: u32) -> bool {
    matches!(u,
        0x0000..=0x001F | 0x007F..=0x009F | 0x00A0 | 0x00AD | 0x034F | 0x061C
        | 0x115F..=0x1160 | 0x17B4..=0x17B5 | 0x180B..=0x180E
        | 0x2000..=0x200F | 0x2028..=0x202F | 0x205F..=0x206F
        | 0x3000 | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0
        | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F | 0xE0100..=0xE01EF)
}

/// One displayed unit of an escaped value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Piece {
    /// A character the value really holds, drawn as itself.
    Char(char),
    /// A hidden-list code point, drawn as its escape in the reserved style.
    Hidden(u32),
    /// A byte that is not valid UTF-8: a kept escape, `\xHH`.
    Byte(u8),
    /// A literal backslash that would otherwise begin an escape: a kept
    /// escape, the backslash's own `\u{5C}`.
    Backslash,
}

impl Piece {
    /// Append what this piece shows on screen.
    fn push_text(self, out: &mut String) {
        match self {
            Piece::Char(c) => out.push(c),
            Piece::Hidden(u) => push_code_point(out, u),
            Piece::Byte(b) => push_byte(out, b),
            Piece::Backslash => push_code_point(out, '\\' as u32),
        }
    }

    fn text(self) -> String {
        let mut s = String::new();
        self.push_text(&mut s);
        s
    }
}

/// Append the escape of one code point: backslash, `u{`, uppercase hex with
/// no leading zeros, `}`.
fn push_code_point(out: &mut String, u: u32) {
    out.push('\\');
    out.push('u');
    out.push('{');
    out.push_str(&format!("{u:X}"));
    out.push('}');
}

/// Append the escape of one byte that is not valid UTF-8: `\x` and two
/// uppercase hex digits.
fn push_byte(out: &mut String, b: u8) {
    out.push_str(&format!("\\x{b:02X}"));
}

/// Whether a backslash followed by `rest` would read as the start of an
/// escape: `u{`, or `x` and a hex digit. Only such a backslash is escaped
/// itself (promise 2: the introducer always begins an escape).
fn begins_escape(rest: &[Result<char, u8>]) -> bool {
    match rest {
        [Ok('u'), Ok('{'), ..] => true,
        [Ok('x'), Ok(h), ..] => h.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Split raw bytes into displayed pieces. Every valid UTF-8 sequence decodes
/// first; only the bytes that fail are escaped, one per byte.
fn pieces(bytes: &[u8]) -> Vec<Piece> {
    let mut decoded: Vec<Result<char, u8>> = Vec::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        decoded.extend(chunk.valid().chars().map(Ok));
        decoded.extend(chunk.invalid().iter().map(|&b| Err(b)));
    }
    let mut out = Vec::with_capacity(decoded.len());
    for (i, d) in decoded.iter().enumerate() {
        out.push(match *d {
            Err(b) => Piece::Byte(b),
            Ok(c) if is_hidden(c as u32) => Piece::Hidden(c as u32),
            Ok('\\') if begins_escape(&decoded[i + 1..]) => Piece::Backslash,
            Ok(c) => Piece::Char(c),
        });
    }
    out
}

/// Escape raw bytes for display: hidden code points and invalid bytes become
/// escapes, a backslash that would begin an escape becomes its own, and every
/// other character is itself. Unstyled.
pub fn escape_bytes(input: &[u8], out: &mut String) {
    for p in pieces(input) {
        p.push_text(out);
    }
}

/// [`escape_bytes`] over a `&str`, which holds no invalid bytes.
pub fn escape_control(input: &str, out: &mut String) {
    escape_bytes(input.as_bytes(), out);
}

// -------------------------------------------------------------------------
// Quoting and the command line. A token is rendered once, as a list of marked
// parts whose texts concatenate to the plain token; the plain line and both
// coloured lines are built from that one list, so the colours are composed
// from the parts and never recovered by re-parsing the rendered text.
// -------------------------------------------------------------------------

/// The conservative safe set: a token made only of these characters (and no
/// escape) is emitted unquoted.
fn is_safe(c: char) -> bool {
    matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9'
        | '+' | '_' | '.' | '/' | ':' | '=' | '@' | '%' | ',' | '-')
}

/// What a rendered part is, which decides its colour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mark {
    /// The token's own characters, kept escapes, and the backslash of the
    /// `'\''` idiom: the base colour of the token's role.
    Plain,
    /// A single quote the renderer added to show an argv element as one
    /// pasteable token: chrome, never a byte of the argument.
    Ours,
    /// A shell metacharacter the argument itself holds: `"`, a backtick, or a
    /// `'` (which can only arrive through the `'\''` idiom).
    Meta,
    /// The escape of a hidden code point: the reserved style.
    Hidden,
}

/// One rendered part: its text and what it is.
type Part = (String, Mark);

/// A rendered token: marked parts whose texts concatenate to the plain token.
type Rendered = Vec<Part>;

/// Render one token: escaped, and single-quoted when it holds anything outside
/// the safe set (any escape included). A quote inside a quoted token takes the
/// classic POSIX `'\''`.
fn render_token(raw: &[u8]) -> Rendered {
    let ours = || ("'".to_string(), Mark::Ours);
    if raw.is_empty() {
        // The empty token contributed no bytes at all: both quotes are ours.
        return vec![ours(), ours()];
    }
    let ps = pieces(raw);
    let mut r = Vec::with_capacity(ps.len() + 2);
    if ps.iter().all(|p| matches!(p, Piece::Char(c) if is_safe(*c))) {
        r.extend(ps.iter().map(|p| (p.text(), Mark::Plain)));
        return r;
    }
    r.push(ours());
    for p in ps {
        match p {
            Piece::Char('\'') => {
                r.push(ours());
                r.push(("\\".to_string(), Mark::Plain));
                r.push(("'".to_string(), Mark::Meta));
                r.push(ours());
            }
            Piece::Char(c @ ('"' | '`')) => r.push((c.to_string(), Mark::Meta)),
            Piece::Hidden(_) => r.push((p.text(), Mark::Hidden)),
            Piece::Char(_) | Piece::Byte(_) | Piece::Backslash => {
                r.push((p.text(), Mark::Plain))
            }
        }
    }
    r.push(ours());
    r
}

fn push_rendered(r: &Rendered, out: &mut String) {
    for (t, _) in r {
        out.push_str(t);
    }
}

/// Shell-quote and escape one token of raw bytes.
pub fn quote_bytes(input: &[u8], out: &mut String) {
    push_rendered(&render_token(input), out);
}

/// [`quote_bytes`] over a `&str`.
pub fn quote_token(input: &str, out: &mut String) {
    quote_bytes(input.as_bytes(), out);
}

/// NSString `lastPathComponent` for the common cases the dedup compares against:
/// strip trailing slashes, take the segment after the final '/'. An all-slash
/// string is "/". Empty is "".
fn last_path_component(p: &[u8]) -> &[u8] {
    if p.is_empty() {
        return b"";
    }
    let mut end = p.len();
    while end > 0 && p[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        return b"/";
    }
    let trimmed = &p[..end];
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(idx) => &trimmed[idx + 1..],
        None => trimmed,
    }
}

/// The displayable token list: the command path, then argv minus argv[0] when it
/// dups the path or its basename. Raw (unescaped) tokens -- rendering happens
/// below. The plain and the coloured renderers share this one token list, so
/// they can never disagree on which tokens the line has.
fn command_tokens<'a>(path: &'a [u8], argv: &[&'a [u8]]) -> Vec<&'a [u8]> {
    let mut toks: Vec<&[u8]> = Vec::with_capacity(argv.len() + 1);
    toks.push(path);

    let basename = last_path_component(path);
    let mut start = 0usize;
    if let Some(&a0) = argv.first()
        && (a0 == path || (!basename.is_empty() && a0 == basename))
    {
        start = 1;
    }
    toks.extend_from_slice(&argv[start..]);
    toks
}

/// The full command line over raw bytes: quoted path, then argv minus argv[0]
/// when it dups the path or its basename.
pub fn full_command_line_bytes(path: &[u8], argv: &[&[u8]], out: &mut String) {
    for (i, tok) in command_tokens(path, argv).iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        quote_bytes(tok, out);
    }
}

/// [`full_command_line_bytes`] over `&str` tokens.
pub fn full_command_line(path: &str, argv: &[&str], out: &mut String) {
    let raw: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    full_command_line_bytes(path.as_bytes(), &raw, out);
}

// -------------------------------------------------------------------------
// Colouriser. SGR goes only AROUND the rendered parts, never between or
// instead of their bytes, so stripping the SGR yields `full_command_line`'s
// bytes exactly (the round-trip invariant the tests pin). No wrapping, no
// elision, no reordering -- one logical line that the terminal soft-wraps.
// -------------------------------------------------------------------------

/// Fixed SGR palette. Kept in one reviewed place so the only escape bytes that
/// can reach the terminal are this closed set. The program path is sudowhat's
/// own (user choice, 2026-09-16), shared with the frame's directory: and PATH:
/// rows so every path in the frame reads one way: its first segment bold cyan,
/// the rest of the directory plain, the basename bold blue. The first segment
/// is where a path says where it lives (/run, /nix, /usr against /Users),
/// which is where a shadowed program shows.
///
/// Colour asserts only what sudowhat KNOWS, which is exactly three kinds of
/// thing: a structural fact (token[0] is the program, because sudo will execve
/// it), a fact about the bytes (a hidden code point, a shell metacharacter,
/// invisible padding -- observations about the data, never readings of it),
/// and our own chrome (the quotes we invented to render an argv array as one
/// pasteable line). Dim is reserved for that third kind and means nothing else:
/// THESE BYTES ARE OURS, NOT THE DATA'S. Anything beyond those three would be a
/// guess about someone else's command grammar, which is why the flag mark is
/// lexical -- see `colored_command_line`.
const SGR_RESET: &str = "\x1b[0m";
/// the escape of a hidden code point: reverse red, reserved for it alone
/// (plain red already means refusal). A kept escape -- an invalid byte, a
/// self-escaped backslash -- wears no style of its own: it takes the base of
/// the token it sits in, like any other character of it.
const SGR_HIDDEN: &str = "\x1b[7;31m";
/// shell metacharacters the DATA contained: `"`, a backtick, and a `'` that
/// arrived through the `'\''` idiom
const SGR_META: &str = "\x1b[1;36m";
/// notable whitespace runs IN THE PROGRAM TOKEN: grey background, so invisible
/// padding in the path that will execve reads as a block. Scoped to token[0] on
/// purpose (2026-08-27). The spoof surface this mark exists for is the program
/// path -- a trailing space or a hidden double space in the thing that runs.
/// Argument tokens are data: a multi-line script passed as one argument
/// (sh -c '...') would fill the line with grey indentation blocks after every
/// escaped line feed and drown the display, while those bytes still render
/// escaped and quoted either way, so the mark bought emphasis on the wrong
/// thing. The rule is identical on BOTH base variants: inside the program
/// token the mark stays a full-strength span, dim base or role base alike.
const SGR_SPACE: &str = "\x1b[100m";
/// program path, first segment of the directory (the leading '/' and the name
/// up to the next '/'); the rest of the directory is plain
const SGR_PROG_HEAD: &str = "\x1b[1;36m";
/// program path, basename -- the one token worth reading at the head of the
/// line. Same bytes as `SGR_FLAG`: against a plain directory it is the loudest
/// word on the line, and it sits first, so it never reads as one of the flags.
const SGR_PROG_BASE: &str = "\x1b[1;34m";
/// our own chrome: the single quotes the renderer added, which were never bytes
/// of an argument. Nothing reaching sudo contains a quote -- sudo hands the
/// plugin an argv ARRAY -- so every quote on screen is one we invented while
/// rendering that array as a line, EXCEPT the ones that arrived through the
/// `'\''` idiom, which are the only way a quote the argument really contained
/// can be represented.
const SGR_OURS: &str = "\x1b[2m";
/// option flags: a rendered token that starts with '-'. Bold blue -- distinct
/// from the frame's yellow, readable where plain blue is not, and shared with
/// the program's basename (see `SGR_PROG_BASE`). This is a deliberately LEXICAL
/// mark (by user choice: colour any flag, no judgement): "starts with a dash"
/// is not a claim about which flag is dangerous -- sudowhat cannot know that
/// (-rf looks like a flag, if=/dev/zero does not), and a token that needed
/// quoting renders as '...' (leading quote, not dash) so hostile input still
/// reads as data, never borrows the flag look.
const SGR_FLAG: &str = "\x1b[1;34m";
/// the quiet base of the DIM variant: every routine token (program directory,
/// flags, values alike) instead of its role colour. Same bytes as `SGR_OURS` on
/// purpose -- on that variant the chrome quotes stop standing out from the
/// content they wrap, which costs nothing, because the line those quotes are
/// attributed on is the loud one right underneath (see `RoleBase`).
const SGR_QUIET: &str = "\x1b[2m";
/// the program's basename on the DIM variant: bold AND dim, so the program is
/// the first word read on a quiet line without taking a hue. Terminals that
/// cannot combine the two show one of them, which still reads as quiet.
const SGR_QUIET_PROG: &str = "\x1b[1;2m";

/// Which base colours the ONE token walk lays under the routine roles. Both
/// variants run the same `command_tokens` / `render_token` / `paint` path, so
/// the two lines can never disagree about which tokens the command has or how
/// a token is spelled -- the variant changes the base palette and nothing else.
/// The marked spans (hidden escapes, metacharacters, program padding) are
/// identical in both: a mark must read the same wherever it appears, or a
/// reader comparing the two lines would have to learn two alphabets.
#[derive(Clone, Copy)]
enum RoleBase {
    /// Full role palette (the approval plugin's `execute:` line): the resolved
    /// command, which is the line that says what actually happens as root.
    Roles,
    /// Flat dim base (the audit plugin's `input:` line): the pre-resolution
    /// line reads quiet under the resolved one, and the marked spans -- kept
    /// at full strength -- pop harder against it.
    Dim,
}

impl RoleBase {
    /// Base for the first segment of the program path's directory part.
    fn prog_head(self) -> &'static str {
        match self {
            RoleBase::Roles => SGR_PROG_HEAD,
            RoleBase::Dim => SGR_QUIET,
        }
    }
    /// Base for the rest of the program path's directory part. Plain in the
    /// role variant, so the head and the basename stand out against it.
    fn prog_middle(self) -> &'static str {
        match self {
            RoleBase::Roles => "",
            RoleBase::Dim => SGR_QUIET,
        }
    }
    /// Base for the program path's basename.
    fn prog_base(self) -> &'static str {
        match self {
            RoleBase::Roles => SGR_PROG_BASE,
            RoleBase::Dim => SGR_QUIET_PROG,
        }
    }
    /// Base for an option flag (a rendered token starting with '-').
    fn flag(self) -> &'static str {
        match self {
            RoleBase::Roles => SGR_FLAG,
            RoleBase::Dim => SGR_QUIET,
        }
    }
    /// Base for every other token. Plain in the role variant -- values carry no
    /// role colour there at all.
    fn value(self) -> &'static str {
        match self {
            RoleBase::Roles => "",
            RoleBase::Dim => SGR_QUIET,
        }
    }
}

/// Emit plain text, arming `base` first if it is not already in effect.
fn push_plain(text: &str, base: &str, armed: &mut bool, out: &mut String) {
    if !base.is_empty() && !*armed {
        out.push_str(base);
        *armed = true;
    }
    out.push_str(text);
}

/// Emit a marked span in `color`, dropping any armed role colour around it so
/// the mark reads the same whatever role it sits in.
fn push_span(text: &str, color: &str, armed: &mut bool, out: &mut String) {
    if *armed {
        out.push_str(SGR_RESET);
        *armed = false;
    }
    out.push_str(color);
    out.push_str(text);
    out.push_str(SGR_RESET);
}

/// Colour one span of rendered parts: each part takes the colour of its mark,
/// plain parts take `base` (empty = plain). Purely additive -- the texts go out
/// in order, unchanged.
///
/// `mark_spaces` decides only whether the whitespace-run rule applies to this
/// span: true for the program token's spans, false for flag and value tokens
/// (see `SGR_SPACE`). Every other mark is fixed and not a parameter.
fn paint(span: &[Part], base: &str, mark_spaces: bool, out: &mut String) {
    let is_space = |p: &Part| p.1 == Mark::Plain && p.0 == " ";
    let len = span.len();
    let mut armed = false;
    let mut i = 0usize;
    while i < len {
        let (text, mark) = &span[i];
        match mark {
            Mark::Ours => push_span(text, SGR_OURS, &mut armed, out),
            Mark::Meta => push_span(text, SGR_META, &mut armed, out),
            Mark::Hidden => push_span(text, SGR_HIDDEN, &mut armed, out),
            // Whitespace runs, IN THE PROGRAM TOKEN ONLY. Mark a run of spaces
            // that is >=2 long or touches the start/end of the span -- the
            // invisible-padding cases (a trailing space on a path, a hidden
            // double space). A single interior space is a normal separator and
            // stays plain. The span, not the token, bounds "start/end": the
            // only extra boundaries are the program's seams (after its first
            // segment, before its basename), and a space at one gets MARKED --
            // more emphasis on invisible padding, never less.
            Mark::Plain if mark_spaces && is_space(&span[i]) => {
                let mut j = i + 1;
                while j < len && is_space(&span[j]) {
                    j += 1;
                }
                let run = " ".repeat(j - i);
                if j - i >= 2 || i == 0 || j == len {
                    push_span(&run, SGR_SPACE, &mut armed, out);
                } else {
                    push_plain(&run, base, &mut armed, out);
                }
                i = j;
                continue;
            }
            Mark::Plain => push_plain(text, base, &mut armed, out),
        }
        i += 1;
    }
    if armed {
        out.push_str(SGR_RESET);
    }
}

/// The full command line as [`full_command_line`] builds it, with SGR colour
/// layered on by role: the first segment of the program's directory bold cyan,
/// the rest of the directory plain, the basename bold blue, option flags bold
/// blue, every other token plain, our own quotes dim, and the marked spans
/// (hidden escapes in reverse red, the data's shell metacharacters, notable
/// whitespace inside the program token) on top. One logical line -- nothing is
/// wrapped, elided or reordered, and the bytes between the SGR sequences are
/// exactly the plain line's bytes.
///
/// Option flags (a rendered token starting with '-') are coloured by user
/// choice: colour any flag, no judgement. This is a LEXICAL mark, not a claim
/// about which flag is dangerous -- "starts with a dash" is wrong after `--`
/// and blind to `dd if=...` or `tar xvf`, and sudowhat has no standing to say
/// which is which. It stays honest about hostile input because a token that
/// needed quoting renders as '...' (leading quote, not dash) and so is never
/// mistaken for a flag.
///
/// This is the approval plugin's `execute:` line. See
/// [`colored_command_line_dim`] for the quiet variant the audit plugin's
/// `input:` line uses -- same walk, same tokens, a different base palette.
pub fn colored_command_line(path: &str, argv: &[&str], out: &mut String) {
    let raw: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    render_command_line(path.as_bytes(), &raw, RoleBase::Roles, out);
}

/// The same line as [`colored_command_line`], rendered through the SAME walk
/// with a flat dim base: every routine token -- program dirname, flags, values
/// -- takes dim instead of its role colour, and the program's basename takes
/// bold dim, so the program is still the first word read. The marked spans
/// keep full strength exactly as they have it on the other variant.
///
/// This is the audit plugin's `input:` line. The pre-resolution line reads
/// quiet under the resolved `execute:` line, which keeps the full role palette:
/// what sudo will actually run is the loud one, and what was typed sits under
/// it. The chrome quotes stay dim here too, and so stop being distinguishable
/// from the content they wrap; quote attribution is still legible on the
/// `execute:` line, which renders the same tokens through the same walk.
pub fn colored_command_line_dim(path: &str, argv: &[&str], out: &mut String) {
    let raw: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    render_command_line(path.as_bytes(), &raw, RoleBase::Dim, out);
}

fn is_slash(p: &Part) -> bool {
    p.1 == Mark::Plain && p.0 == "/"
}

/// A rendered program directory (ending in '/') split into its first segment
/// and the rest: "/run/current-system/sw/bin/" -> ("/run", "/current-system/
/// sw/bin/"). The head is the leading '/' and the name up to the next '/'. A
/// token that needed quoting starts with our chrome quote, which rides along
/// with the head ('/a  b/ -> "'/a  b", "/"), and `paint` still renders it as
/// chrome. A relative directory, or "/" alone, has no head: the whole
/// directory is the rest. No escape text holds a '/', so a '/' part is always
/// the character itself.
fn split_head(dir: &[Part]) -> (&[Part], &[Part]) {
    let start = if dir.len() >= 2 && dir[0].1 == Mark::Ours && is_slash(&dir[1]) {
        1
    } else {
        0
    };
    if !dir.get(start).is_some_and(is_slash) {
        return (&dir[..0], dir);
    }
    match dir[start + 1..].iter().position(is_slash) {
        Some(p) => dir.split_at(start + 1 + p),
        None => (&dir[..0], dir),
    }
}

/// The one token walk both public renderers use. Sharing it is the property
/// worth protecting: `input:` and `execute:` are built from the same
/// `command_tokens` list, rendered by the same `render_token` and coloured by
/// the same `paint`, so any difference a reader sees between the two lines is
/// a real difference in the command, never a rendering artefact. `base` decides
/// only which colour sits UNDER the routine roles; the marks are not a
/// parameter and cannot vary between the two.
fn render_command_line(path: &[u8], argv: &[&[u8]], base: RoleBase, out: &mut String) {
    for (i, tok) in command_tokens(path, argv).iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let r = render_token(tok);

        if i == 0 {
            // Split at the last '/' of the rendered token, the same separator
            // last_path_component finds. No '/' -> the whole token is the
            // basename. The directory part splits again into its first segment
            // and the rest (`split_head`), unless both take the same base (the
            // dim variant), where the split would only add a redundant span.
            //
            // Every part passes mark_spaces = true: this is the program, the
            // one token whose invisible padding changes what executes.
            match r.iter().rposition(is_slash) {
                Some(idx) => {
                    let (dir, rest) = r.split_at(idx + 1);
                    if base.prog_head() == base.prog_middle() {
                        paint(dir, base.prog_head(), true, out);
                    } else {
                        let (head, middle) = split_head(dir);
                        paint(head, base.prog_head(), true, out);
                        paint(middle, base.prog_middle(), true, out);
                    }
                    paint(rest, base.prog_base(), true, out);
                }
                None => paint(&r, base.prog_base(), true, out),
            }
        } else if r.first().is_some_and(|(t, m)| *m == Mark::Plain && t == "-") {
            // Option flag (lexical: the rendered token starts with '-'). A token
            // that needed quoting renders as '...' with a leading quote, so it
            // never reaches here -- hostile input stays data-coloured.
            paint(&r, base.flag(), false, out);
        } else {
            // Values carry no role colour on the role variant; only the marks
            // and our own quotes style anything inside them. Spaces are not
            // marked here: argument bytes are data, and a script argument
            // would otherwise drown the line in grey indentation blocks.
            paint(&r, base.value(), false, out);
        }
    }
}

// -------------------------------------------------------------------------
// FFI boundary. Every function is panic-free by construction: input reads are
// bounded by the caller-supplied length, bytes are taken as they are (never
// rejected), and output writes are gated on a capacity check.
// -------------------------------------------------------------------------

/// The `len` bytes at `ptr`. Null/zero yields an empty slice.
///
/// # Safety
/// `ptr` must be valid for `len` bytes, or null (with any `len`).
fn read_input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: caller guarantees `ptr` is valid for `len` bytes.
    unsafe { slice::from_raw_parts(ptr, len) }
}

/// The `argv_count` tokens of a C argv array. A null `argv` or `argv_lens`
/// yields no tokens.
///
/// # Safety
/// `argv` and `argv_lens` must be valid for `argv_count` elements (or null), and
/// each `argv[i]` valid for `argv_lens[i]` bytes.
fn read_argv<'a>(argv: *const *const u8, argv_lens: *const usize, argv_count: usize) -> Vec<&'a [u8]> {
    let mut toks: Vec<&[u8]> = Vec::new();
    if !argv.is_null() && !argv_lens.is_null() {
        for i in 0..argv_count {
            // SAFETY: caller guarantees argv/argv_lens hold argv_count elements.
            let tok_ptr = unsafe { *argv.add(i) };
            let tok_len = unsafe { *argv_lens.add(i) };
            toks.push(read_input(tok_ptr, tok_len));
        }
    }
    toks
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

/// Escape the `input_len` bytes at `input` (see [`escape_bytes`]) into `out`
/// (`out_cap` bytes). See the buffer contract on [`write_result`]. Returns
/// [`SW_ESCAPE_OK`] or [`SW_ESCAPE_TRUNCATED`].
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
    let mut result = String::new();
    escape_bytes(read_input(input, input_len), &mut result);
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
    let mut result = String::new();
    quote_bytes(read_input(input, input_len), &mut result);
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
    let toks = read_argv(argv, argv_lens, argv_count);
    let mut result = String::new();
    full_command_line_bytes(read_input(path, path_len), &toks, &mut result);
    write_result(&result, out, out_cap, needed)
}

/// The same line as [`sw_full_command_line`], with SGR colour layered on by role
/// (program dirname / basename, flags, our own quotes) and the marked spans
/// on top. Byte-identical to that function once the SGR is stripped, and still
/// one logical line. Same buffer contract as [`sw_escape_control`].
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
    let toks = read_argv(argv, argv_lens, argv_count);
    let mut result = String::new();
    render_command_line(read_input(path, path_len), &toks, RoleBase::Roles, &mut result);
    write_result(&result, out, out_cap, needed)
}

/// The same line as [`sw_full_command_line_colored`], rendered by the same walk
/// with the quiet base: the routine tokens (program, flags, values) all dim,
/// the marked spans at full strength. Identical signature and buffer contract.
///
/// The audit plugin's `input:` line uses this one, so the pre-resolution line
/// reads quiet under the resolved `execute:` line and its marks pop harder.
/// The caller decides whether colour is permitted at all (build-time knob plus
/// the NO_COLOR / TERM / isatty gates) and must fall back to
/// [`sw_full_command_line`] if this returns anything but [`SW_ESCAPE_OK`].
///
/// # Safety
/// See [`sw_full_command_line`].
#[unsafe(no_mangle)]
pub extern "C" fn sw_full_command_line_colored_dim(
    path: *const u8,
    path_len: usize,
    argv: *const *const u8,
    argv_lens: *const usize,
    argv_count: usize,
    out: *mut u8,
    out_cap: usize,
    needed: *mut usize,
) -> c_int {
    let toks = read_argv(argv, argv_lens, argv_count);
    let mut result = String::new();
    render_command_line(read_input(path, path_len), &toks, RoleBase::Dim, &mut result);
    write_result(&result, out, out_cap, needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hidden characters and expected escapes are built in code, never typed as
    // a literal escape in this file: `ch(0x202E)` is the character itself,
    // `u("202E")` the six-or-more-character escape the display shows for it.
    fn ch(u: u32) -> String {
        char::from_u32(u).expect("a scalar value").to_string()
    }
    fn u(hex: &str) -> String {
        format!("{}u{{{}}}", '\\', hex)
    }
    fn hidden(hex: &str) -> String {
        format!("{SGR_HIDDEN}{}{SGR_RESET}", u(hex))
    }

    fn esc(s: &str) -> String {
        let mut o = String::new();
        escape_control(s, &mut o);
        o
    }
    fn esc_bytes(b: &[u8]) -> String {
        let mut o = String::new();
        escape_bytes(b, &mut o);
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
    fn hidden_list_endpoints_escape() {
        // Both ends of every range on the hidden list, and each single point.
        let points: &[(u32, &str)] = &[
            (0x0000, "0"), (0x0009, "9"), (0x000A, "A"), (0x001F, "1F"),
            (0x007F, "7F"), (0x0085, "85"), (0x009F, "9F"),
            (0x00A0, "A0"), (0x00AD, "AD"), (0x034F, "34F"), (0x061C, "61C"),
            (0x115F, "115F"), (0x1160, "1160"), (0x17B4, "17B4"), (0x17B5, "17B5"),
            (0x180B, "180B"), (0x180E, "180E"), (0x2000, "2000"), (0x200F, "200F"),
            (0x2028, "2028"), (0x202E, "202E"), (0x202F, "202F"),
            (0x205F, "205F"), (0x2060, "2060"), (0x206F, "206F"),
            (0x3000, "3000"), (0x3164, "3164"), (0xFE00, "FE00"), (0xFE0F, "FE0F"),
            (0xFEFF, "FEFF"), (0xFFA0, "FFA0"), (0xFFF9, "FFF9"), (0xFFFB, "FFFB"),
            (0xE0000, "E0000"), (0xE0041, "E0041"), (0xE007F, "E007F"),
            (0xE0100, "E0100"), (0xE01EF, "E01EF"),
        ];
        for &(cp, hex) in points {
            assert_eq!(esc(&ch(cp)), u(hex), "U+{cp:04X}");
        }
    }

    #[test]
    fn neighbours_of_the_hidden_list_pass() {
        // Just outside each range: drawn as themselves. A plain space is not
        // hidden, nor are lookalikes such as U+2026 or a run of dots.
        for cp in [0x0020, 0x007E, 0x00A1, 0x00AC, 0x00AE, 0x034E, 0x0350,
                   0x2030, 0x205E, 0x2070, 0x2026, 0x22EF, 0x2024, 0xFDFF,
                   0xFE10, 0xFFA1, 0xFFFC, 0xE0080, 0xE01F0] {
            assert_eq!(esc(&ch(cp)), ch(cp), "U+{cp:04X}");
        }
        assert_eq!(esc("..."), "...");
        assert_eq!(esc("a....b"), "a....b");
    }

    #[test]
    fn escape_form_is_uppercase_without_leading_zeros() {
        assert_eq!(esc("\t"), u("9"));
        assert_eq!(esc(&ch(0x1B)), u("1B"));
        assert_eq!(esc(&ch(0x200B)), u("200B"));
        assert_eq!(esc(&format!("a{}b", ch(0x0A))), format!("a{}b", u("A")));
    }

    #[test]
    fn backslash_escapes_only_where_it_would_begin_an_escape() {
        // Promise 2: an escape on screen can only be one. A backslash before
        // u{ or before x and a hex digit shows as its own escape.
        let bs = u("5C");
        assert_eq!(esc("\\u{41}"), format!("{bs}u{{41}}"));
        assert_eq!(esc("\\x41"), format!("{bs}x41"));
        assert_eq!(esc("\\xff"), format!("{bs}xff"));
        assert_eq!(esc("\\xF"), format!("{bs}xF"));
        // Every other backslash is drawn as itself.
        assert_eq!(esc("\\"), "\\");
        assert_eq!(esc("\\n"), "\\n");
        assert_eq!(esc("a\\b"), "a\\b");
        assert_eq!(esc("\\u41"), "\\u41");
        assert_eq!(esc("\\xg"), "\\xg");
        assert_eq!(esc("\\x"), "\\x");
        assert_eq!(esc("C:\\Users"), "C:\\Users");
        // A literal backslash-n can no longer pass for a line feed, which now
        // shows as its code point.
        assert_ne!(esc("\\n"), esc("\n"));
        // Two backslashes before u{: only the second begins an escape.
        assert_eq!(esc("\\\\u{41}"), format!("\\{bs}u{{41}}"));
    }

    #[test]
    fn invalid_bytes_escape_after_valid_sequences_decode() {
        assert_eq!(esc_bytes(&[0xC3, 0xA9, 0xFF]), "é\\xFF");
        assert_eq!(esc_bytes(&[0xFF]), "\\xFF");
        assert_eq!(esc_bytes(&[0x80, 0x41]), "\\x80A");
        // A truncated sequence: one escape per byte.
        assert_eq!(esc_bytes(&[0xE2, 0x82, 0x41]), "\\xE2\\x82A");
        // A backslash before an invalid byte is not an introducer.
        assert_eq!(esc_bytes(&[b'\\', 0xFF]), "\\\\xFF");
        // A backslash before the letters x and a hex digit is, even when the
        // next byte is invalid.
        assert_eq!(esc_bytes(&[b'\\', b'x', b'A', 0xFF]), format!("{}xA\\xFF", u("5C")));
    }

    #[test]
    fn passthrough() {
        assert_eq!(esc("abcXYZ012"), "abcXYZ012");
        assert_eq!(esc("a b c"), "a b c");
        assert_eq!(esc("+_/.:=@%,-"), "+_/.:=@%,-");
        assert_eq!(esc(&ch(0x1F600)), ch(0x1F600));
        assert_eq!(esc("日本語"), "日本語");
        assert_eq!(esc("café"), "café");
        assert_eq!(esc(&format!("e{}", ch(0x0301))), format!("e{}", ch(0x0301)));
    }

    #[test]
    fn quote_basic() {
        assert_eq!(q(""), "''");
        assert_eq!(q("/bin/echo"), "/bin/echo");
        assert_eq!(q("a b"), "'a b'");
        assert_eq!(q("a'b"), "'a'\\''b'");
        assert_eq!(q("\t"), format!("'{}'", u("9")));
        assert_eq!(q("\\"), "'\\'");
        assert_eq!(q("\\'"), "'\\'\\'''");
        assert_eq!(q("..."), "...");
    }

    #[test]
    fn quote_bytes_escapes_invalid_utf8() {
        let mut o = String::new();
        quote_bytes(&[b'a', 0xFF], &mut o);
        assert_eq!(o, "'a\\xFF'");
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
    fn full_command_bytes_keeps_an_invalid_token() {
        // A token that is not valid UTF-8 is shown, escaped, never dropped.
        let mut o = String::new();
        full_command_line_bytes(b"/bin/cp", &[b"cp", &[b'x', 0xFF], b"/etc/y"], &mut o);
        assert_eq!(o, "/bin/cp 'x\\xFF' /etc/y");
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
    fn ffi_escape_reads_raw_bytes() {
        let input = [b'a', 0xFF];
        let mut needed = 0usize;
        sw_escape_control(input.as_ptr(), input.len(), std::ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u8; needed + 1];
        let mut got = 0usize;
        let rc = sw_escape_control(input.as_ptr(), input.len(),
                                   buf.as_mut_ptr(), buf.len(), &mut got);
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(&buf[..got], b"a\\xFF");
    }

    // --- colouriser -------------------------------------------------------

    fn colored(path: &str, argv: &[&str]) -> String {
        let mut o = String::new();
        colored_command_line(path, argv, &mut o);
        o
    }

    fn colored_dim(path: &str, argv: &[&str]) -> String {
        let mut o = String::new();
        colored_command_line_dim(path, argv, &mut o);
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
    fn color_cases() -> Vec<(String, Vec<String>)> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        vec![
            ("/bin/echo".into(), s(&["echo", "hello"])),
            ("/bin/echo".into(), s(&[])),
            ("id".into(), s(&["id"])),
            ("".into(), s(&[])),
            ("".into(), s(&[""])),
            ("/usr/bin/git".into(), s(&["git", "status", "--porcelain"])),
            (
                "/run/current-system/sw/bin/pinned".into(),
                s(&["pinned", "review", "--file", "/Library/App Support/x.json"]),
            ),
            ("/bin/echo".into(), s(&["echo", "a b", "a'b", "-", "--", "-x"])),
            ("/bin/echo".into(), s(&["echo", "sudowhat: user: evil"])),
            (
                "/bin/echo".into(),
                vec!["echo".into(), "a\nb".into(), "a\tb".into(), "a\\b".into(),
                     format!("a{}b", ch(0x202E)), "\\u{41}".into(), "\\'".into()],
            ),
            ("/bin/echo".into(), s(&["echo", "...", "  padded  ", ""])),
            ("/usr/bin/日本".into(), vec!["日本".into(), "café".into(), ch(0x1F600)]),
            ("/a b/prog name".into(), s(&["prog name"])),
            ("/usr/bin/".into(), s(&["-v"])),
            ("prog".into(), s(&["prog", "-f", "v"])),
            (format!("/bin/{}sh", ch(0x202E)), s(&[])),
        ]
    }

    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn colored_preserves_bytes() {
        // The invariant: colour is layout, never content. Strip the SGR and the
        // plain line must come back byte for byte.
        for (path, argv) in color_cases() {
            let argv = refs(&argv);
            let c = colored(&path, &argv);
            assert_eq!(strip_sgr(&c), full(&path, &argv), "path={path:?} argv={argv:?}");
        }
    }

    #[test]
    fn colored_never_emits_a_raw_control_byte() {
        // Every ESC in the output must start one of our SGR sequences, and no
        // other C0 byte may appear -- the input is attacker-influenced.
        for (path, argv) in color_cases() {
            let argv = refs(&argv);
            for c in [colored(&path, &argv), colored_dim(&path, &argv)] {
                let chars: Vec<char> = c.chars().collect();
                for (i, ch) in chars.iter().enumerate() {
                    let u = *ch as u32;
                    if u == 0x1b {
                        assert_eq!(chars.get(i + 1), Some(&'['), "ESC not starting a CSI");
                    } else {
                        assert!(u >= 0x20, "raw control byte {u:#x} in output");
                    }
                }
            }
        }
    }

    #[test]
    fn colored_program_roles() {
        // first segment bold cyan, the rest of the directory plain, basename
        // bold blue, each styled span closed by a reset.
        assert_eq!(
            colored("/bin/echo", &["echo"]),
            "\x1b[1;36m/bin\x1b[0m/\x1b[1;34mecho\x1b[0m"
        );
        // no '/' at all -> the whole program token is the basename.
        assert_eq!(colored("id", &["id"]), "\x1b[1;34mid\x1b[0m");
    }

    #[test]
    fn colored_program_head_split() {
        // A deep path: only the first segment carries the head colour.
        assert_eq!(
            colored("/run/current-system/sw/bin/locked", &["locked"]),
            "\x1b[1;36m/run\x1b[0m/current-system/sw/bin/\x1b[1;34mlocked\x1b[0m"
        );
        // A program at the root: "/" alone has no head.
        assert_eq!(colored("/ls", &["ls"]), "/\x1b[1;34mls\x1b[0m");
        // A relative directory has no head either.
        assert_eq!(colored("bin/tool", &["tool"]), "bin/\x1b[1;34mtool\x1b[0m");
        // A program that needed quoting: our opening quote rides with the head
        // and still renders as chrome, and the head colour starts after it.
        assert_eq!(
            colored("/a b/t", &["t"]),
            "\x1b[2m'\x1b[0m\x1b[1;36m/a b\x1b[0m/\x1b[1;34mt\x1b[0m\x1b[2m'\x1b[0m"
        );
        // The dim variant keeps the directory as one quiet span and the
        // basename bold dim.
        assert_eq!(
            colored_dim("./bin/foo", &["foo"]),
            "\x1b[2m./bin/\x1b[0m\x1b[1;2mfoo\x1b[0m"
        );
    }

    #[test]
    fn colored_flag_and_value_roles() {
        // Flags are bold blue (by user choice: colour any flag, no judgement);
        // values stay unstyled. The flag colour is a role of its own, so dim
        // continues to mean exactly one thing: our own quotes.
        assert_eq!(
            colored("/bin/git", &["git", "--file", "x"]),
            "\x1b[1;36m/bin\x1b[0m/\x1b[1;34mgit\x1b[0m \x1b[1;34m--file\x1b[0m x"
        );
        // a bare "-" / "--" is lexically a flag too -- the mark is lexical, not a
        // judgement about what the token means.
        assert_eq!(colored("p", &["p", "--"]), "\x1b[1;34mp\x1b[0m \x1b[1;34m--\x1b[0m");
        // dim still appears only where our quoting does, never on a flag.
        assert!(!colored("/bin/git", &["git", "-rf", "x"]).contains("\x1b[2m"));
    }

    #[test]
    fn colored_hostile_token_reads_as_data() {
        // A token spelled like one of our own lines lands quoted. The wrapping
        // quotes are OURS, so they read dim -- the token's own bytes stay at
        // full weight: the reader sees data inside chrome, not a second
        // sudowhat line.
        let c = colored("/bin/echo", &["echo", "sudowhat: user: evil"]);
        assert!(c.ends_with("\x1b[2m'\x1b[0m"), "unterminated quote: {c:?}");
        assert!(c.contains("\x1b[2m'\x1b[0msudowhat:"), "opening quote: {c:?}");
        // the whitespace run rule does not reach an argument token at all, so
        // the spaces inside the quotes carry no grey block.
        assert!(!c.contains("\x1b[100m"), "argument space marked: {c:?}");
        assert_eq!(strip_sgr(&c), "/bin/echo 'sudowhat: user: evil'");
    }

    #[test]
    fn colored_hidden_and_kept_escapes() {
        // A hidden code point's escape wears reverse red, over whatever role
        // the token carries.
        let c = colored("/bin/echo", &["echo", "a\nb"]);
        assert!(c.contains(&hidden("A")), "line feed: {c:?}");
        let c = colored("/bin/echo", &["echo", &format!("{}x", ch(0x202E))]);
        assert!(c.contains(&hidden("202E")), "bidi override: {c:?}");
        // A literal backslash is plain text, and its self-escape is a kept
        // escape: no style of its own. No retired anomaly colour remains.
        let c = colored("/bin/echo", &["echo", "a\\b"]);
        assert_eq!(c, "\x1b[1;36m/bin\x1b[0m/\x1b[1;34mecho\x1b[0m \x1b[2m'\x1b[0ma\\b\x1b[2m'\x1b[0m");
        let c = colored("/bin/echo", &["echo", "\\x41"]);
        assert_eq!(strip_sgr(&c), format!("/bin/echo '{}x41'", u("5C")));
        assert!(!c.contains(SGR_HIDDEN), "kept escape styled: {c:?}");
        for retired in ["\x1b[1;31m", "\x1b[1;35m"] {
            for (path, argv) in color_cases() {
                let argv = refs(&argv);
                assert!(!colored(&path, &argv).contains(retired));
                assert!(!colored_dim(&path, &argv).contains(retired));
            }
        }
        // A kept escape takes the base of its token: dim on the quiet variant,
        // bold blue in the program's basename.
        let mut o = String::new();
        render_command_line(&[b'x', 0xFF], &[], RoleBase::Roles, &mut o);
        assert_eq!(o, "\x1b[2m'\x1b[0m\x1b[1;34mx\\xFF\x1b[0m\x1b[2m'\x1b[0m");
    }

    #[test]
    fn colored_whitespace_and_metacharacters() {
        // Notable whitespace is marked in the PROGRAM token, where invisible
        // padding changes what executes.
        let c = colored("/tmp/my  tool", &[]);
        assert!(c.contains("\x1b[100m  \x1b[0m"), "program space run: {c:?}");
        // and NOT in an argument token: those bytes are data, they still render
        // escaped and quoted, and a script argument would otherwise fill the
        // line with grey indentation blocks.
        let c = colored("p", &["p", "-x  y"]);
        assert!(!c.contains("\x1b[100m"), "argument space marked: {c:?}");
        let c = colored("/bin/sh", &["sh", "-c", "if true; then\n  echo hi\nfi"]);
        assert!(!c.contains("\x1b[100m"), "script argument marked: {c:?}");
        // The data's shell metacharacters keep their mark.
        let c = colored("p", &["p", "a\"b`c"]);
        assert!(c.contains("\x1b[1;36m\"\x1b[0m") && c.contains("\x1b[1;36m`\x1b[0m"), "{c:?}");
    }

    #[test]
    fn colored_quote_attribution() {
        // a'b -> 'a'\''b' : ours, a, ours, a plain backslash, the DATA's quote,
        // ours, b, ours.
        assert_eq!(
            colored("p", &["p", "a'b"]),
            "\x1b[1;34mp\x1b[0m \x1b[2m'\x1b[0ma\x1b[2m'\x1b[0m\\\x1b[1;36m'\x1b[0m\
             \x1b[2m'\x1b[0mb\x1b[2m'\x1b[0m"
        );
        // The trap a re-parse gets wrong: \' renders '\'\''' , where the quote
        // right after the first backslash is OUR closing quote, not the data's.
        // Built from the parts, the attribution is right by construction.
        let c = colored("p", &["p", "\\'"]);
        assert_eq!(strip_sgr(&c), "p '\\'\\'''");
        assert_eq!(
            c,
            "\x1b[1;34mp\x1b[0m \x1b[2m'\x1b[0m\\\x1b[2m'\x1b[0m\\\x1b[1;36m'\x1b[0m\
             \x1b[2m'\x1b[0m\x1b[2m'\x1b[0m"
        );
    }

    #[test]
    fn program_token_whitespace_marks_both_halves() {
        // The program token is ONE token for the whitespace rule; the
        // dirname/basename split exists only so the two halves can take
        // different base colours. A doubled space in either half is marked.
        let c = colored("/a  b/my  tool", &[]);
        assert_eq!(strip_sgr(&c), "'/a  b/my  tool'");
        assert_eq!(
            c.matches("\x1b[100m  \x1b[0m").count(),
            2,
            "dirname and basename runs: {c:?}"
        );

        // The span, not the token, bounds "start/end", so a single space just
        // past the split starts the basename span and IS marked. More emphasis
        // on invisible padding in the program path, never less.
        let c = colored("/a/ b", &[]);
        assert_eq!(strip_sgr(&c), "'/a/ b'");
        assert!(c.contains("\x1b[100m \x1b[0m"), "seam space: {c:?}");

        // Identical on the quiet variant -- inside the program token the mark
        // is a full-strength span under either base.
        let d = colored_dim("/a  b/my  tool", &[]);
        assert_eq!(
            d.matches("\x1b[100m  \x1b[0m").count(),
            2,
            "dim variant keeps both runs: {d:?}"
        );
    }

    #[test]
    fn colored_hidden_in_the_program_token() {
        // An escape inside the program path drops the role colour for its span
        // and the role resumes after it -- the bytes still round-trip.
        let path = format!("/bin/{}sh", ch(0x202E));
        let c = colored(&path, &[]);
        assert_eq!(strip_sgr(&c), format!("'/bin/{}sh'", u("202E")));
        assert!(c.contains(&format!("{}\x1b[1;34msh", hidden("202E"))), "{c:?}");
    }

    #[test]
    fn colored_empty_argv() {
        // an empty command word renders as the empty quoted token: the token
        // contributed no bytes at all, so BOTH quotes are ours and both dim.
        assert_eq!(colored("", &[]), "\x1b[2m'\x1b[0m\x1b[2m'\x1b[0m");
        assert_eq!(strip_sgr(&colored("", &[])), "''");
        assert_eq!(strip_sgr(&colored("/bin/ls", &[])), "/bin/ls");
    }

    // --- the dim variant (the audit plugin's input: line) -----------------

    #[test]
    fn dim_preserves_bytes() {
        // The round-trip invariant holds for the quiet variant exactly as it
        // does for the loud one, and the two agree on every byte they show:
        // one walk, one token list, two base palettes.
        for (path, argv) in color_cases() {
            let argv = refs(&argv);
            let d = colored_dim(&path, &argv);
            assert_eq!(strip_sgr(&d), full(&path, &argv), "path={path:?} argv={argv:?}");
            assert_eq!(
                strip_sgr(&d),
                strip_sgr(&colored(&path, &argv)),
                "the two variants show different bytes for {path:?} {argv:?}"
            );
        }
    }

    #[test]
    fn dim_routine_tokens_take_the_quiet_base() {
        // Program dirname and value dim, the basename bold dim, no role colour.
        // Pinned to exact bytes: one span for the whole directory, since the
        // head and the rest share the quiet base here.
        let d = colored_dim("/bin/echo", &["echo", "hello"]);
        assert_eq!(
            d,
            "\x1b[2m/bin/\x1b[0m\x1b[1;2mecho\x1b[0m \x1b[2mhello\x1b[0m"
        );
        // No cyan anywhere on a clean line. Checked on a case with no marked
        // span, because SGR_META is 1;36 too and legitimately appears on a
        // metachar -- there, the bold cyan is a mark, not a role.
        assert!(!d.contains("\x1b[36m"), "role cyan on the dim variant: {d:?}");
        assert!(!d.contains("\x1b[1;36m"), "bold role cyan on the dim variant: {d:?}");
        // A bare command word is all basename, and still dim.
        assert_eq!(colored_dim("id", &["id"]), "\x1b[1;2mid\x1b[0m");
    }

    #[test]
    fn dim_flags_are_not_blue() {
        let d = colored_dim("/bin/git", &["git", "--file", "x"]);
        assert_eq!(
            d,
            "\x1b[2m/bin/\x1b[0m\x1b[1;2mgit\x1b[0m \x1b[2m--file\x1b[0m \x1b[2mx\x1b[0m"
        );
        assert!(!d.contains("\x1b[1;34m"), "flag blue on the dim variant: {d:?}");
        // and the role variant still has it, so this is a variant difference
        // rather than the flag role having been dropped.
        assert!(colored("/bin/git", &["git", "--file", "x"]).contains("\x1b[1;34m"));
    }

    #[test]
    fn dim_keeps_the_marks_at_full_strength() {
        // The whole point of the quiet base: against flat dim, the marked
        // spans are the only coloured thing on the line.
        let d = colored_dim("/bin/echo", &["echo", "a\nb"]);
        assert!(d.contains(&hidden("A")), "line feed: {d:?}");
        let d = colored_dim("/bin/echo", &["echo", &format!("{}x", ch(0x202E))]);
        assert!(d.contains(&hidden("202E")), "bidi override: {d:?}");
        // The whitespace mark is scoped to the program token on this variant
        // exactly as on the other one, and it keeps full strength there.
        let d = colored_dim("/tmp/my  tool", &[]);
        assert!(d.contains("\x1b[100m  \x1b[0m"), "program space run: {d:?}");
        let d = colored_dim("p", &["p", "-x  y"]);
        assert!(!d.contains("\x1b[100m"), "argument space marked: {d:?}");
        // the argument's spaces render on the quiet base like any routine char.
        assert!(d.contains("\x1b[2m"), "argument lost the dim base: {d:?}");
        // A hidden escape inside the program token drops the base for its span
        // and the base resumes after it, exactly as on the role variant.
        let path = format!("/bin/{}sh", ch(0x202E));
        let d = colored_dim(&path, &[]);
        assert_eq!(strip_sgr(&d), format!("'/bin/{}sh'", u("202E")));
        assert!(d.contains(&hidden("202E")), "{d:?}");
    }

    #[test]
    fn ffi_colored_dim_two_call_sizing() {
        let path = b"/bin/echo";
        let a0 = b"echo";
        let argv: [*const u8; 1] = [a0.as_ptr()];
        let lens: [usize; 1] = [a0.len()];

        let mut needed = 0usize;
        let rc = sw_full_command_line_colored_dim(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            std::ptr::null_mut(), 0, &mut needed,
        );
        assert_eq!(rc, SW_ESCAPE_TRUNCATED);

        let mut buf = vec![0u8; needed + 1];
        let mut got = 0usize;
        let rc = sw_full_command_line_colored_dim(
            path.as_ptr(), path.len(),
            argv.as_ptr(), lens.as_ptr(), 1,
            buf.as_mut_ptr(), buf.len(), &mut got,
        );
        assert_eq!(rc, SW_ESCAPE_OK);
        assert_eq!(&buf[..got], b"\x1b[2m/bin/\x1b[0m\x1b[1;2mecho\x1b[0m");
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
        assert_eq!(&buf[..got], b"\x1b[1;36m/bin\x1b[0m/\x1b[1;34mecho\x1b[0m");
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
        assert_eq!(&buf[..got], b"\x1b[1;36m/bin\x1b[0m/\x1b[1;34mls\x1b[0m");

        // An invalid UTF-8 byte in a token shows as its kept escape, never a
        // panic, and the coloured line still strips back to the plain one.
        let bad = [b'a', 0xFF, b'b'];
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
        let mut plain = String::new();
        full_command_line_bytes(path, &[&bad], &mut plain);
        assert_eq!(strip_sgr(s), plain);
        assert_eq!(plain, format!("/bin/ls 'a{}xFFb'", '\\'));
    }

    #[test]
    fn ffi_colored_matches_plain_after_stripping() {
        // The FFI trio, not just the Rust functions: the entry points the
        // plugins pick between must agree byte for byte modulo SGR.
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
        let dim = render(sw_full_command_line_colored_dim);
        assert_eq!(strip_sgr(&color), plain);
        assert_ne!(color, plain);
        assert_eq!(strip_sgr(&dim), plain);
        assert_ne!(dim, plain);
        assert_ne!(dim, color);
    }
}
