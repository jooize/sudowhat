/*
 * Adversarial unit tests for SudoWhatPromptFormatter.
 *
 * This class is the anti-spoofing boundary: it shell-quotes argv tokens and
 * escapes control / homoglyph characters so the bytes shown in the Touch ID
 * sheet cannot fake structure (hidden newlines, fake truncation markers,
 * doubled-up escapes). These tests try hard to break those guarantees.
 *
 * escapeControlChars: is private to the .m; we redeclare it in a category so
 * the test can call it without changing production code (the method exists at
 * runtime). quoteToken: and formatWith...: are public in the header.
 */
#import "PromptFormatter.h"
#import "sw_test.h"

/* escapeControlChars: is now public (the plugin escapes echoed values with it),
 * so no category is needed. */

/* Closing-line constants copied verbatim from PromptFormatter.m. If these ever
 * mismatch the source the exact-match tests below will flag it. */
static NSString *const BOTTOM_CLEAN = @"Code must match your terminal";
static NSString *const BOTTOM_TRUNC = @"⚠️ Long items are shown in your terminal";
static NSString *const SEE_TERMINAL = @"(see terminal)";

static const NSUInteger kMaxTotal = 480;   /* PromptFormatter.m kMaxTotal */

static NSString *esc(NSString *s) { return [SudoWhatPromptFormatter escapeControlChars:s]; }
static NSString *q(NSString *s)   { return [SudoWhatPromptFormatter quoteToken:s]; }
static NSString *fmt(NSString *path, NSString *user, NSString *cwd,
                     NSString *verify, NSArray *argv, SWPromptStyle style) {
    return [SudoWhatPromptFormatter formatWithCommandPath:path runasUser:user
                                                      cwd:cwd verifyCode:verify
                                                     argv:argv style:style];
}
static NSString *fullcmd(NSString *path, NSArray *argv) {
    return [SudoWhatPromptFormatter fullCommandLineForCommandPath:path argv:argv];
}
static BOOL fmt_trunc(NSString *path, NSArray *argv, SWPromptStyle style) {
    BOOL t = NO;
    [SudoWhatPromptFormatter formatWithCommandPath:path runasUser:@"root"
                                               cwd:nil verifyCode:@"AB12"
                                              argv:argv style:style
                                      wasTruncated:&t];
    return t;
}

/* unichar -> length-1 NSString (reliable for NUL and other controls, unlike
 * @"\0" literals whose handling is ambiguous). */
static NSString *uni(unichar c) { return [NSString stringWithCharacters:&c length:1]; }
static NSString *rep(NSString *s, NSUInteger n) {
    NSMutableString *o = [NSMutableString string];
    for (NSUInteger i = 0; i < n; i++) [o appendString:s];
    return o;
}
static NSUInteger nlcount(NSString *s) {
    NSUInteger n = 0;
    for (NSUInteger i = 0; i < s.length; i++) if ([s characterAtIndex:i] == '\n') n++;
    return n;
}
static NSUInteger charcount(NSString *s, unichar target) {
    NSUInteger n = 0;
    for (NSUInteger i = 0; i < s.length; i++) if ([s characterAtIndex:i] == target) n++;
    return n;
}
static NSString *color(NSString *s) { return [SudoWhatPromptFormatter colorizeEscaped:s]; }
/* Strip CSI SGR sequences (ESC '[' ... 'm') so we can assert the round-trip
 * invariant: colorizeEscaped adds only colour, never changes the bytes. */
static NSString *strip_sgr(NSString *s) {
    NSMutableString *o = [NSMutableString string];
    NSUInteger i = 0, len = s.length;
    while (i < len) {
        unichar c = [s characterAtIndex:i];
        if (c == 0x1b && i + 1 < len && [s characterAtIndex:i + 1] == '[') {
            i += 2;
            while (i < len && [s characterAtIndex:i] != 'm') i++;
            if (i < len) i++;   /* skip the terminating 'm' */
            continue;
        }
        [o appendFormat:@"%C", c];
        i++;
    }
    return o;
}

static void test_escape_named(void) {
    /* The five named escapes. */
    EQ(esc(uni(0x0a)), @"\\n", "esc newline -> backslash-n");
    EQ(esc(uni(0x0d)), @"\\r", "esc CR -> backslash-r");
    EQ(esc(uni(0x09)), @"\\t", "esc tab -> backslash-t");
    EQ(esc(uni(0x00)), @"\\0", "esc NUL -> backslash-0");
    EQ(esc(@"\\"),     @"\\\\", "esc backslash -> double backslash");
}

static void test_escape_antispoof_backslash(void) {
    /* The core anti-spoof property (README:30): a literal two-char "\n"
     * (backslash, 'n') must NOT render the same as a real 0x0a newline. */
    NSString *literalBackslashN = esc(@"\\n");   /* input: backslash, n */
    NSString *realNewline       = esc(uni(0x0a));
    EQ(literalBackslashN, @"\\\\n", "literal backslash-n escapes to \\\\n");
    EQ(realNewline,       @"\\n",   "real newline escapes to \\n");
    OK(![literalBackslashN isEqualToString:realNewline],
       "literal backslash-n distinguishable from real newline");
}

static void test_escape_hex_c0_del(void) {
    EQ(esc(uni(0x07)), @"\\x07", "esc BEL -> \\x07");
    EQ(esc(uni(0x01)), @"\\x01", "esc SOH -> \\x01");
    EQ(esc(uni(0x1b)), @"\\x1b", "esc ESC -> \\x1b (lowercase hex)");
    EQ(esc(uni(0x1f)), @"\\x1f", "esc 0x1f -> \\x1f");
    EQ(esc(uni(0x7f)), @"\\x7f", "esc DEL -> \\x7f");
}

static void test_escape_c1_and_separators(void) {
    EQ(esc(uni(0x80)), @"\\u0080", "esc C1 0x80 -> \\u0080");
    EQ(esc(uni(0x85)), @"\\u0085", "esc NEL -> \\u0085");
    EQ(esc(uni(0x9f)), @"\\u009f", "esc 0x9f -> \\u009f");
    EQ(esc(uni(0x2028)), @"\\u2028", "esc LINE SEPARATOR -> \\u2028");
    EQ(esc(uni(0x2029)), @"\\u2029", "esc PARA SEPARATOR -> \\u2029");
}

static void test_escape_ellipsis_homoglyphs(void) {
    EQ(esc(uni(0x2026)), @"\\u2026", "esc U+2026 ellipsis -> \\u2026");
    EQ(esc(uni(0x22ef)), @"\\u22ef", "esc U+22EF midline ellipsis -> \\u22ef");
    EQ(esc(uni(0x2024)), @"\\u2024", "esc U+2024 one-dot leader -> \\u2024");
    EQ(esc(uni(0x2025)), @"\\u2025", "esc U+2025 two-dot leader -> \\u2025");
    /* three one-dot-leaders read as `…` but are escaped, so cannot mimic it */
    EQ(esc(([NSString stringWithFormat:@"%@%@%@", uni(0x2024), uni(0x2024), uni(0x2024)])),
       @"\\u2024\\u2024\\u2024", "esc run of one-dot leaders");
    /* mixed with text */
    EQ(esc(([NSString stringWithFormat:@"a%@b", uni(0x2026)])), @"a\\u2026b",
       "esc ellipsis between letters");
}

static void test_escape_bidi(void) {
    /* Trojan Source (CVE-2021-42574): bidi overrides visually reorder text so
     * the glyphs on the sheet can read as a different command than runs. Every
     * one must be escaped, even inside a single-quoted token. */
    EQ(esc(uni(0x202A)), @"\\u202a", "esc LRE -> \\u202a");
    EQ(esc(uni(0x202B)), @"\\u202b", "esc RLE -> \\u202b");
    EQ(esc(uni(0x202C)), @"\\u202c", "esc PDF -> \\u202c");
    EQ(esc(uni(0x202D)), @"\\u202d", "esc LRO -> \\u202d");
    EQ(esc(uni(0x202E)), @"\\u202e", "esc RLO -> \\u202e");
    EQ(esc(uni(0x2066)), @"\\u2066", "esc LRI -> \\u2066");
    EQ(esc(uni(0x2067)), @"\\u2067", "esc RLI -> \\u2067");
    EQ(esc(uni(0x2068)), @"\\u2068", "esc FSI -> \\u2068");
    EQ(esc(uni(0x2069)), @"\\u2069", "esc PDI -> \\u2069");
    EQ(esc(uni(0x200E)), @"\\u200e", "esc LRM -> \\u200e");
    EQ(esc(uni(0x200F)), @"\\u200f", "esc RLM -> \\u200f");
    EQ(esc(uni(0x061C)), @"\\u061c", "esc ALM -> \\u061c");
    /* the canonical attack token still carries the raw override nowhere */
    NSString *rlo = [NSString stringWithFormat:@"/etc/%@fdp.ssm", uni(0x202E)];
    OK(charcount(esc(rlo), 0x202E) == 0, "no raw RLO survives escaping");
    /* and single-quoting does not smuggle it either */
    OK(charcount(q(rlo), 0x202E) == 0, "no raw RLO survives quoteToken");
}

static void test_escape_zero_width(void) {
    EQ(esc(uni(0x200B)), @"\\u200b", "esc ZWSP -> \\u200b");
    EQ(esc(uni(0x200C)), @"\\u200c", "esc ZWNJ -> \\u200c");
    EQ(esc(uni(0x200D)), @"\\u200d", "esc ZWJ -> \\u200d");
    EQ(esc(uni(0x2060)), @"\\u2060", "esc WORD JOINER -> \\u2060");
    EQ(esc(uni(0xFEFF)), @"\\ufeff", "esc ZWNBSP/BOM -> \\ufeff");
}

static void test_escape_dot_runs(void) {
    EQ(esc(@"."),    @".",  "single dot passes through");
    EQ(esc(@".."),   @"..", "two dots (parent dir) pass through");
    EQ(esc(@"..."),  @"\\u002e\\u002e\\u002e", "three dots all escaped");
    EQ(esc(@"...."), @"\\u002e\\u002e\\u002e\\u002e", "four dots all escaped");
    EQ(esc(@"a...b"), @"a\\u002e\\u002e\\u002eb", "interior 3-dot run escaped");
    EQ(esc(@"a..b"),  @"a..b", "interior 2-dot run passes");
    EQ(esc(@"a.b.c"), @"a.b.c", "scattered single dots pass");
    EQ(esc(@".....b"), @"\\u002e\\u002e\\u002e\\u002e\\u002eb", "five-dot run escaped");
}

static void test_escape_dot_run_transitions(void) {
    /* Dot-run handling must hand off cleanly to normal escaping for the char
     * that ends the run. */
    EQ(esc(([NSString stringWithFormat:@"...%@", uni(0x0a)])),
       @"\\u002e\\u002e\\u002e\\n", "3-dot run then newline");
    EQ(esc(([NSString stringWithFormat:@"%@...", uni(0x09)])),
       @"\\t\\u002e\\u002e\\u002e", "tab then 3-dot run");
    EQ(esc(@"a...b...c"), @"a\\u002e\\u002e\\u002eb\\u002e\\u002e\\u002ec",
       "two separate 3-dot runs both escaped");
    EQ(esc(@"..a.."), @"..a..", "2-dot runs around a letter pass");
}

static void test_escape_lone_surrogate(void) {
    /* A lone (unpaired) surrogate is invalid Unicode; the formatter passes it
     * through (renders as a replacement glyph downstream). Documenting the
     * behavior: it must not crash or be mistaken for an escape. */
    NSString *hi = uni(0xD800), *lo = uni(0xDC00);
    EQ(esc(hi), hi, "lone high surrogate passes through");
    EQ(esc(lo), lo, "lone low surrogate passes through");
}

static void test_escape_passthrough(void) {
    EQ(esc(@"abcXYZ012"), @"abcXYZ012", "alnum passthrough");
    EQ(esc(@"a b c"),     @"a b c",     "space passthrough (not a control)");
    EQ(esc(@"+_/.:=@%,-"), @"+_/.:=@%,-", "safe punctuation passthrough");
    EQ(esc(@"😀"),  @"😀",  "emoji (astral/surrogate pair) survives intact");
    EQ(esc(@"日本語"), @"日本語", "CJK survives intact");
    EQ(esc(@"café"), @"café", "latin-1 accented survives");
    EQ(esc(([NSString stringWithFormat:@"e%@", uni(0x0301)])),
       ([NSString stringWithFormat:@"e%@", uni(0x0301)]),
       "combining mark survives");
}

static void test_quote_empty_nil(void) {
    EQ(q(nil), @"''", "quote nil -> ''");
    EQ(q(@""), @"''", "quote empty -> ''");
}

static void test_quote_safe(void) {
    EQ(q(@"/bin/echo"), @"/bin/echo", "safe path unquoted");
    EQ(q(@"hello"),     @"hello",     "safe word unquoted");
    EQ(q(@"+_./:=@%,-"), @"+_./:=@%,-", "all-safe-punct unquoted");
    EQ(q(@"a1B2"),      @"a1B2",      "alnum unquoted");
}

static void test_quote_unsafe(void) {
    EQ(q(@"a b"),  @"'a b'",  "space forces single-quote");
    EQ(q(@"a;b"),  @"'a;b'",  "semicolon forces quote");
    EQ(q(@"#x"),   @"'#x'",   "hash forces quote");
    EQ(q(@"$HOME"),@"'$HOME'","dollar forces quote");
    EQ(q(@"a&b"),  @"'a&b'",  "ampersand forces quote");
    EQ(q(@"a|b"),  @"'a|b'",  "pipe forces quote");
    EQ(q(@"a>b"),  @"'a>b'",  "redirect forces quote");
}

static void test_quote_embedded_single_quote(void) {
    /* classic POSIX single-quote escape: ' -> '\'' */
    EQ(q(@"a'b"), @"'a'\\''b'", "embedded single quote escaped a'b");
    EQ(q(@"'"),   @"''\\'''",   "lone single quote");
    EQ(q(@"can't"), @"'can'\\''t'", "apostrophe in word");
}

static void test_quote_control_chars_get_quoted(void) {
    /* A control char escapes to a backslash sequence; backslash is unsafe,
     * so the token gets single-quoted with the escape shown literally. */
    EQ(q(uni(0x09)),  @"'\\t'",  "tab token -> '\\t'");
    EQ(q(uni(0x0a)),  @"'\\n'",  "newline token -> '\\n'");
    EQ(q(uni(0x07)),  @"'\\x07'","bell token -> '\\x07'");
    EQ(q(@"\\"),      @"'\\\\'", "backslash token -> '\\\\'");
    EQ(q(([NSString stringWithFormat:@"a%@b", uni(0x0a)])), @"'a\\nb'",
       "newline inside word -> 'a\\nb' (no real break)");
}

/* ---- formatWith: layout, dedup, caps, all-or-nothing overflow, budget ---- */

static NSString *fmt_ov(NSString *path, NSString *user, NSString *cwd,
                        NSString *verify, NSArray *argv, SWPromptStyle style,
                        SWPromptOverflow *ov) {
    return [SudoWhatPromptFormatter formatWithCommandPath:path runasUser:user
                                                      cwd:cwd verifyCode:verify
                                                     argv:argv style:style
                                                 overflow:ov];
}

static void test_format_basic_exact_systemsheet(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", @"hello"], SWPromptStyleSystemSheet);
    NSString *expected =
        @"run a command.\n\nVerify Code: AB12\n\nUser: root\n"
        @"Command: /bin/echo hello\n\nCode must match your terminal";
    EQ(out, expected, "basic SystemSheet exact layout (lowercase, period at top)");
}

static void test_format_basic_exact_selfcontained(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", @"hello"], SWPromptStyleSelfContained);
    NSString *expected =
        @"Run a command.\n\nVerify Code: AB12\n\nUser: root\n"
        @"Command: /bin/echo hello\n\nCode must match your terminal";
    EQ(out, expected, "basic SelfContained exact layout (capital Run, period at top)");
}

static void test_format_path_line(void) {
    NSString *out = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12",
                        @[@"echo"], SWPromptStyleSystemSheet);
    OK([out containsString:@"User: root\nDirectory: /tmp\nCommand: /bin/echo\n\n"],
       "cwd rendered on its own Directory line, between User and Command");
    /* no cwd -> no Directory line at all */
    NSString *noPath = fmt(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo"], SWPromptStyleSystemSheet);
    OK(![noPath containsString:@"Directory:"], "absent cwd omits the Directory line");
}

static void test_format_argv0_dedup(void) {
    /* argv[0] == basename -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo", @"hi"], 0)
        containsString:@"Command: /bin/echo hi"], "dedup basename argv0");
    /* argv[0] == full path -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"/bin/echo", @"hi"], 0)
        containsString:@"Command: /bin/echo hi"], "dedup full-path argv0");
    /* argv[0] != path/basename -> kept */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"notecho", @"hi"], 0)
        containsString:@"Command: /bin/echo notecho hi"], "non-matching argv0 kept");
    /* no argv -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[], 0)
        containsString:@"Command: /bin/echo\n"], "empty argv -> path only");
    /* single argv == basename -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo"], 0)
        containsString:@"Command: /bin/echo\n"], "single matching argv0 -> path only");
}

static void test_format_quoting_in_command(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"X",
                        @[@"echo", @"a b"], SWPromptStyleSystemSheet);
    OK([out containsString:@"/bin/echo 'a b'"], "space arg quoted in command");
}

static void test_format_verify_empty(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"", @[@"echo"], 0);
    OK([out containsString:@"Verify Code: unavailable"], "empty verify -> unavailable");
}

static void test_format_user_overflow(void) {
    /* All-or-nothing: a user value past the cap becomes the marker, never a
     * partial value with an ellipsis. */
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *longUser = rep(@"u", 100);
    NSString *out = fmt_ov(@"/bin/echo", longUser, nil, @"X", @[@"echo"],
                           SWPromptStyleSystemSheet, &ov);
    OK([out containsString:@"User: (see terminal)\n"], "long user -> (see terminal)");
    OK(ov.user && !ov.path && !ov.command, "overflow flags user only");
    OK(![out containsString:@"…"], "no ellipsis anywhere in the prompt");
    /* a short user is shown whole with no marker */
    SWPromptOverflow ov2 = { NO, NO, NO };
    NSString *out2 = fmt_ov(@"/bin/echo", @"alice", nil, @"X", @[@"echo"],
                            SWPromptStyleSystemSheet, &ov2);
    OK([out2 containsString:@"User: alice\n"] && !ov2.user, "short user shown whole");
}

static void test_format_path_overflow(void) {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *longCwd = [@"/" stringByAppendingString:rep(@"c", 300)];
    NSString *out = fmt_ov(@"/bin/echo", @"root", longCwd, @"X", @[@"echo"],
                           SWPromptStyleSystemSheet, &ov);
    OK([out containsString:@"Directory: (see terminal)\n"], "long cwd -> (see terminal)");
    OK(ov.path && !ov.user && !ov.command, "overflow flags path only");
}

static void test_format_command_overflow(void) {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *out = fmt_ov(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo", rep(@"x", 4000)],
                           SWPromptStyleSystemSheet, &ov);
    OK([out containsString:@"Command: (see terminal)\n"], "long command -> (see terminal)");
    OK(ov.command && !ov.user && !ov.path, "overflow flags command only");
    OK([out containsString:BOTTOM_TRUNC], "closing line is the truncated variant");
    OK(![out containsString:BOTTOM_CLEAN], "clean closing line absent when truncated");
}

static void test_format_antiinjection_newline_count(void) {
    /* A non-truncated, no-path layout has exactly 7 structural newlines. An
     * argv token carrying a real newline must be escaped, so the count stays 7,
     * never 8. This is the load-bearing anti-injection assertion. */
    NSString *evilArg = [NSString stringWithFormat:@"a%@b", uni(0x0a)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", evilArg], SWPromptStyleSystemSheet);
    OK(nlcount(out) == 7, "argv newline does not add a structural line");
    /* line/paragraph separators likewise must not introduce breaks */
    NSString *evil2 = [NSString stringWithFormat:@"a%@%@b", uni(0x2028), uni(0x2029)];
    NSString *out2 = fmt(@"/bin/echo", @"root", nil, @"AB12",
                         @[@"echo", evil2], SWPromptStyleSystemSheet);
    OK(nlcount(out2) == 7, "U+2028/2029 in argv add no structural line");
    /* a fake "Command:" line inside an arg must not forge structure: the colon
     * survives but the leading newline is escaped, so it stays one line. */
    NSString *evil3 = [NSString stringWithFormat:@"a%@Command: /bin/sh", uni(0x0a)];
    NSString *out3 = fmt(@"/bin/echo", @"root", nil, @"AB12",
                         @[@"echo", evil3], SWPromptStyleSystemSheet);
    OK(nlcount(out3) == 7, "argv cannot forge an extra labelled line");
}

static void test_format_ellipsis_in_arg_escaped(void) {
    /* No part of the prompt uses a bare U+2026 any more (all-or-nothing dropped
     * the ellipsis marker), so an argv token's real U+2026 must render as
     * … text and leave ZERO bare ellipses in the output. */
    NSString *arg = [NSString stringWithFormat:@"x%@y", uni(0x2026)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", arg], SWPromptStyleSystemSheet);
    OK([out containsString:@"x\\u2026y"], "arg ellipsis shown as \\u2026 text");
    OK(charcount(out, 0x2026) == 0, "no bare ellipsis anywhere in the prompt");
}

static void test_format_length_invariant(void) {
    /* The hard guarantee: rendered length stays within the LA budget for ANY
     * input size, so nothing is silently clipped past the cap. */
    NSUInteger worstSeen = 0;
    NSArray *styles = @[@(SWPromptStyleSystemSheet), @(SWPromptStyleSelfContained)];
    for (NSNumber *st in styles) {
        SWPromptStyle style = (SWPromptStyle)st.integerValue;
        /* one giant single arg */
        for (NSUInteger len = 1; len <= 4000; len += 37) {
            NSString *out = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12",
                                @[@"echo", rep(@"x", len)], style);
            if (out.length > worstSeen) worstSeen = out.length;
            OK(out.length <= kMaxTotal, "single-arg length within budget");
        }
        /* many args */
        NSMutableArray *many = [NSMutableArray arrayWithObject:@"echo"];
        for (NSUInteger i = 0; i < 200; i++) [many addObject:rep(@"y", 20)];
        NSString *out2 = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12", many, style);
        OK(out2.length <= kMaxTotal, "many-args length within budget");
        OK([out2 containsString:SEE_TERMINAL], "over-long command -> (see terminal)");
        /* every field over budget at once */
        NSString *out3 = fmt(rep(@"/p", 2000), rep(@"u", 100),
                             [@"/" stringByAppendingString:rep(@"c", 300)],
                             @"AB12", @[], style);
        OK(out3.length <= kMaxTotal, "all-fields-overflow length within budget");
    }
    fprintf(stderr, "  (worst rendered length observed: %lu / %lu)\n",
            (unsigned long)worstSeen, (unsigned long)kMaxTotal);
}

static void test_format_no_marker_when_it_fits(void) {
    NSString *small = fmt(@"/bin/echo", @"root", nil, @"AB12",
                          @[@"echo", @"hi"], SWPromptStyleSystemSheet);
    OK(![small containsString:SEE_TERMINAL], "no marker when it all fits");
    OK([small containsString:BOTTOM_CLEAN], "clean closing line when nothing overflows");
}

static void test_format_surrogate_boundary(void) {
    /* Emoji flood: all-or-nothing sends it to the terminal; must not crash and
     * must stay within budget. */
    NSMutableArray *argv = [NSMutableArray arrayWithObject:@"echo"];
    [argv addObject:rep(@"😀", 1000)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12", argv,
                        SWPromptStyleSystemSheet);
    OK(out != nil && out.length <= kMaxTotal, "emoji flood stays in budget");
    OK([out containsString:@"Command: (see terminal)"], "emoji flood -> (see terminal)");
}

static void test_format_verifycode_bounded(void) {
    /* verifyCode is capped (plain cut, no marker) purely so the budget holds
     * against a malformed code - a hard guarantee, not a probe. */
    NSString *out = fmt(@"/bin/echo", @"root", nil, rep(@"V", 1000),
                        @[@"echo"], SWPromptStyleSystemSheet);
    OK(out.length <= kMaxTotal, "huge verifyCode stays within budget");
    NSString *expectVerify = [NSString stringWithFormat:@"Verify Code: %@\n", rep(@"V", 32)];
    OK([out containsString:expectVerify], "long verifyCode capped at 32, no marker");
    OK(![out containsString:@"…"], "capped verifyCode adds no ellipsis");
    /* the normal production code (4 chars) must NOT be truncated */
    NSString *normal = fmt(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo"], SWPromptStyleSystemSheet);
    OK([normal containsString:@"Verify Code: AB12\n"], "short code rendered verbatim");
}

/* ---- fullCommandLineForCommandPath: and wasTruncated: (terminal echo) ---- */

static void test_fullcmd_basic(void) {
    /* Same dedup + quoting as the sheet's command region, joined with spaces. */
    EQ(fullcmd(@"/bin/echo", @[@"echo", @"hello"]), @"/bin/echo hello",
       "full command joins path + argv, dedup basename argv0");
    EQ(fullcmd(@"/bin/echo", @[@"/bin/echo", @"hi"]), @"/bin/echo hi",
       "full command dedups full-path argv0");
    EQ(fullcmd(@"/bin/echo", @[@"notecho", @"hi"]), @"/bin/echo notecho hi",
       "full command keeps non-matching argv0");
    EQ(fullcmd(@"/bin/echo", @[]), @"/bin/echo", "full command path only when no argv");
    EQ(fullcmd(@"/bin/echo", @[@"echo", @"a b"]), @"/bin/echo 'a b'",
       "full command shell-quotes a spaced arg");
}

static void test_fullcmd_escapes_controls(void) {
    /* The point of routing through PromptFormatter: a real newline / ESC in
     * argv is rendered as escape TEXT, so writing the result to a terminal can
     * inject no real control byte (no cursor moves, no ANSI). */
    NSString *evil = [NSString stringWithFormat:@"a%@b%@c", uni(0x0a), uni(0x1b)];
    NSString *out = fullcmd(@"/bin/echo", @[@"echo", evil]);
    OK([out containsString:@"\\n"],   "newline in arg rendered as \\n text");
    OK([out containsString:@"\\x1b"], "ESC in arg rendered as \\x1b text");
    OK(charcount(out, 0x0a) == 0, "no real newline byte in the full command");
    OK(charcount(out, 0x1b) == 0, "no real ESC byte in the full command");
}

static void test_fullcmd_untruncated(void) {
    /* The terminal echo has NO budget cap: a command far longer than the
     * sheet's 480-char budget comes back in full, with no truncation marker. */
    NSString *bigArg = rep(@"x", 4000);
    NSString *out = fullcmd(@"/bin/echo", @[@"echo", bigArg]);
    OK(out.length >= 4000, "full command is not capped to the sheet budget");
    OK([out containsString:bigArg], "full command preserves the entire long arg");
    OK(![out containsString:@"COMMAND TRUNCATED"], "full command carries no truncation marker");
}

static void test_wastruncated_flag(void) {
    /* The wasTruncated: wrapper ORs the three overflow flags. It must be YES
     * exactly when some item was replaced by "(see terminal)". */
    OK(!fmt_trunc(@"/bin/echo", @[@"echo", @"hi"], SWPromptStyleSystemSheet),
       "wasTruncated NO for a short command");
    OK(fmt_trunc(@"/bin/echo", @[@"echo", rep(@"x", 4000)], SWPromptStyleSystemSheet),
       "wasTruncated YES for an over-long command");
    NSMutableArray *many = [NSMutableArray arrayWithObject:@"echo"];
    for (NSUInteger i = 0; i < 200; i++) [many addObject:rep(@"y", 20)];
    OK(fmt_trunc(@"/bin/echo", many, SWPromptStyleSystemSheet),
       "wasTruncated YES for many args");
    OK(fmt_trunc(@"/bin/echo", many, SWPromptStyleSelfContained),
       "wasTruncated YES holds for SelfContained too");
    /* The wrapper passes NULL through to the overflow variant; tolerate it. */
    NSString *out = [SudoWhatPromptFormatter formatWithCommandPath:@"/bin/echo"
        runasUser:@"root" cwd:nil verifyCode:@"AB12" argv:@[@"echo", @"hi"]
        style:SWPromptStyleSystemSheet wasTruncated:NULL];
    OK(out != nil, "wasTruncated:NULL is tolerated");
    /* overflow:NULL likewise tolerated */
    NSString *out2 = fmt_ov(@"/bin/echo", @"root", nil, @"AB12", @[@"echo", @"hi"],
                            SWPromptStyleSystemSheet, NULL);
    OK(out2 != nil, "overflow:NULL is tolerated");
}

/* ---- colorizeEscaped: (terminal echo emphasis) ---- */

static void test_color_roundtrip(void) {
    /* The security-load-bearing invariant: stripping the SGR must yield the
     * exact escaped input back, for every category, so colour can never alter
     * the bytes shown — only what is emphasised. */
    NSString *inputs[] = {
        @"/usr/bin/git status",
        esc(@"a\nb\tc"),                 /* control escapes */
        esc(uni(0x202E)),                /* ‮ bidi override */
        q(@"a b"),                       /* quoted token: 'a b' */
        q(@"weird\"`$"),                 /* metachars inside a quoted token */
        @"  lead and  double  ",         /* leading / double / trailing runs */
        esc(@"back\\slash"),             /* literal backslash -> \\ */
        q(@"it's"),                      /* the '\'' quote idiom */
    };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        EQ(strip_sgr(color(inputs[i])), inputs[i], "colorize round-trips to input");
    }
}

static void test_color_categories(void) {
    /* Deceptive Unicode escape \uNNNN -> red (1;31). */
    OK([color(esc(uni(0x200B))) containsString:@"\033[1;31m\\u200b\033[0m"],
       "\\uNNNN wrapped red");
    /* Control-byte escapes -> magenta (1;35). */
    OK([color(esc(@"\n")) containsString:@"\033[1;35m\\n\033[0m"],
       "\\n wrapped magenta");
    OK([color(esc(uni(0x01))) containsString:@"\033[1;35m\\x01\033[0m"],
       "\\xNN wrapped magenta");
    /* Shell metacharacters -> cyan (1;36). */
    EQ(color(@"'"), @"\033[1;36m'\033[0m", "single quote wrapped cyan");
    EQ(color(@"`"), @"\033[1;36m`\033[0m", "backtick wrapped cyan");
    EQ(color(@"\""), @"\033[1;36m\"\033[0m", "double quote wrapped cyan");
    /* Escaped literal backslash \\ -> cyan, consumed as ONE unit so its second
     * '\' is not re-read as the start of a new escape. */
    EQ(color(esc(@"\\")), @"\033[1;36m\\\\\033[0m", "\\\\ wrapped cyan as one unit");
    /* The '\'' idiom's lone backslash renders plain; round-trip proves it. */
    EQ(strip_sgr(color(q(@"it's"))), q(@"it's"), "quote idiom round-trips");
}

static void test_color_whitespace(void) {
    /* Single interior space stays plain, so ordinary commands are unmarked. */
    EQ(color(@"a b"), @"a b", "single interior space is not underlined");
    /* A run of 2+ spaces is highlighted (grey background). */
    OK([color(@"a  b") containsString:@"\033[100m  \033[0m"], "double space highlighted");
    /* Leading and trailing single spaces are the invisible-padding cases. */
    OK([color(@" x") hasPrefix:@"\033[100m \033[0m"], "leading space highlighted");
    OK([color(@"x ") hasSuffix:@"\033[100m \033[0m"], "trailing space highlighted");
}

static void test_color_nil_empty_clean(void) {
    OK(color(nil) == nil, "nil passes through");
    EQ(color(@""), @"", "empty passes through");
    /* No anomalies, only single-space separators -> byte-identical (no SGR). */
    EQ(color(@"/usr/bin/git status"), @"/usr/bin/git status", "clean command unchanged");
}

int main(void) {
    @autoreleasepool {
        test_escape_named();
        test_escape_antispoof_backslash();
        test_escape_hex_c0_del();
        test_escape_c1_and_separators();
        test_escape_ellipsis_homoglyphs();
        test_escape_bidi();
        test_escape_zero_width();
        test_escape_dot_runs();
        test_escape_dot_run_transitions();
        test_escape_lone_surrogate();
        test_escape_passthrough();

        test_quote_empty_nil();
        test_quote_safe();
        test_quote_unsafe();
        test_quote_embedded_single_quote();
        test_quote_control_chars_get_quoted();

        test_format_basic_exact_systemsheet();
        test_format_basic_exact_selfcontained();
        test_format_path_line();
        test_format_argv0_dedup();
        test_format_quoting_in_command();
        test_format_verify_empty();
        test_format_user_overflow();
        test_format_path_overflow();
        test_format_command_overflow();
        test_format_antiinjection_newline_count();
        test_format_ellipsis_in_arg_escaped();
        test_format_length_invariant();
        test_format_no_marker_when_it_fits();
        test_format_surrogate_boundary();
        test_format_verifycode_bounded();

        test_fullcmd_basic();
        test_fullcmd_escapes_controls();
        test_fullcmd_untruncated();
        test_wastruncated_flag();

        test_color_roundtrip();
        test_color_categories();
        test_color_whitespace();
        test_color_nil_empty_clean();

        SW_SUMMARY("PromptFormatter");
    }
}
