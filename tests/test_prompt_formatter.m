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

@interface SudoWhatPromptFormatter (SWTest)
+ (NSString *)escapeControlChars:(NSString *)s;
@end

/* Trailer constants copied verbatim from PromptFormatter.m:209-210. If these
 * ever mismatch the source the exact-match tests below will flag it. */
static NSString *const TRAILER_SELF =
  @"Code verifies origin. Command shown is what runs, unless marked truncated with ellipsis \"…\" (\\u2026).";
static NSString *const TRAILER_SHEET =
  @"Code verifies origin. Command shown is what runs, unless marked truncated with ellipsis \"…\" (\\u2026)";

static const NSUInteger kMaxTotal = 480;   /* PromptFormatter.m:197 */

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
    /* mixed with text */
    EQ(esc(([NSString stringWithFormat:@"a%@b", uni(0x2026)])), @"a\\u2026b",
       "esc ellipsis between letters");
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

/* ---- formatWith: layout, dedup, caps, truncation, length invariant ---- */

static void test_format_basic_exact_systemsheet(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", @"hello"], SWPromptStyleSystemSheet);
    NSString *expected = [NSString stringWithFormat:
        @"%@\n\n%@\n\n\n%@\n\n\n%@",
        @"run as user root", @"Verify code: AB12", @"/bin/echo hello", TRAILER_SHEET];
    EQ(out, expected, "basic SystemSheet exact layout");
}

static void test_format_basic_exact_selfcontained(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", @"hello"], SWPromptStyleSelfContained);
    NSString *expected = [NSString stringWithFormat:
        @"%@\n\n%@\n\n\n%@\n\n\n%@",
        @"Run as user root", @"Verify code: AB12", @"/bin/echo hello", TRAILER_SELF];
    EQ(out, expected, "basic SelfContained exact layout (capital Run, period)");
}

static void test_format_cwd_in_header(void) {
    NSString *out = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12",
                        @[@"echo"], SWPromptStyleSystemSheet);
    OK([out hasPrefix:@"run as user root in directory /tmp\n\n"],
       "cwd rendered in header");
}

static void test_format_argv0_dedup(void) {
    /* argv[0] == basename -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo", @"hi"], 0)
        containsString:@"/bin/echo hi"], "dedup basename argv0");
    /* argv[0] == full path -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"/bin/echo", @"hi"], 0)
        containsString:@"/bin/echo hi"], "dedup full-path argv0");
    /* argv[0] != path/basename -> kept */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"notecho", @"hi"], 0)
        containsString:@"/bin/echo notecho hi"], "non-matching argv0 kept");
    /* no argv -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[], 0)
        containsString:@"/bin/echo"], "empty argv -> path only");
    /* single argv == basename -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo"], 0)
        containsString:@"/bin/echo"], "single matching argv0 -> path only");
}

static void test_format_quoting_in_command(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"X",
                        @[@"echo", @"a b"], SWPromptStyleSystemSheet);
    OK([out containsString:@"/bin/echo 'a b'"], "space arg quoted in command");
}

static void test_format_verify_empty(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"", @[@"echo"], 0);
    OK([out containsString:@"Verify code: unavailable"], "empty verify -> unavailable");
}

static void test_format_user_cap(void) {
    NSString *longUser = rep(@"u", 50);
    NSString *out = fmt(@"/bin/echo", longUser, nil, @"X", @[@"echo"], 0);
    NSString *expectHead = [NSString stringWithFormat:@"run as user %@…", rep(@"u", 32)];
    OK([out hasPrefix:expectHead], "long user capped at 32 + ellipsis");
}

static void test_format_cwd_cap(void) {
    NSString *longCwd = rep(@"c", 100);
    NSString *out = fmt(@"/bin/echo", @"root", longCwd, @"X", @[@"echo"], 0);
    NSString *expectCwd = [NSString stringWithFormat:@"in directory %@…", rep(@"c", 80)];
    OK([out containsString:expectCwd], "long cwd capped at 80 + ellipsis");
}

static void test_format_antiinjection_newline_count(void) {
    /* A non-truncated layout has exactly 8 structural newlines. An argv token
     * carrying a real newline must be escaped, so the count stays 8 - never 9.
     * This is the load-bearing anti-injection assertion. */
    NSString *evilArg = [NSString stringWithFormat:@"a%@b", uni(0x0a)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", evilArg], SWPromptStyleSystemSheet);
    OK(nlcount(out) == 8, "argv newline does not add a structural line");
    /* line/paragraph separators likewise must not introduce breaks */
    NSString *evil2 = [NSString stringWithFormat:@"a%@%@b", uni(0x2028), uni(0x2029)];
    NSString *out2 = fmt(@"/bin/echo", @"root", nil, @"AB12",
                         @[@"echo", evil2], SWPromptStyleSystemSheet);
    OK(nlcount(out2) == 8, "U+2028/2029 in argv add no structural line");
}

static void test_format_ellipsis_in_arg_escaped(void) {
    /* An argv token containing a real U+2026 must appear as the literal text
     * …, never as a bare ellipsis that could fake truncation. The only
     * bare U+2026 chars in a non-truncated prompt come from the trailer. */
    NSString *arg = [NSString stringWithFormat:@"x%@y", uni(0x2026)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", arg], SWPromptStyleSystemSheet);
    OK([out containsString:@"x\\u2026y"], "arg ellipsis shown as \\u2026 text");
    /* trailer contains exactly one bare U+2026; arg added none */
    OK(charcount(out, 0x2026) == 1, "no bare ellipsis leaked from argv");
}

static void test_format_length_invariant(void) {
    /* The hard guarantee: rendered length stays within the LA budget for ANY
     * command size, so nothing is silently clipped past the cap. */
    NSUInteger worstSeen = 0;
    NSArray *styles = @[@(SWPromptStyleSystemSheet), @(SWPromptStyleSelfContained)];
    for (NSNumber *st in styles) {
        SWPromptStyle style = (SWPromptStyle)st.integerValue;
        /* one giant single arg (forces middle-break) */
        for (NSUInteger len = 1; len <= 4000; len += 37) {
            NSString *out = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12",
                                @[@"echo", rep(@"x", len)], style);
            if (out.length > worstSeen) worstSeen = out.length;
            OK(out.length <= kMaxTotal, "single-arg length within budget");
        }
        /* many args (forces above-indicator + trailing drop) */
        NSMutableArray *many = [NSMutableArray arrayWithObject:@"echo"];
        for (NSUInteger i = 0; i < 200; i++) [many addObject:rep(@"y", 20)];
        NSString *out2 = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12", many, style);
        OK(out2.length <= kMaxTotal, "many-args length within budget");
        OK([out2 containsString:@"… COMMAND TRUNCATED …"], "truncation marker present");
        /* a long path as the only token */
        NSString *out3 = fmt(rep(@"/p", 2000), @"root", nil, @"AB12", @[], style);
        OK(out3.length <= kMaxTotal, "long-path length within budget");
    }
    fprintf(stderr, "  (worst rendered length observed: %lu / %lu)\n",
            (unsigned long)worstSeen, (unsigned long)kMaxTotal);
}

static void test_format_truncation_marker_only_when_truncated(void) {
    NSString *small = fmt(@"/bin/echo", @"root", nil, @"AB12",
                          @[@"echo", @"hi"], SWPromptStyleSystemSheet);
    OK(![small containsString:@"COMMAND TRUNCATED"], "no marker when it all fits");
}

static void test_format_middle_break_preserves_ends(void) {
    /* A single over-long last arg should middle-break: head + marker + tail,
     * so the user still sees BOTH ends of the argument, not just the start. */
    NSString *arg = [NSString stringWithFormat:@"%@%@", rep(@"A", 300), rep(@"Z", 300)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", arg], SWPromptStyleSystemSheet);
    OK([out containsString:@"… COMMAND TRUNCATED …"], "middle-break shows marker");
    OK([out containsString:@"AAAAAAAA"], "middle-break preserves head of arg");
    OK([out containsString:@"ZZZZZZZZ"], "middle-break preserves tail of arg");
    OK(out.length <= kMaxTotal, "middle-break stays within budget");
}

static void test_format_surrogate_boundary(void) {
    /* Emoji at the truncation boundary: must not crash and must stay within
     * budget even if a surrogate pair is split (a split yields a lone
     * surrogate, cosmetically a replacement glyph, but never an overflow). */
    NSMutableArray *argv = [NSMutableArray arrayWithObject:@"echo"];
    [argv addObject:rep(@"😀", 1000)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12", argv,
                        SWPromptStyleSystemSheet);
    OK(out != nil && out.length <= kMaxTotal, "emoji flood stays in budget");
}

static void test_format_verifycode_bounded(void) {
    /* verifyCode is now head-capped like user/cwd, so the length invariant
     * holds even for an absurd code - this is a hard guarantee, not a probe. */
    NSString *out = fmt(@"/bin/echo", @"root", nil, rep(@"V", 1000),
                        @[@"echo"], SWPromptStyleSystemSheet);
    OK(out.length <= kMaxTotal, "huge verifyCode stays within budget");
    NSString *expectVerify = [NSString stringWithFormat:@"Verify code: %@…", rep(@"V", 32)];
    OK([out containsString:expectVerify], "long verifyCode capped at 32 + ellipsis");
    /* the normal production code (4 chars) must NOT be truncated */
    NSString *normal = fmt(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo"], SWPromptStyleSystemSheet);
    OK([normal containsString:@"Verify code: AB12\n"], "short code rendered verbatim");
    OK(![normal containsString:@"AB12…"], "short code not given a truncation ellipsis");
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
    /* The flag the plugin keys the terminal echo on. It must be YES exactly when
     * the sheet shows a truncation marker (the existing length tests pin that the
     * marker appears in these same cases). */
    OK(!fmt_trunc(@"/bin/echo", @[@"echo", @"hi"], SWPromptStyleSystemSheet),
       "wasTruncated NO for a short command");
    OK(fmt_trunc(@"/bin/echo", @[@"echo", rep(@"x", 4000)], SWPromptStyleSystemSheet),
       "wasTruncated YES for an over-long arg (middle-break)");
    NSMutableArray *many = [NSMutableArray arrayWithObject:@"echo"];
    for (NSUInteger i = 0; i < 200; i++) [many addObject:rep(@"y", 20)];
    OK(fmt_trunc(@"/bin/echo", many, SWPromptStyleSystemSheet),
       "wasTruncated YES for many args (above-indicator)");
    OK(fmt_trunc(@"/bin/echo", many, SWPromptStyleSelfContained),
       "wasTruncated YES holds for SelfContained too");
    /* The 6-arg wrapper passes NULL; the formatter must tolerate it. */
    NSString *out = [SudoWhatPromptFormatter formatWithCommandPath:@"/bin/echo"
        runasUser:@"root" cwd:nil verifyCode:@"AB12" argv:@[@"echo", @"hi"]
        style:SWPromptStyleSystemSheet wasTruncated:NULL];
    OK(out != nil, "wasTruncated:NULL is tolerated");
}

int main(void) {
    @autoreleasepool {
        test_escape_named();
        test_escape_antispoof_backslash();
        test_escape_hex_c0_del();
        test_escape_c1_and_separators();
        test_escape_ellipsis_homoglyphs();
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
        test_format_cwd_in_header();
        test_format_argv0_dedup();
        test_format_quoting_in_command();
        test_format_verify_empty();
        test_format_user_cap();
        test_format_cwd_cap();
        test_format_antiinjection_newline_count();
        test_format_ellipsis_in_arg_escaped();
        test_format_length_invariant();
        test_format_truncation_marker_only_when_truncated();
        test_format_middle_break_preserves_ends();
        test_format_surrogate_boundary();
        test_format_verifycode_bounded();

        test_fullcmd_basic();
        test_fullcmd_escapes_controls();
        test_fullcmd_untruncated();
        test_wastruncated_flag();

        SW_SUMMARY("PromptFormatter");
    }
}
