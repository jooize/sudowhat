/*
 * Adversarial unit tests for SudoWhatPromptFormatter.
 *
 * This class is the anti-spoofing boundary: it shell-quotes argv tokens and
 * escapes hidden characters (the untrusted-text hidden list) so the bytes
 * shown in the Touch ID sheet cannot fake structure (hidden line breaks,
 * reordered text, an escape that is not one). These tests try hard to break
 * those guarantees.
 */
#import "PromptFormatter.h"
#import "sw_test.h"

/* escapeControlChars: is now public (the plugin escapes echoed values with it),
 * so no category is needed. */

/* Closing-line constants copied verbatim from PromptFormatter.m. If these ever
 * mismatch the source the exact-match tests below will flag it. */
static NSString *const BOTTOM_CLEAN = @"Code must match your terminal.";
static NSString *const BOTTOM_TRUNC = @"⚠️ Long items are shown in your terminal.";
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
/* The escape the sheet shows for a code point, built here rather than typed
 * as a literal: U(@"202E") is a backslash, "u{", the hex, "}". */
static NSString *U(NSString *hex) {
    return [NSString stringWithFormat:@"%Cu{%@}", (unichar)'\\', hex];
}
static NSString *astral(UTF32Char u) {
    UniChar pair[2];
    CFStringGetSurrogatePairForLongCharacter(u, pair);
    return [NSString stringWithCharacters:pair length:2];
}

static void test_escape_form(void) {
    /* Every hidden character shows as backslash, u{, uppercase hex with no
     * leading zeros, }. No named escapes: a line feed is its code point. */
    EQ(esc(uni(0x0a)), U(@"A"), "line feed -> its code point");
    EQ(esc(uni(0x0d)), U(@"D"), "carriage return -> its code point");
    EQ(esc(uni(0x09)), U(@"9"), "tab -> its code point");
    EQ(esc(uni(0x00)), U(@"0"), "NUL -> its code point");
    EQ(esc(uni(0x1b)), U(@"1B"), "ESC -> uppercase hex");
    EQ(esc(uni(0x7f)), U(@"7F"), "DEL");
    EQ(esc(([NSString stringWithFormat:@"a%@b", uni(0x0a)])),
       ([NSString stringWithFormat:@"a%@b", U(@"A")]), "escape between letters");
}

static void test_escape_backslash(void) {
    /* An escape on screen can only be one: a literal backslash that would read
     * as the start of an escape (before u{, or before x and a hex digit) shows
     * as its own escape; every other backslash is drawn as itself. */
    NSString *bs = U(@"5C");
    EQ(esc(@"\\"), @"\\", "a lone backslash is itself");
    EQ(esc(@"\\n"), @"\\n", "backslash-n is itself");
    EQ(esc(@"C:\\Users"), @"C:\\Users", "a path backslash is itself");
    EQ(esc(@"\\u41"), @"\\u41", "backslash-u without a brace is itself");
    EQ(esc(@"\\xg"), @"\\xg", "backslash-x without a hex digit is itself");
    EQ(esc(@"\\x"), @"\\x", "a trailing backslash-x is itself");
    EQ(esc(@"\\u{41}"), ([NSString stringWithFormat:@"%@u{41}", bs]),
       "backslash before u{ is escaped");
    EQ(esc(@"\\x41"), ([NSString stringWithFormat:@"%@x41", bs]),
       "backslash before x and a hex digit is escaped");
    EQ(esc(@"\\xff"), ([NSString stringWithFormat:@"%@xff", bs]),
       "lowercase hex digits count too");
    /* A literal backslash-n can no longer pass for a line feed. */
    OK(![esc(@"\\n") isEqualToString:esc(uni(0x0a))],
       "literal backslash-n distinguishable from a real line feed");
}

static void test_escape_hidden_list(void) {
    /* Both ends of every range and each single point on the hidden list. */
    struct { UTF32Char cp; NSString *hex; } pts[] = {
        {0x80, @"80"}, {0x85, @"85"}, {0x9f, @"9F"}, {0xa0, @"A0"}, {0xad, @"AD"},
        {0x34f, @"34F"}, {0x61c, @"61C"}, {0x115f, @"115F"}, {0x1160, @"1160"},
        {0x17b4, @"17B4"}, {0x17b5, @"17B5"}, {0x180b, @"180B"}, {0x180e, @"180E"},
        {0x2000, @"2000"}, {0x200b, @"200B"}, {0x200f, @"200F"},
        {0x2028, @"2028"}, {0x2029, @"2029"}, {0x202e, @"202E"}, {0x202f, @"202F"},
        {0x205f, @"205F"}, {0x2060, @"2060"}, {0x2066, @"2066"}, {0x206f, @"206F"},
        {0x3000, @"3000"}, {0x3164, @"3164"}, {0xfe00, @"FE00"}, {0xfe0f, @"FE0F"},
        {0xfeff, @"FEFF"}, {0xffa0, @"FFA0"}, {0xfff9, @"FFF9"}, {0xfffb, @"FFFB"},
        {0xe0000, @"E0000"}, {0xe0041, @"E0041"}, {0xe007f, @"E007F"},
        {0xe0100, @"E0100"}, {0xe01ef, @"E01EF"},
    };
    for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++) {
        NSString *in = pts[i].cp > 0xffff ? astral(pts[i].cp) : uni((unichar)pts[i].cp);
        EQ(esc(in), U(pts[i].hex), "a hidden-list code point is escaped");
    }
    /* Just outside the list, and lookalikes: drawn as themselves. */
    UTF32Char outside[] = { 0x7e, 0xa1, 0xac, 0x34e, 0x2010, 0x2030, 0x205e,
                            0x2070, 0xfe10, 0xfffc, 0x2026, 0x22ef, 0x2024,
                            0xe0080, 0xe01f0 };
    for (size_t i = 0; i < sizeof(outside) / sizeof(outside[0]); i++) {
        NSString *in = outside[i] > 0xffff ? astral(outside[i]) : uni((unichar)outside[i]);
        EQ(esc(in), in, "a code point off the hidden list is itself");
    }
    EQ(esc(@"..."), @"...", "a run of dots is itself (a lookalike, out of scope)");
}

static void test_escape_bidi(void) {
    /* Trojan Source (CVE-2021-42574): bidi overrides visually reorder text so
     * the glyphs on the sheet can read as a different command than runs. Every
     * one must be escaped, even inside a single-quoted token. */
    EQ(esc(uni(0x202A)), U(@"202A"), "esc LRE");
    EQ(esc(uni(0x202E)), U(@"202E"), "esc RLO");
    EQ(esc(uni(0x2066)), U(@"2066"), "esc LRI");
    EQ(esc(uni(0x2069)), U(@"2069"), "esc PDI");
    EQ(esc(uni(0x200E)), U(@"200E"), "esc LRM");
    EQ(esc(uni(0x061C)), U(@"61C"), "esc ALM");
    /* the canonical attack token still carries the raw override nowhere */
    NSString *rlo = [NSString stringWithFormat:@"/etc/%@fdp.ssm", uni(0x202E)];
    OK(charcount(esc(rlo), 0x202E) == 0, "no raw RLO survives escaping");
    /* and single-quoting does not smuggle it either */
    OK(charcount(q(rlo), 0x202E) == 0, "no raw RLO survives quoteToken");
}

static void test_escape_zero_width(void) {
    EQ(esc(uni(0x200B)), U(@"200B"), "esc ZWSP");
    EQ(esc(uni(0x200C)), U(@"200C"), "esc ZWNJ");
    EQ(esc(uni(0x200D)), U(@"200D"), "esc ZWJ");
    EQ(esc(uni(0x2060)), U(@"2060"), "esc WORD JOINER");
    EQ(esc(uni(0xFEFF)), U(@"FEFF"), "esc ZWNBSP/BOM");
    /* A variation selector after a character draws nothing but can carry
     * data, so it shows too, astral ones included. */
    EQ(esc(([NSString stringWithFormat:@"a%@", uni(0xFE0F)])),
       ([NSString stringWithFormat:@"a%@", U(@"FE0F")]), "esc VS16 after a letter");
    EQ(esc(([NSString stringWithFormat:@"a%@", astral(0xE0100)])),
       ([NSString stringWithFormat:@"a%@", U(@"E0100")]), "esc VS17 after a letter");
}

static void test_escape_lone_surrogate(void) {
    /* A lone (unpaired) surrogate is not text: drawn raw it would become a
     * replacement glyph that hides which unit was there, so it shows as its
     * escape. It must not crash, and it never pairs with its neighbours. */
    EQ(esc(uni(0xD800)), U(@"D800"), "lone high surrogate is escaped");
    EQ(esc(uni(0xDC00)), U(@"DC00"), "lone low surrogate is escaped");
    EQ(esc(([NSString stringWithFormat:@"%@a", uni(0xD83D)])),
       ([NSString stringWithFormat:@"%@a", U(@"D83D")]),
       "a high surrogate before a letter stays lone");
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
    /* A hidden character escapes to a backslash sequence; backslash is unsafe,
     * so the token gets single-quoted with the escape shown literally. */
    EQ(q(uni(0x09)), ([NSString stringWithFormat:@"'%@'", U(@"9")]), "tab token");
    EQ(q(uni(0x0a)), ([NSString stringWithFormat:@"'%@'", U(@"A")]), "line feed token");
    EQ(q(uni(0x07)), ([NSString stringWithFormat:@"'%@'", U(@"7")]), "bell token");
    EQ(q(@"\\"),     @"'\\'", "a backslash token is quoted, the backslash itself");
    EQ(q(([NSString stringWithFormat:@"a%@b", uni(0x0a)])),
       ([NSString stringWithFormat:@"'a%@b'", U(@"A")]),
       "line feed inside a word (no real break)");
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
        @"run a command.\n\nRUN AS\nroot\n\nEXECUTE\n/bin/echo hello\n\n"
        @"Verify Code: AB12\n\nCode must match your terminal.";
    EQ(out, expected, "basic SystemSheet exact layout (lowercase, period at top)");
}

/* macOS 27's sheet appends its period even after ours, so SystemHeadline is
 * SystemSheet with the final stop left off -- and nothing else changed. */
static void test_format_basic_exact_systemheadline(void) {
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", @"hello"], SWPromptStyleSystemHeadline);
    NSString *expected =
        @"run a command.\n\nRUN AS\nroot\n\nEXECUTE\n/bin/echo hello\n\n"
        @"Verify Code: AB12\n\nCode must match your terminal";
    EQ(out, expected, "basic SystemHeadline exact layout (no final stop)");
    NSString *sheet = fmt(@"/bin/echo", @"root", nil, @"AB12",
                          @[@"echo", @"hello"], SWPromptStyleSystemSheet);
    EQ([out stringByAppendingString:@"."], sheet,
       "SystemHeadline differs from SystemSheet by the final stop only");
    NSString *trunc = fmt(@"/bin/echo", @"root", nil, @"AB12",
                          @[@"echo", rep(@"x", 4000)], SWPromptStyleSystemHeadline);
    OK([trunc hasSuffix:@"shown in your terminal"],
       "the truncated closing line ends bare too");
}

static void test_format_path_line(void) {
    NSString *out = fmt(@"/bin/echo", @"root", @"/tmp", @"AB12",
                        @[@"echo"], SWPromptStyleSystemSheet);
    NSString *expected =
        @"run a command.\n\nRUN AS\nroot\n\nDIRECTORY\n/tmp\n\n"
        @"EXECUTE\n/bin/echo\n\nVerify Code: AB12\n\nCode must match your terminal.";
    EQ(out, expected,
       "cwd rendered under its own DIRECTORY label, between RUN AS and EXECUTE");
    /* no cwd -> no DIRECTORY field at all */
    NSString *noPath = fmt(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo"], SWPromptStyleSystemSheet);
    OK(![noPath containsString:@"DIRECTORY"], "absent cwd omits the DIRECTORY field");
}

static void test_format_argv0_dedup(void) {
    /* argv[0] == basename -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo", @"hi"], 0)
        containsString:@"EXECUTE\n/bin/echo hi"], "dedup basename argv0");
    /* argv[0] == full path -> dropped */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"/bin/echo", @"hi"], 0)
        containsString:@"EXECUTE\n/bin/echo hi"], "dedup full-path argv0");
    /* argv[0] != path/basename -> kept */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"notecho", @"hi"], 0)
        containsString:@"EXECUTE\n/bin/echo notecho hi"], "non-matching argv0 kept");
    /* no argv -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[], 0)
        containsString:@"EXECUTE\n/bin/echo\n"], "empty argv -> path only");
    /* single argv == basename -> just the path */
    OK([fmt(@"/bin/echo", @"root", nil, @"X", @[@"echo"], 0)
        containsString:@"EXECUTE\n/bin/echo\n"], "single matching argv0 -> path only");
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
    OK([out containsString:@"RUN AS\n(see terminal)\n"], "long user -> (see terminal)");
    OK(ov.user && !ov.path && !ov.command, "overflow flags user only");
    OK(![out containsString:@"…"], "no ellipsis anywhere in the prompt");
    /* a short user is shown whole with no marker */
    SWPromptOverflow ov2 = { NO, NO, NO };
    NSString *out2 = fmt_ov(@"/bin/echo", @"alice", nil, @"X", @[@"echo"],
                            SWPromptStyleSystemSheet, &ov2);
    OK([out2 containsString:@"RUN AS\nalice\n"] && !ov2.user, "short user shown whole");
}

static void test_format_path_overflow(void) {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *longCwd = [@"/" stringByAppendingString:rep(@"c", 300)];
    NSString *out = fmt_ov(@"/bin/echo", @"root", longCwd, @"X", @[@"echo"],
                           SWPromptStyleSystemSheet, &ov);
    OK([out containsString:@"DIRECTORY\n(see terminal)\n"], "long cwd -> (see terminal)");
    OK(ov.path && !ov.user && !ov.command, "overflow flags path only");
}

static void test_format_command_overflow(void) {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *out = fmt_ov(@"/bin/echo", @"root", nil, @"AB12",
                           @[@"echo", rep(@"x", 4000)],
                           SWPromptStyleSystemSheet, &ov);
    OK([out containsString:@"EXECUTE\n(see terminal)\n"], "long command -> (see terminal)");
    OK(ov.command && !ov.user && !ov.path, "overflow flags command only");
    OK([out containsString:BOTTOM_TRUNC], "closing line is the truncated variant");
    OK(![out containsString:BOTTOM_CLEAN], "clean closing line absent when truncated");
}

static void test_format_antiinjection_newline_count(void) {
    /* A non-truncated, no-path layout has exactly 10 structural newlines. An
     * argv token carrying a real newline must be escaped, so the count stays 10,
     * never 11. This is the load-bearing anti-injection assertion. */
    NSString *evilArg = [NSString stringWithFormat:@"a%@b", uni(0x0a)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", evilArg], SWPromptStyleSystemSheet);
    OK(nlcount(out) == 10, "argv newline does not add a structural line");
    /* line/paragraph separators likewise must not introduce breaks */
    NSString *evil2 = [NSString stringWithFormat:@"a%@%@b", uni(0x2028), uni(0x2029)];
    NSString *out2 = fmt(@"/bin/echo", @"root", nil, @"AB12",
                         @[@"echo", evil2], SWPromptStyleSystemSheet);
    OK(nlcount(out2) == 10, "U+2028/2029 in argv add no structural line");
    /* a fake stacked "EXECUTE" label inside an arg must not forge structure:
     * the text survives (the spelling is not the guarantee) but its
     * surrounding newlines are escaped, so it can never sit alone on a line of
     * its own, let alone after a blank line. */
    NSString *evil3 = [NSString stringWithFormat:@"a%@%@EXECUTE%@/bin/sh",
                       uni(0x0a), uni(0x0a), uni(0x0a)];
    NSString *out3 = fmt(@"/bin/echo", @"root", nil, @"AB12",
                         @[@"echo", evil3], SWPromptStyleSystemSheet);
    OK(nlcount(out3) == 10, "argv cannot forge an extra labelled field");
    OK([out3 containsString:([NSString stringWithFormat:@"EXECUTE%@/bin/sh", U(@"A")])],
       "the label text itself is not censored");
    /* the real label is the only one preceded by a blank line: exactly one
     * "\n\nEXECUTE\n" occurs, no matter what the argv spells. */
    NSUInteger realLabels = 0;
    NSRange scan = NSMakeRange(0, out3.length);
    while (scan.length > 0) {
        NSRange hit = [out3 rangeOfString:@"\n\nEXECUTE\n" options:0 range:scan];
        if (hit.location == NSNotFound) break;
        realLabels++;
        scan = NSMakeRange(hit.location + 1, out3.length - hit.location - 1);
    }
    OK(realLabels == 1, "exactly one blank-line-anchored EXECUTE label");
}

static void test_format_ellipsis_in_arg_drawn(void) {
    /* No part of the prompt uses U+2026 as a marker (all-or-nothing dropped
     * the ellipsis marker for "(see terminal)"), so an argv token's real
     * U+2026 is a lookalike with nothing to impersonate: drawn as itself, and
     * the only ellipsis in the prompt is the argument's own. */
    NSString *arg = [NSString stringWithFormat:@"x%@y", uni(0x2026)];
    NSString *out = fmt(@"/bin/echo", @"root", nil, @"AB12",
                        @[@"echo", arg], SWPromptStyleSystemSheet);
    OK([out containsString:arg], "arg ellipsis drawn as itself");
    OK(charcount(out, 0x2026) == 1, "the argument's ellipsis is the only one");
}

static void test_format_length_invariant(void) {
    /* The hard guarantee: rendered length stays within the LA budget for ANY
     * input size, so nothing is silently clipped past the cap. */
    NSUInteger worstSeen = 0;
    NSArray *styles = @[@(SWPromptStyleSystemSheet), @(SWPromptStyleSystemHeadline)];
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
    OK([out containsString:@"EXECUTE\n(see terminal)"], "emoji flood -> (see terminal)");
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
    OK([out containsString:U(@"A")],  "line feed in arg rendered as escape text");
    OK([out containsString:U(@"1B")], "ESC in arg rendered as escape text");
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
    OK(fmt_trunc(@"/bin/echo", many, SWPromptStyleSystemHeadline),
       "wasTruncated YES holds for SystemHeadline too");
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

int main(void) {
    @autoreleasepool {
        test_escape_form();
        test_escape_backslash();
        test_escape_hidden_list();
        test_escape_bidi();
        test_escape_zero_width();
        test_escape_lone_surrogate();
        test_escape_passthrough();

        test_quote_empty_nil();
        test_quote_safe();
        test_quote_unsafe();
        test_quote_embedded_single_quote();
        test_quote_control_chars_get_quoted();

        test_format_basic_exact_systemsheet();
        test_format_basic_exact_systemheadline();
        test_format_path_line();
        test_format_argv0_dedup();
        test_format_quoting_in_command();
        test_format_verify_empty();
        test_format_user_overflow();
        test_format_path_overflow();
        test_format_command_overflow();
        test_format_antiinjection_newline_count();
        test_format_ellipsis_in_arg_drawn();
        test_format_length_invariant();
        test_format_no_marker_when_it_fits();
        test_format_surrogate_boundary();
        test_format_verifycode_bounded();

        test_fullcmd_basic();
        test_fullcmd_escapes_controls();
        test_fullcmd_untruncated();
        test_wastruncated_flag();

        SW_SUMMARY("PromptFormatter");
    }
}
