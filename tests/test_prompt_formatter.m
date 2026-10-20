/*
 * Adversarial unit tests for SudoWhatPromptFormatter.
 *
 * This class lays out the Touch ID sheet, the anti-spoofing boundary: every
 * value on it is escaped and shell-quoted by escape_core from the raw bytes
 * sudo handed over, so the text shown cannot fake structure (hidden line
 * breaks, reordered text, an escape that is not one) and no value is dropped
 * for its bytes. The escape rules themselves are pinned in escape_core's own
 * test module; these tests try hard to break the layout built on them.
 */
#import "PromptFormatter.h"
#import "sw_test.h"

/* Closing-line constants copied verbatim from PromptFormatter.m. If these ever
 * mismatch the source the exact-match tests below will flag it. */
static NSString *const BOTTOM_CLEAN = @"Code must match your terminal.";
static NSString *const BOTTOM_TRUNC = @"⚠️ Long items are shown in your terminal.";
static NSString *const SEE_TERMINAL = @"(see terminal)";

static const NSUInteger kMaxTotal = 480;   /* PromptFormatter.m kMaxTotal */

/* The values as sudo hands them over: NUL-terminated byte strings, argv a
 * NULL-terminated array of them. These helpers take NSStrings for the many
 * valid-UTF-8 cases; the invalid-byte tests call the formatter with C strings
 * directly. */
static NSString *fmt_ov(NSString *path, NSString *user, NSString *cwd,
                        NSString *verify, NSArray<NSString *> *argv,
                        SWPromptStyle style, SWPromptOverflow *ov) {
    NSUInteger n = argv.count;
    char *a[n + 1];
    for (NSUInteger i = 0; i < n; i++) a[i] = (char *)argv[i].UTF8String;
    a[n] = NULL;
    return [SudoWhatPromptFormatter formatWithCommandPath:path.UTF8String
                                                runasUser:user.UTF8String
                                                      cwd:cwd.UTF8String
                                               verifyCode:verify
                                                     argv:a
                                                    style:style
                                                 overflow:ov];
}
static NSString *fmt(NSString *path, NSString *user, NSString *cwd,
                     NSString *verify, NSArray *argv, SWPromptStyle style) {
    return fmt_ov(path, user, cwd, verify, argv, style, NULL);
}
static BOOL fmt_trunc(NSString *path, NSArray<NSString *> *argv,
                      SWPromptStyle style) {
    NSUInteger n = argv.count;
    char *a[n + 1];
    for (NSUInteger i = 0; i < n; i++) a[i] = (char *)argv[i].UTF8String;
    a[n] = NULL;
    BOOL t = NO;
    [SudoWhatPromptFormatter formatWithCommandPath:path.UTF8String
                                         runasUser:"root" cwd:NULL
                                        verifyCode:@"AB12" argv:a style:style
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

/* ---- formatWith: layout, dedup, caps, all-or-nothing overflow, budget ---- */

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
    char *hi[] = { (char *)"echo", (char *)"hi", NULL };
    NSString *out = [SudoWhatPromptFormatter formatWithCommandPath:"/bin/echo"
        runasUser:"root" cwd:NULL verifyCode:@"AB12" argv:hi
        style:SWPromptStyleSystemSheet wasTruncated:NULL];
    OK(out != nil, "wasTruncated:NULL is tolerated");
    /* overflow:NULL likewise tolerated */
    NSString *out2 = fmt_ov(@"/bin/echo", @"root", nil, @"AB12", @[@"echo", @"hi"],
                            SWPromptStyleSystemSheet, NULL);
    OK(out2 != nil, "overflow:NULL is tolerated");
}

/* ---- bytes that are not valid UTF-8: shown escaped, never dropped ---- */

/* The defect this pins: the sheet once decoded each token to an NSString,
 * which fails on an invalid byte, and the nil dropped the token. sudo cp
 * $'x\xff' /etc/y then showed "cp /etc/y" on the sheet while the terminal's
 * execute: line showed 'x\xFF'. Every token now shows, its invalid byte as
 * \xHH, exactly as the terminal draws it. */
static void test_format_invalid_utf8_argv(void) {
    char *argv[] = { (char *)"cp", (char *)"x\xff", (char *)"/etc/y", NULL };
    NSString *out = [SudoWhatPromptFormatter formatWithCommandPath:"/bin/cp"
        runasUser:"root" cwd:NULL verifyCode:@"AB12" argv:argv
        style:SWPromptStyleSystemSheet];
    EQ(out,
       @"run a command.\n\nRUN AS\nroot\n\nEXECUTE\n/bin/cp 'x\\xFF' /etc/y\n\n"
       @"Verify Code: AB12\n\nCode must match your terminal.",
       "an argv token with an invalid byte is shown as \\xHH, not dropped");

    /* Valid sequences decode first; only the byte that fails is escaped. */
    char *mixed[] = { (char *)"echo", (char *)"caf\xc3\xa9\xff", NULL };
    NSString *m = [SudoWhatPromptFormatter formatWithCommandPath:"/bin/echo"
        runasUser:"root" cwd:NULL verifyCode:@"AB12" argv:mixed
        style:SWPromptStyleSystemSheet];
    OK([m containsString:@"EXECUTE\n/bin/echo 'café\\xFF'\n"],
       "a valid sequence before an invalid byte is drawn as itself");

    /* A lone invalid byte is a token of its own, still shown. */
    char *lone[] = { (char *)"rm", (char *)"\xfe", NULL };
    NSString *l = [SudoWhatPromptFormatter formatWithCommandPath:"/bin/rm"
        runasUser:"root" cwd:NULL verifyCode:@"AB12" argv:lone
        style:SWPromptStyleSystemSheet];
    OK([l containsString:@"EXECUTE\n/bin/rm '\\xFE'\n"],
       "a token that is one invalid byte is shown");
}

/* The same for the values that are paths: the program sudo will execve, the
 * directory it runs in, and the target user's name. */
static void test_format_invalid_utf8_paths(void) {
    char *argv[] = { (char *)"tool", (char *)"-v", NULL };
    NSString *out = [SudoWhatPromptFormatter formatWithCommandPath:"/opt/a\xff/tool"
        runasUser:"u\xff" cwd:"/tmp/d\xfe" verifyCode:@"AB12" argv:argv
        style:SWPromptStyleSystemSheet];
    EQ(out,
       @"run a command.\n\nRUN AS\nu\\xFF\n\nDIRECTORY\n/tmp/d\\xFE\n\n"
       @"EXECUTE\n'/opt/a\\xFF/tool' -v\n\n"
       @"Verify Code: AB12\n\nCode must match your terminal.",
       "a program path, directory and user with an invalid byte all show it");
}

/* No path, nothing to show: the formatter returns nil and the plugin refuses,
 * rather than raising a sheet without a command. */
static void test_format_null_path(void) {
    char *argv[] = { (char *)"x", NULL };
    OK([SudoWhatPromptFormatter formatWithCommandPath:NULL runasUser:"root"
            cwd:NULL verifyCode:@"AB12" argv:argv
            style:SWPromptStyleSystemSheet] == nil,
       "a NULL path -> nil");
    OK(fmt(@"/bin/echo", @"root", nil, @"AB12", @[], SWPromptStyleSystemSheet) != nil,
       "an empty argv is a path-only command, not a failure");
    NSString *noArgv = [SudoWhatPromptFormatter formatWithCommandPath:"/bin/echo"
        runasUser:NULL cwd:NULL verifyCode:@"AB12" argv:NULL
        style:SWPromptStyleSystemSheet];
    OK([noArgv containsString:@"RUN AS\nroot\n"]
       && [noArgv containsString:@"EXECUTE\n/bin/echo\n"],
       "a NULL argv is path-only and a NULL user shows root");
}

int main(void) {
    @autoreleasepool {
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

        test_wastruncated_flag();

        test_format_invalid_utf8_argv();
        test_format_invalid_utf8_paths();
        test_format_null_path();

        SW_SUMMARY("PromptFormatter");
    }
}
