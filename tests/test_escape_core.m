/*
 * Cross-surface guard: the Touch ID sheet and the terminal show one command one
 * way. The approval plugin draws the terminal's execute: line with
 * sw_full_command_line (and its coloured twins), and PromptFormatter lays the
 * sheet's EXECUTE value out from the same function over the same raw bytes.
 * These tests hold that: for every vector, the sheet's EXECUTE value is the
 * terminal's plain line byte for byte, invalid UTF-8 included (a byte that
 * does not decode shows as \xHH on both, and is never dropped).
 *
 * Vectors carry no NUL: sudo's argv is C strings, so a NUL cannot reach either
 * surface. The escape rules themselves are pinned in escape_core's Rust test
 * module.
 *
 * The colouriser (sw_full_command_line_colored and its dim variant
 * sw_full_command_line_colored_dim) is guarded here too, against the same
 * reference: strip the SGR of either and the bytes must equal the plain line
 * and the sheet's command. Colour is layout over those bytes, never content.
 */
#import "PromptFormatter.h"
#import "sw_test.h"
#include "escape_core.h"
#include <stdlib.h>
#include <string.h>

/* ---- the sheet (PromptFormatter over raw bytes) ---- */

/* data plus a NUL, so .bytes is a C string. */
static NSData *cstr(NSData *d) {
    NSMutableData *m = [d mutableCopy];
    [m appendBytes:"" length:1];
    return m;
}

/* The sheet's EXECUTE value for these bytes: the line after the label. nil
 * when the formatter refused or the value went to the terminal. */
static NSString *sheetCmdBytes(NSData *path, NSArray<NSData *> *argv) {
    NSData *pc = cstr(path);
    NSUInteger n = argv.count;
    NSMutableArray<NSData *> *hold = [NSMutableArray array];  /* keep bytes alive */
    char *a[n + 1];
    for (NSUInteger i = 0; i < n; i++) {
        NSData *d = cstr(argv[i]);
        [hold addObject:d];
        a[i] = (char *)d.bytes;
    }
    a[n] = NULL;
    NSString *sheet = [SudoWhatPromptFormatter formatWithCommandPath:pc.bytes
                                                           runasUser:"root"
                                                                 cwd:NULL
                                                          verifyCode:@"AB12"
                                                                argv:a
                                                               style:SWPromptStyleSystemSheet];
    NSRange label = [sheet rangeOfString:@"\n\nEXECUTE\n"];
    if (label.location == NSNotFound) return nil;
    NSUInteger from = NSMaxRange(label);
    NSRange end = [sheet rangeOfString:@"\n" options:0
                                 range:NSMakeRange(from, sheet.length - from)];
    if (end.location == NSNotFound) return nil;
    NSString *v = [sheet substringWithRange:NSMakeRange(from, end.location - from)];
    return [v isEqualToString:@"(see terminal)"] ? nil : v;
}

static NSData *utf8(NSString *s) { return [s dataUsingEncoding:NSUTF8StringEncoding]; }

static NSString *sheetCmd(NSString *path, NSArray<NSString *> *argv) {
    NSMutableArray<NSData *> *a = [NSMutableArray array];
    for (NSString *t in argv) [a addObject:utf8(t)];
    return sheetCmdBytes(utf8(path), a);
}

/* ---- Rust side (via the C ABI, two-call sizing) ---- */
static NSString *bytesToStr(const uint8_t *buf, size_t n) {
    return [[NSString alloc] initWithBytes:buf length:n encoding:NSUTF8StringEncoding];
}

static NSString *rustEscape(NSString *s) {
    NSData *in = [s dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *ip = in.bytes;
    size_t il = in.length, needed = 0;
    sw_escape_control(ip, il, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    if (!buf) return nil;
    size_t got = 0;
    NSString *out = (sw_escape_control(ip, il, buf, needed + 1, &got) == SW_ESCAPE_OK)
        ? bytesToStr(buf, got) : nil;
    free(buf);
    return out;
}

static NSString *rustQuote(NSString *s) {
    NSData *in = [s dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *ip = in.bytes;
    size_t il = in.length, needed = 0;
    sw_quote_token(ip, il, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    if (!buf) return nil;
    size_t got = 0;
    NSString *out = (sw_quote_token(ip, il, buf, needed + 1, &got) == SW_ESCAPE_OK)
        ? bytesToStr(buf, got) : nil;
    free(buf);
    return out;
}

static NSString *rustFullCmdBytes(NSData *pd, NSArray<NSData *> *argv) {
    NSUInteger n = argv.count;
    const uint8_t **ap = calloc(n ? n : 1, sizeof(*ap));
    size_t *al = calloc(n ? n : 1, sizeof(*al));
    for (NSUInteger i = 0; i < n; i++) {
        ap[i] = argv[i].bytes;
        al[i] = argv[i].length;
    }
    size_t needed = 0;
    sw_full_command_line(pd.bytes, pd.length, ap, al, n, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    size_t got = 0;
    NSString *out = nil;
    if (buf && sw_full_command_line(pd.bytes, pd.length, ap, al, n,
                                    buf, needed + 1, &got) == SW_ESCAPE_OK) {
        out = bytesToStr(buf, got);
    }
    free(buf);
    free(ap);
    free(al);
    return out;
}

static NSString *rustFullCmd(NSString *path, NSArray<NSString *> *argv) {
    NSMutableArray<NSData *> *a = [NSMutableArray array];
    for (NSString *t in argv) [a addObject:[t dataUsingEncoding:NSUTF8StringEncoding]];
    return rustFullCmdBytes([path dataUsingEncoding:NSUTF8StringEncoding], a);
}

static NSString *rustColoredCmd(NSString *path, NSArray<NSString *> *argv) {
    NSData *pd = [path dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger n = argv.count;
    const uint8_t **ap = calloc(n ? n : 1, sizeof(*ap));
    size_t *al = calloc(n ? n : 1, sizeof(*al));
    NSMutableArray<NSData *> *hold = [NSMutableArray array];  /* keep bytes alive */
    for (NSUInteger i = 0; i < n; i++) {
        NSData *d = [argv[i] dataUsingEncoding:NSUTF8StringEncoding];
        [hold addObject:d];
        ap[i] = d.bytes;
        al[i] = d.length;
    }
    size_t needed = 0;
    sw_full_command_line_colored(pd.bytes, pd.length, ap, al, n, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    size_t got = 0;
    NSString *out = nil;
    if (buf && sw_full_command_line_colored(pd.bytes, pd.length, ap, al, n,
                                            buf, needed + 1, &got) == SW_ESCAPE_OK) {
        out = bytesToStr(buf, got);
    }
    free(buf);
    free(ap);
    free(al);
    return out;
}

/* The DIM variant of the same renderer -- the audit plugin's input: line. Same
 * walk, same tokens, a flat dim base under the routine roles. */
static NSString *rustColoredDimCmd(NSString *path, NSArray<NSString *> *argv) {
    NSData *pd = [path dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger n = argv.count;
    const uint8_t **ap = calloc(n ? n : 1, sizeof(*ap));
    size_t *al = calloc(n ? n : 1, sizeof(*al));
    NSMutableArray<NSData *> *hold = [NSMutableArray array];  /* keep bytes alive */
    for (NSUInteger i = 0; i < n; i++) {
        NSData *d = [argv[i] dataUsingEncoding:NSUTF8StringEncoding];
        [hold addObject:d];
        ap[i] = d.bytes;
        al[i] = d.length;
    }
    size_t needed = 0;
    sw_full_command_line_colored_dim(pd.bytes, pd.length, ap, al, n, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    size_t got = 0;
    NSString *out = nil;
    if (buf && sw_full_command_line_colored_dim(pd.bytes, pd.length, ap, al, n,
                                                buf, needed + 1, &got) == SW_ESCAPE_OK) {
        out = bytesToStr(buf, got);
    }
    free(buf);
    free(ap);
    free(al);
    return out;
}

/* Drop every SGR sequence, leaving the bytes the terminal actually shows.
 * Deliberately dumb (ESC '[' ... 'm'): the colouriser emits nothing else, and a
 * stricter parser would hide a regression that emitted something else. */
static NSString *stripSGR(NSString *s) {
    if (s == nil) return nil;
    NSMutableString *o = [NSMutableString stringWithCapacity:s.length];
    NSUInteger len = s.length, i = 0;
    while (i < len) {
        unichar c = [s characterAtIndex:i];
        if (c == 0x1b) {
            i++;
            while (i < len && [s characterAtIndex:i] != 'm') i++;
            i++;                                   /* consume the 'm' */
            continue;
        }
        [o appendFormat:@"%C", c];
        i++;
    }
    return o;
}

/* unichar -> length-1 NSString (reliable for NUL and other controls). */
static NSString *uni(unichar c) { return [NSString stringWithCharacters:&c length:1]; }
/* An astral code point as its surrogate pair. */
static NSString *astral(UTF32Char u) {
    UniChar pair[2];
    CFStringGetSurrogatePairForLongCharacter(u, pair);
    return [NSString stringWithCharacters:pair length:2];
}
/* The escape the display shows for a code point, built here rather than typed
 * as a literal: U(@"202E") is a backslash, "u{", the hex, "}". H() is the same
 * escape in the reserved reverse red. */
static NSString *U(NSString *hex) {
    return [NSString stringWithFormat:@"%Cu{%@}", (unichar)'\\', hex];
}
static NSString *H(NSString *hex) {
    return [NSString stringWithFormat:@"\033[7;31m%@\033[0m", U(hex)];
}
static NSString *cat(NSString *a, NSString *b) {
    return [a stringByAppendingString:b];
}

/* The vectors both escaping and quoting are checked against. Every escape
 * category, the quoting triggers, and Unicode passthrough. */
static NSArray<NSString *> *escapeVectors(void) {
    NSMutableArray<NSString *> *v = [NSMutableArray array];
    NSArray *fixed = @[
        @"", @"abcXYZ012", @"a b c", @"+_/.:=@%,-", @"/bin/echo", @"hello world",
        @"a'b", @"can't", @"'", @"$HOME", @"a;b", @"#x", @"a&b", @"a|b", @"a>b",
        @"weird\"`$", @"  lead and  double  ",
        @"\\", @"\\n", @"back\\slash", @"C:\\Users", @"\\u41", @"\\xg", @"\\x",
        @"\\u{41}", @"\\x41", @"\\xff", @"\\\\u{41}", @"a\\u{", @"\\'",
        @".", @"..", @"...", @"....", @"a...b", @"a..b", @"a.b.c", @".....b",
        @"..a..", @"/tmp/../etc",
        @"😀", @"日本語", @"café", @"emoji 😀 in text",
    ];
    [v addObjectsFromArray:fixed];

    /* control chars */
    for (unichar c = 0x00; c < 0x20; c++) [v addObject:uni(c)];
    [v addObject:uni(0x7f)];
    [v addObject:uni(0x1b)];

    /* control chars embedded in text */
    [v addObject:cat(cat(@"a", uni(0x0a)), @"b")];
    [v addObject:cat(cat(@"a", uni(0x1b)), @"b")];

    /* The hidden list's ranges and points, their neighbours just outside,
     * and lookalikes that are drawn as themselves; standalone and embedded. */
    unichar special[] = {
        0x80, 0x85, 0x9f, 0xa0, 0xa1, 0xad, 0x34e, 0x34f, 0x350, 0x61c,
        0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180e,
        0x2000, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2010,
        0x2027, 0x2028, 0x2029, 0x202a, 0x202e, 0x202f, 0x2030,
        0x205e, 0x205f, 0x2060, 0x2066, 0x2069, 0x206f, 0x2070,
        0x2026, 0x22ef, 0x2024, 0x2025,
        0x3000, 0x3164, 0xfe00, 0xfe0f, 0xfe10, 0xfeff, 0xffa0,
        0xfff9, 0xfffb, 0xfffc,
    };
    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); i++) {
        [v addObject:uni(special[i])];
        [v addObject:cat(cat(@"x", uni(special[i])), @"y")];
    }

    /* tag characters and variation selectors past the BMP, and an emoji */
    UTF32Char astrals[] = { 0xe0000, 0xe0041, 0xe007f, 0xe0080, 0xe0100, 0xe01ef,
                            0xe01f0, 0x1f600 };
    for (size_t i = 0; i < sizeof(astrals) / sizeof(astrals[0]); i++) {
        [v addObject:astral(astrals[i])];
        [v addObject:cat(cat(@"x", astral(astrals[i])), @"y")];
    }

    /* combining mark, RLO attack token, ellipsis in text */
    [v addObject:cat(@"e", uni(0x0301))];
    [v addObject:cat(@"/etc/", cat(uni(0x202e), @"fdp.ssm"))];
    [v addObject:cat(cat(@"x", uni(0x2026)), @"y")];
    return v;
}

/* Every vector as an argument and inside the program path: the sheet's
 * EXECUTE value is the terminal's plain line. */
static void test_sheet_equals_terminal_vectors(void) {
    for (NSString *vec in escapeVectors()) {
        if ([vec rangeOfString:uni(0x00)].location != NSNotFound) continue;
        EQ(sheetCmd(@"/bin/echo", @[@"echo", vec]),
           rustFullCmd(@"/bin/echo", @[@"echo", vec]),
           "an argument reads the same on the sheet and the terminal");
        NSString *path = cat(@"/opt/", vec);
        EQ(sheetCmd(path, @[@"prog"]), rustFullCmd(path, @[@"prog"]),
           "a program path reads the same on the sheet and the terminal");
    }
}

static void test_sheet_equals_terminal_cases(void) {
    NSArray *cases = @[
        @[@"/bin/echo", @[@"echo", @"hello"]],
        @[@"/bin/echo", @[@"/bin/echo", @"hi"]],
        @[@"/bin/echo", @[@"notecho", @"hi"]],
        @[@"/bin/echo", @[]],
        @[@"/bin/echo", @[@"echo", @"a b"]],
        @[@"/usr/bin/git", @[@"git", @"status"]],
        @[@"id", @[@"id"]],
        @[@"echo", @[@"echo"]],
        @[@"/bin/echo", @[@"echo", @"a'b"]],
        @[@"/bin/echo", @[@"echo", @"$HOME", @"a;b"]],
        @[@"/usr/bin/日本", @[@"日本", @"café"]],
    ];
    for (NSArray *c in cases) {
        NSString *path = c[0];
        NSArray *argv = c[1];
        EQ(sheetCmd(path, argv), rustFullCmd(path, argv),
           "the sheet's command is the terminal's line (dedup, quoting)");
    }
}

/* Bytes that are not valid UTF-8, the case an NSString cannot hold. The sheet
 * once decoded each token to an NSString and dropped the ones that failed;
 * both surfaces now show every token, each failing byte as \xHH. */
static void test_sheet_equals_terminal_invalid_utf8(void) {
    const char *cp = "cp", *bad = "x\xff", *dst = "/etc/y";
    NSArray<NSData *> *argv = @[
        [NSData dataWithBytes:cp length:strlen(cp)],
        [NSData dataWithBytes:bad length:strlen(bad)],
        [NSData dataWithBytes:dst length:strlen(dst)],
    ];
    NSData *path = utf8(@"/bin/cp");
    EQ(sheetCmdBytes(path, argv), @"/bin/cp 'x\\xFF' /etc/y",
       "sudo cp $'x\\xff' /etc/y: the sheet shows the token as 'x\\xFF'");
    EQ(sheetCmdBytes(path, argv), rustFullCmdBytes(path, argv),
       "and the terminal's line is the same bytes");

    const uint8_t badPath[] = { '/', 'o', 'p', 't', '/', 'a', 0xFF, '/', 't' };
    NSData *bp = [NSData dataWithBytes:badPath length:sizeof badPath];
    NSArray<NSData *> *targv = @[ utf8(@"t"), utf8(@"-v") ];
    EQ(sheetCmdBytes(bp, targv), @"'/opt/a\\xFF/t' -v",
       "a program path with an invalid byte shows it as \\xFF");
    EQ(sheetCmdBytes(bp, targv), rustFullCmdBytes(bp, targv),
       "and reads the same on the terminal");

    /* Every lone byte that is not valid UTF-8 on its own, inside a token. */
    for (unsigned b = 0x80; b <= 0xFF; b++) {
        uint8_t tok[] = { 'a', (uint8_t)b, 'z' };
        NSArray<NSData *> *av = @[ utf8(@"echo"), [NSData dataWithBytes:tok length:3] ];
        NSData *ep = utf8(@"/bin/echo");
        EQ(sheetCmdBytes(ep, av), rustFullCmdBytes(ep, av),
           "a byte that does not decode reads the same on both surfaces");
    }
}

/* The coloured command line is the SAME line with SGR layered on: strip the
 * colour and the bytes must equal the plain line and the sheet's command. That
 * is the invariant the whole design rests on --
 * colour is layout, never content, so no highlight can add, hide, or reorder a
 * byte of the command the user is about to authorize. */
static void test_colored_preserves_bytes(void) {
    NSArray *cases = @[
        @[@"/bin/echo", @[@"echo", @"hello"]],
        @[@"/bin/echo", @[]],
        @[@"id", @[@"id"]],
        @[@"/usr/bin/git", @[@"git", @"status", @"--porcelain"]],
        @[@"/run/current-system/sw/bin/pinned",
          @[@"pinned", @"review", @"--file", @"/Library/App Support/x.json"]],
        @[@"/bin/echo", @[@"echo", @"a b", @"a'b", @"-", @"--", @"-x"]],
        @[@"/bin/echo", @[@"echo", @"sudowhat: run as: evil"]],
        @[@"/bin/echo", @[@"echo", @"...", @"  padded  ", @""]],
        @[@"/usr/bin/日本", @[@"日本", @"café", @"😀"]],
        @[@"/a b/prog name", @[@"prog name"]],
    ];
    for (NSArray *c in cases) {
        NSString *path = c[0];
        NSArray *argv = c[1];
        EQ(stripSGR(rustColoredCmd(path, argv)), sheetCmd(path, argv),
           "coloured command strips back to the sheet's command");
        EQ(stripSGR(rustColoredCmd(path, argv)), rustFullCmd(path, argv),
           "coloured command strips back to the Rust plain line");
        /* The dim variant (input:) is the same walk under a different base, so
         * it owes the same round trip against the same plain line. */
        EQ(stripSGR(rustColoredDimCmd(path, argv)), rustFullCmd(path, argv),
           "dim command strips back to the plain line");
        EQ(stripSGR(rustColoredDimCmd(path, argv)), stripSGR(rustColoredCmd(path, argv)),
           "input: and execute: show the same bytes, differing only in emphasis");
    }

    /* control chars, bidi override and a literal backslash: the escapes must
     * survive the colouriser byte for byte, wrapped but never rewritten. */
    NSString *evil = cat(cat(@"a", uni(0x0a)), cat(uni(0x202e), @"b\\c"));
    EQ(stripSGR(rustColoredCmd(@"/bin/echo", @[@"echo", evil])),
       rustFullCmd(@"/bin/echo", @[@"echo", evil]),
       "coloured command with escapes strips back to the plain line");
}

/* Role assignment on the execute: variant, pinned to exact bytes: the first
 * segment of the program's directory bold cyan, the rest of it plain, the
 * basename bold blue, option flags bold blue,
 * every other token unstyled. The flag mark is openly lexical -- it colours
 * every flag alike rather than guessing which one matters, and a token that
 * needed quoting renders '...' and so never borrows the look. */
static void test_colored_roles(void) {
    EQ(rustColoredCmd(@"/bin/echo", @[@"echo"]),
       @"\033[1;36m/bin\033[0m/\033[1;34mecho\033[0m",
       "first segment bold cyan, the rest plain, basename bold blue");
    EQ(rustColoredCmd(@"id", @[@"id"]), @"\033[1;34mid\033[0m",
       "a bare command word is all basename");
    EQ(rustColoredCmd(@"/bin/git", @[@"git", @"--file", @"x"]),
       @"\033[1;36m/bin\033[0m/\033[1;34mgit\033[0m \033[1;34m--file\033[0m x",
       "flags bold blue, values plain, separators untouched");
    OK([rustColoredCmd(@"/bin/rm", @[@"rm", @"-rf", @"/"]) rangeOfString:@"\033[2m"].location
       == NSNotFound,
       "no dim anywhere on a line that needed no quoting");
    OK([rustColoredCmd(@"/bin/rm", @[@"rm", @"-rf", @"/"]) rangeOfString:@"\033[1;34m-rf\033[0m"].location
       != NSNotFound,
       "a flag is bold blue (lexical: starts with a dash)");
    /* A hostile token that needed quoting renders '...' (leading quote, not
     * dash) -- it must NOT borrow the flag colour. Pinned whole: the only bold
     * blue on the line is the program's basename. */
    EQ(rustColoredCmd(@"/bin/echo", @[@"echo", @"-rf x"]),
       @"\033[1;36m/bin\033[0m/\033[1;34mecho\033[0m \033[2m'\033[0m-rf x\033[2m'\033[0m",
       "a quoted token is never flag-coloured");
}

/* Dim means exactly one thing: these bytes are ours. sudo hands the plugin an
 * argv ARRAY, so every quote on screen is one the renderer added -- except the
 * ones that arrived through the POSIX '\'' idiom, which are the only way a
 * quote the argument really contained can be represented. Those stay lit. The
 * exhaustive attribution oracle lives in the Rust test module; this is the
 * cross-language sighting of the same rule. */
static void test_colored_quote_attribution(void) {
    /* a'b -> 'a'\''b' : ours, a, ours, a plain backslash, the DATA's quote,
     * ours, b, ours. */
    EQ(rustColoredCmd(@"p", @[@"p", @"a'b"]),
       @"\033[1;34mp\033[0m \033[2m'\033[0ma\033[2m'\033[0m\\\033[1;36m'\033[0m"
       @"\033[2m'\033[0mb\033[2m'\033[0m",
       "our quotes dim, the argument's own quote lit");

    /* The trap a re-parse gets wrong: \' renders '\'\''' , where the quote
     * right after the first backslash is OUR closing quote, though a
     * backslash precedes it. The colours are composed from the parts, so the
     * attribution is right by construction. */
    NSString *trap = rustColoredCmd(@"p", @[@"p", @"\\'"]);
    EQ(stripSGR(trap), @"p '\\'\\'''", "the backslash-quote token round-trips");
    EQ(trap, @"\033[1;34mp\033[0m \033[2m'\033[0m\\\033[2m'\033[0m\\\033[1;36m'\033[0m"
             @"\033[2m'\033[0m\033[2m'\033[0m",
       "only the data's quote is lit; the quote after the first backslash is ours");

    /* An empty token is entirely chrome: both quotes ours. */
    EQ(rustColoredCmd(@"p", @[@"p", @""]),
       @"\033[1;34mp\033[0m \033[2m'\033[0m\033[2m'\033[0m",
       "the empty token is all chrome, both quotes dim");
}

/* A hostile token spelled like one of our own display lines lands quoted, in
 * our own dim quotes -- it reads as data, not as a real sudowhat line. A
 * hidden code point's escape wears reverse red, the style reserved for it. */
static void test_colored_hostile_and_anomalies(void) {
    NSString *hostile = rustColoredCmd(@"/bin/echo", @[@"echo", @"sudowhat: run as: evil"]);
    OK([hostile containsString:@"\033[2m'\033[0msudowhat:"],
       "hostile token opens with one of our own (dim) quotes");
    OK([hostile hasSuffix:@"\033[2m'\033[0m"],
       "hostile token closes with one of our own (dim) quotes");
    EQ(stripSGR(hostile), @"/bin/echo 'sudowhat: run as: evil'",
       "hostile token is quoted, not structural");

    NSString *nl = rustColoredCmd(@"/bin/echo", @[@"echo", cat(cat(@"a", uni(0x0a)), @"b")]);
    OK([nl containsString:H(@"A")], "a line feed's escape is reverse red");

    NSString *bidi = rustColoredCmd(@"/bin/echo", @[@"echo", cat(uni(0x202e), @"x")]);
    OK([bidi containsString:H(@"202E")], "a bidi override's escape is reverse red");

    /* A kept escape -- a backslash that would begin an escape -- is shown as
     * exactly what it is, with no style of its own. */
    NSString *kept = rustColoredCmd(@"/bin/echo", @[@"echo", @"\\x41"]);
    EQ(kept, ([NSString stringWithFormat:
                  @"\033[1;36m/bin\033[0m/\033[1;34mecho\033[0m \033[2m'\033[0m%@x41\033[2m'\033[0m",
                  U(@"5C")]),
       "a self-escaped backslash is unstyled");

    /* Notable whitespace is marked in the PROGRAM token, where invisible
     * padding changes what execve gets -- and nowhere else. An argument's
     * spaces stay unmarked: those bytes are data, they render escaped and
     * quoted either way, and a script argument would otherwise fill the line
     * with grey indentation blocks after every escaped newline. */
    NSString *progPad = rustColoredCmd(@"/tmp/my  tool", @[]);
    OK([progPad containsString:@"\033[100m  \033[0m"],
       "a doubled space in the program token is grey-backed");
    NSString *argPad = rustColoredCmd(@"/bin/echo", @[@"echo", @"a  b"]);
    OK([argPad rangeOfString:@"\033[100m"].location == NSNotFound,
       "an argument's doubled space carries no grey background");
    EQ(stripSGR(argPad), @"/bin/echo 'a  b'",
       "and the argument still round-trips to the plain line");
}

/* The dim variant, which the audit bundle's input: line uses: the routine roles
 * collapse to one dim base with the basename bold dim, and the anomaly palette
 * above it does not move. The
 * exhaustive per-role table lives in the Rust test module; this is the
 * cross-language sighting that the exported dim entry point is the same walk. */
static void test_colored_dim_variant(void) {
    EQ(rustColoredDimCmd(@"/bin/echo", @[@"echo", @"hello"]),
       @"\033[2m/bin/\033[0m\033[1;2mecho\033[0m \033[2mhello\033[0m",
       "input: renders the directory and value dim, the basename bold dim");
    EQ(rustColoredDimCmd(@"/bin/git", @[@"git", @"--file", @"x"]),
       @"\033[2m/bin/\033[0m\033[1;2mgit\033[0m \033[2m--file\033[0m \033[2mx\033[0m",
       "flags take the dim base too, not their bold blue");

    NSString *nl = rustColoredDimCmd(@"/bin/echo", @[@"echo", cat(cat(@"a", uni(0x0a)), @"b")]);
    OK([nl containsString:H(@"A")],
       "a line feed's escape keeps full-strength reverse red over the dim base");
    NSString *bidi = rustColoredDimCmd(@"/bin/echo", @[@"echo", cat(uni(0x202e), @"x")]);
    OK([bidi containsString:H(@"202E")],
       "a bidi override's escape keeps full-strength reverse red over the dim base");
    NSString *pad = rustColoredDimCmd(@"/tmp/my  tool", @[]);
    OK([pad containsString:@"\033[100m  \033[0m"],
       "a doubled space in the program token keeps its grey background over "
       "the dim base");
    NSString *argPad = rustColoredDimCmd(@"/bin/echo", @[@"echo", @"a  b"]);
    OK([argPad rangeOfString:@"\033[100m"].location == NSNotFound,
       "an argument's doubled space renders dim, with no grey background");
}

/* A couple of explicit sanity checks so a totally broken Rust build fails
 * loudly, not just silently matching itself on both surfaces. */
static void test_explicit_values(void) {
    EQ(rustEscape(uni(0x0a)), U(@"A"), "rust escapes a line feed as its code point");
    EQ(rustEscape(@"\\x41"), [U(@"5C") stringByAppendingString:@"x41"],
       "rust escapes a backslash that would begin an escape");
    EQ(rustEscape(astral(0xe0041)), U(@"E0041"), "rust escapes a tag character");
    EQ(rustEscape(@"..."), @"...", "rust draws a run of dots as itself");
    EQ(rustQuote(@"a b"), @"'a b'", "rust quotes a spaced token");
    EQ(rustFullCmd(@"/bin/echo", @[@"echo", @"a b"]), @"/bin/echo 'a b'",
       "rust full command quotes + dedups");
}

int main(void) {
    @autoreleasepool {
        test_explicit_values();
        test_sheet_equals_terminal_vectors();
        test_sheet_equals_terminal_cases();
        test_sheet_equals_terminal_invalid_utf8();
        test_colored_preserves_bytes();
        test_colored_roles();
        test_colored_quote_attribution();
        test_colored_hostile_and_anomalies();
        test_colored_dim_variant();
        SW_SUMMARY("escape_core cross-surface (Touch ID sheet == terminal line)");
    }
}
