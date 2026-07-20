/*
 * Cross-language equivalence guard: the Rust escape_core C-ABI functions vs the
 * ObjC SudoWhatPromptFormatter, run against the SAME vectors and asserted
 * byte-identical. This is the divergence guard the two-language split requires —
 * the audit plugin renders untrusted argv in Rust, the biometric sheet in ObjC,
 * and they must agree on every byte or a command could read differently in the
 * two places.
 *
 * Vectors are valid Unicode only (a lone surrogate cannot cross a UTF-8 C
 * string, so it is out of scope here; the ObjC-only surrogate passthrough is
 * covered in test_prompt_formatter.m). Invalid-UTF-8 handling deliberately
 * differs (Rust: U+FFFD; ObjC: drops the token) and is likewise not compared.
 */
#import "PromptFormatter.h"
#import "sw_test.h"
#include "escape_core.h"
#include <stdlib.h>
#include <string.h>

/* ---- ObjC side ---- */
static NSString *esc(NSString *s) { return [SudoWhatPromptFormatter escapeControlChars:s]; }
static NSString *q(NSString *s)   { return [SudoWhatPromptFormatter quoteToken:s]; }
static NSString *fullcmd(NSString *path, NSArray *argv) {
    return [SudoWhatPromptFormatter fullCommandLineForCommandPath:path argv:argv];
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

static NSString *rustFullCmd(NSString *path, NSArray<NSString *> *argv) {
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

/* unichar -> length-1 NSString (reliable for NUL and other controls). */
static NSString *uni(unichar c) { return [NSString stringWithCharacters:&c length:1]; }
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
        @"\\", @"\\n", @"back\\slash",
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

    /* C1 / separators / ellipsis / bidi / zero-width, standalone and embedded */
    unichar special[] = {
        0x80, 0x85, 0x9f, 0x2028, 0x2029,
        0x2026, 0x22ef, 0x2024, 0x2025,
        0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
        0x200e, 0x200f, 0x061c,
        0x200b, 0x200c, 0x200d, 0x2060, 0xfeff,
    };
    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); i++) {
        [v addObject:uni(special[i])];
        [v addObject:cat(cat(@"x", uni(special[i])), @"y")];
    }

    /* combining mark, RLO attack token, ellipsis in text */
    [v addObject:cat(@"e", uni(0x0301))];
    [v addObject:cat(@"/etc/", cat(uni(0x202e), @"fdp.ssm"))];
    [v addObject:cat(cat(@"x", uni(0x2026)), @"y")];
    return v;
}

static void test_escape_equivalence(void) {
    for (NSString *vec in escapeVectors()) {
        EQ(rustEscape(vec), esc(vec), "escape byte-identical (Rust == ObjC)");
    }
}

static void test_quote_equivalence(void) {
    for (NSString *vec in escapeVectors()) {
        EQ(rustQuote(vec), q(vec), "quote byte-identical (Rust == ObjC)");
    }
}

static void test_fullcmd_equivalence(void) {
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
    ];
    for (NSArray *c in cases) {
        NSString *path = c[0];
        NSArray *argv = c[1];
        EQ(rustFullCmd(path, argv), fullcmd(path, argv),
           "full command byte-identical (Rust == ObjC)");
    }

    /* control char in an argv token: the escape must match too */
    NSString *evilArg = cat(cat(@"a", uni(0x0a)), uni(0x1b));
    EQ(rustFullCmd(@"/bin/echo", @[@"echo", evilArg]),
       fullcmd(@"/bin/echo", @[@"echo", evilArg]),
       "full command with control chars byte-identical");

    /* unicode path + argv */
    EQ(rustFullCmd(@"/usr/bin/日本", @[@"日本", @"café"]),
       fullcmd(@"/usr/bin/日本", @[@"日本", @"café"]),
       "full command with unicode byte-identical");
}

/* A couple of explicit sanity checks so a totally broken Rust build fails
 * loudly, not just silently matching a broken ObjC side. */
static void test_explicit_values(void) {
    EQ(rustEscape(uni(0x0a)), @"\\n", "rust escapes newline to \\n");
    EQ(rustEscape(@"..."), @"\\u002e\\u002e\\u002e", "rust escapes 3-dot run");
    EQ(rustQuote(@"a b"), @"'a b'", "rust quotes a spaced token");
    EQ(rustFullCmd(@"/bin/echo", @[@"echo", @"a b"]), @"/bin/echo 'a b'",
       "rust full command quotes + dedups");
}

int main(void) {
    @autoreleasepool {
        test_explicit_values();
        test_escape_equivalence();
        test_quote_equivalence();
        test_fullcmd_equivalence();
        SW_SUMMARY("escape_core equivalence (Rust C-ABI == ObjC PromptFormatter)");
    }
}
