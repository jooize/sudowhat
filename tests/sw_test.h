/*
 * sw_test.h - minimal TAP 14 harness for sudowhat unit tests.
 *
 * No XCTest dependency: each test file is a standalone executable compiled
 * with clang, prints one TAP 14 stream on stdout, and exits non-zero if any
 * check failed. Fits the project's Makefile/clang build (no Xcode project).
 * Every OK/EQ/NOTE/SKIP is a numbered test point; failure detail follows its
 * `not ok` as `# ` comment lines; SW_SUMMARY prints the plan and a comment
 * summary. Read a binary's stream with `prove --exec '' build/test_x`.
 *
 * Static counters live per translation unit; each test binary is its own
 * process, so there is no cross-file sharing to worry about.
 */
#ifndef SW_TEST_H
#define SW_TEST_H

#import <Foundation/Foundation.h>
#include <stdio.h>

/* Every test point lands in exactly one bucket, so the four sum to the plan. */
static int sw_n = 0;        /* test points emitted, numbered from 1 */
static int sw_pass = 0;
static int sw_fail = 0;
static int sw_skip = 0;
static int sw_todo = 0;     /* NOTE probes, whether or not they held */
static NSMutableArray<NSString *> *sw_skipped = nil;  /* "name (reason)" */

/* Render control / non-ASCII chars visibly so failure output is readable and
 * the stream stays ASCII. Marked unused: only the EQ macro references it, so a
 * test file that uses only OK/NOTE would otherwise warn under -Wall. */
__attribute__((unused))
static NSString *sw_vis(NSString *s) {
    if (s == nil) return @"(nil)";
    NSMutableString *o = [NSMutableString string];
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '\n')      [o appendString:@"<\\n>"];
        else if (c == '\t') [o appendString:@"<\\t>"];
        else if (c == '\r') [o appendString:@"<\\r>"];
        else if (c < 0x20 || c == 0x7f) [o appendFormat:@"<%02x>", (unsigned)c];
        else if (c < 0x80)  [o appendFormat:@"%C", c];
        else if (CFStringIsSurrogateHighCharacter(c) && i + 1 < s.length &&
                 CFStringIsSurrogateLowCharacter([s characterAtIndex:i + 1])) {
            UTF32Char cp = CFStringGetLongCharacterForSurrogatePair(
                c, [s characterAtIndex:i + 1]);
            i++;
            [o appendFormat:@"<U+%04X>", (unsigned)cp];
        }
        else                [o appendFormat:@"<U+%04X>", (unsigned)c];
    }
    return o;
}

/* "TAP version 14" once, as the first stdout line. stdout is line-buffered
 * from here so a crash mid-run still leaves every point already emitted. */
static void sw_begin(void) {
    static int started = 0;
    if (started) return;
    started = 1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    fputs("TAP version 14\n", stdout);
}

/* Write s on the current line. As a description (desc != 0) `\` -> `\\` and
 * `#` -> `\#`, so it can never start a directive; newlines always collapse to
 * a space, so it can never start a new line. */
static void sw_put(const char *s, int desc) {
    if (s == NULL) s = "(null)";
    for (; *s; s++) {
        if (desc && (*s == '\\' || *s == '#')) { fputc('\\', stdout); fputc(*s, stdout); }
        else if (*s == '\n' || *s == '\r') fputc(' ', stdout);
        else fputc(*s, stdout);
    }
}

/* One test point: `ok N - name` or `not ok N - name`, then ` # directive`
 * when directive is non-NULL ("skip REASON", "todo REASON"). */
static void sw_point(int ok, const char *name, const char *directive) {
    sw_begin();
    sw_n++;
    printf("%sok %d - ", ok ? "" : "not ", sw_n);
    sw_put(name, 1);
    if (directive != NULL) { fputs(" # ", stdout); sw_put(directive, 0); }
    fputc('\n', stdout);
}

#define OK(cond, name) do {                                                   \
    if (cond) { sw_pass++; sw_point(1, (name), NULL); }                      \
    else { sw_fail++; sw_point(0, (name), NULL);                             \
        printf("# at %s:%d\n", __FILE__, __LINE__); }                        \
} while (0)

#define EQ(got, want, name) do {                                             \
    NSString *_g = (got); NSString *_w = (want);                             \
    if (_g != nil && [_g isEqualToString:_w]) {                              \
        sw_pass++; sw_point(1, (name), NULL); }                              \
    else { sw_fail++; sw_point(0, (name), NULL);                             \
        printf("# at %s:%d\n# got:  |%s|\n# want: |%s|\n",                   \
               __FILE__, __LINE__,                                           \
               sw_vis(_g).UTF8String, sw_vis(_w).UTF8String); }              \
} while (0)

/* NOTE: an informational probe of a latent assumption that is NOT a
 * guaranteed invariant in production (e.g. an input that the caller always
 * bounds). A todo point: `not ok` when the probe fails, `ok` when it holds;
 * TAP never counts a todo failure, so it does not fail the suite. */
#define NOTE(cond, name) do {                                                \
    int _c = (cond) ? 1 : 0;                                                 \
    sw_todo++;                                                               \
    sw_point(_c, (name), "todo latent, not prod-reachable");                 \
    if (!_c) printf("# at %s:%d\n", __FILE__, __LINE__);                     \
} while (0)

/* SKIP: a check this environment cannot run. A skip point, named in the
 * summary after the plan so a hand run still says what it left out. */
#define SKIP(name, reason) do {                                              \
    const char *_n = (name); const char *_r = (reason);                      \
    sw_skip++;                                                               \
    sw_point(1, _n, [@"skip " stringByAppendingString:@(_r)].UTF8String);    \
    if (sw_skipped == nil) sw_skipped = [NSMutableArray array];              \
    [sw_skipped addObject:[NSString stringWithFormat:@"%s (%s)", _n, _r]];   \
} while (0)

#define SW_SUMMARY(suite) do {                                               \
    sw_begin();                                                              \
    printf("1..%d\n", sw_n);                                                 \
    printf("# %s: %d passed, %d failed, %d skipped, %d todo\n",              \
           (suite), sw_pass, sw_fail, sw_skip, sw_todo);                     \
    for (NSString *_s in sw_skipped) {                                       \
        fputs("#   skipped: ", stdout); sw_put(_s.UTF8String, 0);            \
        fputc('\n', stdout); }                                               \
    fflush(stdout);                                                          \
    return sw_fail == 0 ? 0 : 1;                                             \
} while (0)

#endif
