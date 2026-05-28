/*
 * sw_test.h - minimal assertion harness for sudowhat unit tests.
 *
 * No XCTest dependency: each test file is a standalone executable compiled
 * with clang, prints failures to stderr, and exits non-zero if any check
 * failed. Fits the project's Makefile/clang build (no Xcode project).
 *
 * Static counters live per translation unit; each test binary is its own
 * process, so there is no cross-file sharing to worry about.
 */
#ifndef SW_TEST_H
#define SW_TEST_H

#import <Foundation/Foundation.h>
#include <stdio.h>

static int sw_pass = 0;
static int sw_fail = 0;
static int sw_note = 0;

/* Render control / non-ASCII chars visibly so failure output is readable.
 * Marked unused: only the EQ macro references it, so a test file that uses
 * only OK/NOTE would otherwise warn under -Wall. */
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
        else                [o appendFormat:@"%C", c];
    }
    return o;
}

#define OK(cond, name) do {                                                   \
    if (cond) { sw_pass++; }                                                  \
    else { sw_fail++;                                                         \
        fprintf(stderr, "FAIL [%s]  %s:%d\n", (name), __FILE__, __LINE__); }  \
} while (0)

#define EQ(got, want, name) do {                                             \
    NSString *_g = (got); NSString *_w = (want);                             \
    if (_g != nil && [_g isEqualToString:_w]) { sw_pass++; }                 \
    else { sw_fail++;                                                        \
        fprintf(stderr, "FAIL [%s]  %s:%d\n      want: |%s|\n      got:  |%s|\n", \
                (name), __FILE__, __LINE__,                                  \
                sw_vis(_w).UTF8String, sw_vis(_g).UTF8String); }             \
} while (0)

/* NOTE: an informational probe of a latent assumption that is NOT a
 * guaranteed invariant in production (e.g. an input that the caller always
 * bounds). Prints but does not fail the suite. */
#define NOTE(cond, name) do {                                                \
    if (!(cond)) { sw_note++;                                                \
        fprintf(stderr, "NOTE [%s]  %s:%d  (latent, not prod-reachable)\n",  \
                (name), __FILE__, __LINE__); }                              \
} while (0)

#define SW_SUMMARY(suite) do {                                               \
    fprintf(stderr, "\n%s: %d passed, %d failed, %d notes\n",                \
            (suite), sw_pass, sw_fail, sw_note);                             \
    return sw_fail == 0 ? 0 : 1;                                             \
} while (0)

#endif
