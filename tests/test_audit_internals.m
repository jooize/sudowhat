/*
 * Adversarial unit tests for the static helpers inside sudowhat_audit.m:
 *   - sw_audit_color_allowed()     : the NO_COLOR / TERM gate on ANSI emphasis.
 *   - sw_audit_command_line()      : the as-typed command line, plain and
 *                                    highlighted by role.
 *   - sw_audit_command_line_with() : the colour -> plain fail-soft fallback,
 *                                    reachable here through its renderer
 *                                    parameters.
 *
 * A SEPARATE binary from test_plugin_internals: that one #includes
 * plugin/sudowhat_approval.m, and the two plugins cannot share a translation
 * unit -- each defines its own file-static find_kv (a redefinition), and each
 * needs a DIFFERENT -DSW_SIGVERIFIER_CLASS (the header's #error enforces one per
 * target). So the audit shell gets its own test executable, compiled with the
 * audit bundle's class name and linked against the Rust escape_core staticlib
 * the colouriser lives in.
 *
 * Colour here is emphasis, never a trust signal -- the anchor stays the verify
 * code matching the system-rendered sheet -- so these tests pin bytes, the gate
 * logic, and above all the round-trip invariant: strip the SGR and the coloured
 * line is the plain line, byte for byte.
 */
#import "sw_test.h"
#include <stdarg.h>
#include "../plugin/sudowhat_audit.m"

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

static void test_color_allowed(void) {
    char *normal[] = { (char *)"TERM=xterm-256color", (char *)"HOME=/x", NULL };
    OK(sw_audit_color_allowed(normal), "color allowed for a normal TERM");

    char *noColor[] = { (char *)"NO_COLOR=", (char *)"TERM=xterm-256color", NULL };
    OK(!sw_audit_color_allowed(noColor), "NO_COLOR at any value disables color");

    char *noColor1[] = { (char *)"NO_COLOR=1", (char *)"TERM=xterm", NULL };
    OK(!sw_audit_color_allowed(noColor1), "NO_COLOR=1 disables color");

    char *dumb[] = { (char *)"TERM=dumb", NULL };
    OK(!sw_audit_color_allowed(dumb), "TERM=dumb disables color");

    char *empty[] = { (char *)"TERM=", NULL };
    OK(!sw_audit_color_allowed(empty), "empty TERM disables color");

    char *none[] = { (char *)"HOME=/x", NULL };
    OK(!sw_audit_color_allowed(none), "absent TERM disables color");

    OK(!sw_audit_color_allowed(NULL), "NULL envp disables color");
}

static void test_color_mode_default(void) {
    /* The test binary is compiled with no -DSW_AUDIT_ECHO_COLOR, so it sees the
     * header default: anomaly colouring on. */
    OK(sw_audit_color_mode == SW_ACOL_anomalies,
       "default build resolves echoColor to anomalies");
}

static void test_command_line_plain(void) {
    /* submit_argv as sudo hands it over: everything from submit_optind on is the
     * command as typed. argv[0] doubles as the path, so the dedup collapses it. */
    char *argv[] = { (char *)"sudo", (char *)"/bin/echo", (char *)"a b", NULL };
    EQ(sw_audit_command_line(argv, 1, NO), @"/bin/echo 'a b'",
       "plain line is quoted and dedupped");
    OK([sw_audit_command_line(argv, 1, NO) rangeOfString:@"\033"].location == NSNotFound,
       "plain line carries no escape byte");
}

static void test_command_line_colored(void) {
    char *argv[] = { (char *)"sudo", (char *)"/bin/echo", (char *)"--flag",
                     (char *)"value", NULL };
    NSString *plain = sw_audit_command_line(argv, 1, NO);
    NSString *color = sw_audit_command_line(argv, 1, YES);

    EQ(plain, @"/bin/echo --flag value", "plain line");
    EQ(color, @"\033[36m/bin/\033[0m\033[1;36mecho\033[0m "
              @"\033[2m--flag\033[0m value",
       "coloured line: dirname plain cyan, basename bold cyan, flag dim");
    EQ(stripSGR(color), plain, "stripping the SGR returns the plain line exactly");

    /* One logical line: never split, never elided, whatever the length. */
    OK([color rangeOfString:@"\n"].location == NSNotFound,
       "coloured line contains no newline");
    OK([color rangeOfString:@"…"].location == NSNotFound,
       "coloured line contains no elision marker");

    /* A hostile token spelled like one of our own display lines lands quoted and
     * coloured as data, so it cannot pass for a real sudowhat line. */
    char *evil[] = { (char *)"sudo", (char *)"/bin/echo",
                     (char *)"sudowhat: user: evil", NULL };
    NSString *e = sw_audit_command_line(evil, 1, YES);
    EQ(stripSGR(e), @"/bin/echo 'sudowhat: user: evil'",
       "hostile token stays quoted under colour");
    OK([e hasSuffix:@"\033[1;36m'\033[0m"], "its closing quote is coloured");
}

static void test_command_line_nothing_to_show(void) {
    char *argv[] = { (char *)"sudo", NULL };
    OK(sw_audit_command_line(argv, 1, YES) == nil, "no command word -> nil");
    OK(sw_audit_command_line(NULL, 0, YES) == nil, "NULL argv -> nil");
    OK(sw_audit_command_line(argv, -1, YES) == nil, "negative optind -> nil");
}

/* Renderer stubs for the fail-soft path. They match sw_cmdline_fn exactly, so
 * sw_audit_command_line_with can be driven through each branch without touching
 * production behaviour. */
static int sw_stub_fail(const uint8_t *path, size_t path_len,
                        const uint8_t *const *argv, const size_t *argv_lens,
                        size_t argv_count, uint8_t *out, size_t out_cap,
                        size_t *needed) {
    (void)path; (void)path_len; (void)argv; (void)argv_lens; (void)argv_count;
    (void)out; (void)out_cap;
    /* Report a size so the caller allocates, then fail the real call -- the
     * shape of an allocation / truncation failure inside the core. */
    if (needed != NULL) *needed = 8;
    return SW_ESCAPE_TRUNCATED;
}

static int sw_stub_marker(const uint8_t *path, size_t path_len,
                          const uint8_t *const *argv, const size_t *argv_lens,
                          size_t argv_count, uint8_t *out, size_t out_cap,
                          size_t *needed) {
    (void)path; (void)path_len; (void)argv; (void)argv_lens; (void)argv_count;
    static const char m[] = "MARKER";
    size_t n = sizeof(m) - 1;
    if (needed != NULL) *needed = n;
    if (out == NULL || out_cap < n + 1) return SW_ESCAPE_TRUNCATED;
    memcpy(out, m, n);
    out[n] = '\0';
    return SW_ESCAPE_OK;
}

static void test_fail_soft_fallback(void) {
    char *argv[] = { (char *)"sudo", (char *)"/bin/echo", (char *)"hi", NULL };

    /* (a) The colouriser fails -> the plain line, never nothing. This is the
     * whole fail-soft contract: a disclosure tool degrades its emphasis, it does
     * not degrade its disclosure. */
    EQ(sw_audit_command_line_with(sw_stub_fail, sw_full_command_line, argv, 1, YES),
       @"/bin/echo hi",
       "colouriser failure falls back to the plain line");

    /* (b) Colour is on -> the coloured renderer is the one used. */
    EQ(sw_audit_command_line_with(sw_stub_marker, sw_full_command_line, argv, 1, YES),
       @"MARKER", "colour on -> the coloured renderer runs");

    /* (c) Colour is off -> the coloured renderer is never called, so NO_COLOR /
     * TERM=dumb / echoColor=off really do reach the bytes. */
    EQ(sw_audit_command_line_with(sw_stub_marker, sw_full_command_line, argv, 1, NO),
       @"/bin/echo hi", "colour off -> the coloured renderer is not called");

    /* (d) Both renderers fail -> nil, and open() then displays nothing rather
     * than a half-built line. */
    OK(sw_audit_command_line_with(sw_stub_fail, sw_stub_fail, argv, 1, YES) == nil,
       "both renderers failing -> nil");
}

int main(void) {
    @autoreleasepool {
        test_color_allowed();
        test_color_mode_default();
        test_command_line_plain();
        test_command_line_colored();
        test_command_line_nothing_to_show();
        test_fail_soft_fallback();
        SW_SUMMARY("audit plugin internals (colour gate, command line, fail-soft)");
    }
}
