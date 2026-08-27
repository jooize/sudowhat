/*
 * Adversarial unit tests for the static helpers inside sudowhat_audit.m:
 *   - sw_audit_color_allowed()     : the NO_COLOR / TERM gate on ANSI emphasis.
 *   - sw_audit_command_line()      : the as-typed command line, plain and in
 *                                    the dim variant the input: line uses.
 *   - sw_audit_command_line_with() : the colour -> plain fail-soft fallback,
 *                                    reachable here through its renderer
 *                                    parameters.
 *   - sw_audit_row()               : the label gutter every row shares.
 *   - sw_audit_color_dir/user()    : the two frame values that carry emphasis.
 *   - sw_audit_is_bare_name()      : the condition gating the path: row.
 *   - sw_audit_path_row_value()    : the caller's PATH as the path: row shows
 *                                    it, or nil when the row must not print.
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
    /* The global CFLAGS pass -DSW_ECHO_COLOR=$(SUDOWHAT_ECHO_COLOR) to both
     * bundles and to this test binary; SUDOWHAT_ECHO_COLOR defaults to
     * on, i.e. anomaly colouring on. This pins the shipped default, so a
     * deliberate `make SUDOWHAT_ECHO_COLOR=off` build is expected to fail this
     * line rather than to pass quietly. */
    OK(sw_audit_color_mode == SW_ACOL_on,
       "default build resolves echoColor to on");
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

/* The input: value takes escape_core's DIM variant: every routine token --
 * program dirname, basename, flags, values alike -- renders dim, and only the
 * anomaly spans keep full strength. The resolved execute: line the approval
 * bundle prints keeps the full role palette, so the pre-resolution line reads
 * quiet under the authoritative one. Both come out of one shared walk, so the
 * round-trip invariant is asserted here exactly as before. */
static void test_command_line_colored(void) {
    char *argv[] = { (char *)"sudo", (char *)"/bin/echo", (char *)"--flag",
                     (char *)"value", NULL };
    NSString *plain = sw_audit_command_line(argv, 1, NO);
    NSString *color = sw_audit_command_line(argv, 1, YES);

    EQ(plain, @"/bin/echo --flag value", "plain line");
    EQ(color, @"\033[2m/bin/\033[0m\033[2mecho\033[0m \033[2m--flag\033[0m"
              @" \033[2mvalue\033[0m",
       "input: line renders its routine tokens dim, program and flag included");
    EQ(stripSGR(color), plain, "stripping the SGR returns the plain line exactly");

    /* No ROLE colour survives on this line: not the program's cyan pair, not
     * the flag's bold blue. (Checked on a clean line -- the metachar anomaly
     * colour is 1;36 too, and legitimately appears on a metachar.) */
    OK([color rangeOfString:@"\033[36m"].location == NSNotFound,
       "no role cyan on the input: line");
    OK([color rangeOfString:@"\033[1;36m"].location == NSNotFound,
       "no bold role cyan on the input: line");
    OK([color rangeOfString:@"\033[1;34m"].location == NSNotFound,
       "no flag blue on the input: line");

    /* The anomaly palette is untouched by the dim base -- that is the point of
     * the dim base: against it, the anomalies are the only colour on the row. */
    char *anom[] = { (char *)"sudo", (char *)"/bin/echo",
                     (char *)"a\nb", (char *)"x  y", NULL };
    NSString *a = sw_audit_command_line(anom, 1, YES);
    OK([a rangeOfString:@"\033[1;35m\\n\033[0m"].location != NSNotFound,
       "control escape keeps full-strength magenta over the dim base");
    /* The whitespace mark is scoped to the program token -- the path that will
     * execve -- so an argument's doubled space carries no grey background. */
    OK([a rangeOfString:@"\033[100m"].location == NSNotFound,
       "an argument's doubled space carries no grey background");
    EQ(stripSGR(a), @"/bin/echo 'a\\nb' 'x  y'",
       "the anomaly line still strips back to the plain line");

    /* and the mark does appear where it belongs, at full strength over the
     * dim base: invisible padding inside the program token. */
    char *pad[] = { (char *)"sudo", (char *)"/tmp/my  tool", NULL };
    NSString *p = sw_audit_command_line(pad, 1, YES);
    OK([p rangeOfString:@"\033[100m  \033[0m"].location != NSNotFound,
       "a doubled space in the program token keeps its grey background");
    EQ(stripSGR(p), @"'/tmp/my  tool'",
       "the padded program token still strips back to the plain line");

    /* One logical line: never split, never elided, whatever the length. */
    OK([color rangeOfString:@"\n"].location == NSNotFound,
       "coloured line contains no newline");
    OK([color rangeOfString:@"…"].location == NSNotFound,
       "coloured line contains no elision marker");

    /* A hostile token spelled like one of our own display lines lands quoted and
     * coloured as data, so it cannot pass for a real sudowhat line. */
    char *evil[] = { (char *)"sudo", (char *)"/bin/echo",
                     (char *)"sudowhat: run as: evil", NULL };
    NSString *e = sw_audit_command_line(evil, 1, YES);
    EQ(stripSGR(e), @"/bin/echo 'sudowhat: run as: evil'",
       "hostile token stays quoted under colour");
    OK([e hasSuffix:@"\033[2m'\033[0m"],
       "its closing quote is still its own span -- chrome, dim like the base");
}

static void test_command_line_nothing_to_show(void) {
    char *argv[] = { (char *)"sudo", NULL };
    OK(sw_audit_command_line(argv, 1, YES) == nil, "no command word -> nil");
    OK(sw_audit_command_line(NULL, 0, YES) == nil, "NULL argv -> nil");
    OK(sw_audit_command_line(argv, -1, YES) == nil, "negative optind -> nil");
}

/* The frame: one gutter, up to four rows, and colour that asserts only what the
 * plugin knows. The values all start in the same column, so the block reads as
 * a table; the "sudowhat: " prefix stays on every row because the block lands
 * mid-stream in output we do not own. */
static void test_frame_gutter(void) {
    EQ(sw_audit_row(@"run as:", @"root", NO),
       @"sudowhat: run as:     root\n", "run as: padded to the gutter");
    EQ(sw_audit_row(@"directory:", @"/x", NO),
       @"sudowhat: directory:  /x\n", "the longest label keeps its two spaces");
    EQ(sw_audit_row(@"input:", @"id", NO),
       @"sudowhat: input:      id\n", "input: padded to the gutter");

    EQ(sw_audit_row(@"path:", @"/usr/bin", NO),
       @"sudowhat: path:       /usr/bin\n",
       "path: padded to the gutter (5-char label, 7 spaces of gap)");

    /* Every value lands in the same column -- the whole point of the gutter,
     * and the reason the approval plugin's verify: and execute: lines can join the
     * same table from a different bundle. */
    NSArray<NSString *> *labels = @[ @"run as:", @"directory:", @"input:", @"path:" ];
    for (NSString *l in labels) {
        NSRange v = [sw_audit_row(l, @"VALUE", NO) rangeOfString:@"VALUE"];
        OK(v.location == 22, "value column is identical across rows");
    }

    /* Coloured: only the label wears the bold, and the padding stays plain. */
    EQ(sw_audit_row(@"run as:", @"root", YES),
       @"sudowhat: \033[1mrun as:\033[0m     root\n",
       "colour bolds the label only, never the padding");
    EQ(stripSGR(sw_audit_row(@"run as:", @"root", YES)),
       sw_audit_row(@"run as:", @"root", NO),
       "the coloured row strips back to the plain row");
}

static void test_frame_value_colour(void) {
    /* root is the expected target and earns no emphasis; any other target is
     * the case worth catching an eye, in plain yellow. */
    EQ(sw_audit_color_user(@"root"), @"root", "root renders plain");
    EQ(sw_audit_color_user(@"postgres"), @"\033[33mpostgres\033[0m",
       "a non-root target is attention-yellow");

    /* The cwd takes the program-path split: dirname plain cyan, last component
     * bold cyan. No quoting is added, so the bytes match the plain row. */
    EQ(sw_audit_color_dir(@"/home/alice"),
       @"\033[36m/home/\033[0m\033[1;36malice\033[0m",
       "cwd dirname plain cyan, basename bold cyan");
    EQ(sw_audit_color_dir(@"relative"), @"\033[1;36mrelative\033[0m",
       "no slash at all -> the whole value is the last component");
    EQ(sw_audit_color_dir(@"/"), @"\033[36m/\033[0m",
       "a trailing slash leaves no last component, and no empty span");
    EQ(stripSGR(sw_audit_color_dir(@"/a b/c d")), @"/a b/c d",
       "a spacey cwd gains no quotes: colour is layout, never content");

    /* The frame palette stays clear of escape_core's anomaly colours, so a
     * highlighted directory can never be mistaken for a flagged anomaly. */
    NSArray<NSString *> *reserved = @[ @"\033[1;31m", @"\033[1;35m", @"\033[100m" ];
    NSString *row = sw_audit_row(@"directory:", sw_audit_color_dir(@"/home/alice"), YES);
    for (NSString *r in reserved) {
        OK([row rangeOfString:r].location == NSNotFound,
           "frame row uses no reserved anomaly colour");
    }
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

/* The path: row's gating condition. Only a BARE NAME is resolved through PATH;
 * anything carrying a '/' -- absolute or relative -- is used as given, so the
 * caller's PATH decides nothing there and the row would be noise. */
static void test_is_bare_name(void) {
    OK(sw_audit_is_bare_name("systemctl"), "a bare name is a bare name");
    OK(!sw_audit_is_bare_name("/bin/echo"), "an absolute path is not");
    OK(!sw_audit_is_bare_name("./x"), "a dot-slash relative path is not");
    OK(!sw_audit_is_bare_name("a/b"), "any relative path with a slash is not");
    OK(!sw_audit_is_bare_name(""), "the empty string is not");
    OK(!sw_audit_is_bare_name(NULL), "NULL is not");
}

/* The path: row's value: the caller's PATH exactly as handed to sudo, escaped
 * through the same core as run as: and directory:, and nil in every case where
 * the row must not print. The row NEVER resolves anything -- it shows the
 * string, it does not walk it -- so there is nothing here that could claim
 * which entry would win; that answer belongs to the execute: line. */
static void test_path_row_value(void) {
    char *env[] = { (char *)"TERM=xterm", (char *)"PATH=/usr/bin:/bin", NULL };

    char *bare[] = { (char *)"sudo", (char *)"systemctl", (char *)"restart",
                     NULL };
    EQ(sw_audit_path_row_value(bare, 1, env), @"/usr/bin:/bin",
       "a bare name with PATH present -> the caller's PATH");

    /* The row is plain text, not a rendered token walk: no quoting is added and
     * no role colour is spent, so what the reader sees is the env string. */
    OK([sw_audit_path_row_value(bare, 1, env)
          rangeOfString:@"\033"].location == NSNotFound,
       "the path: value carries no escape byte");

    /* Hostile bytes in PATH reach the terminal as TEXT, never as bytes: a
     * newline cannot forge a second sudowhat row, and a bidi override cannot
     * reverse the reading order of the entries. */
    char *hostile[] = { (char *)"TERM=xterm",
                        (char *)"PATH=/a\n/b:/c\u202Ed", NULL };
    NSString *h = sw_audit_path_row_value(bare, 1, hostile);
    EQ(h, @"/a\\n/b:/c\\u202ed",
       "control byte and bidi override are escaped to text");
    OK([h rangeOfString:@"\n"].location == NSNotFound,
       "no raw newline survives into the row");
    OK([h rangeOfString:@"\u202e"].location == NSNotFound,
       "no raw bidi override survives into the row");

    /* Nothing to disclose -> no row. */
    char *noPath[] = { (char *)"TERM=xterm", (char *)"HOME=/x", NULL };
    OK(sw_audit_path_row_value(bare, 1, noPath) == nil, "PATH absent -> nil");

    char *emptyPath[] = { (char *)"TERM=xterm", (char *)"PATH=", NULL };
    OK(sw_audit_path_row_value(bare, 1, emptyPath) == nil, "PATH empty -> nil");

    OK(sw_audit_path_row_value(bare, 1, NULL) == nil, "NULL envp -> nil");

    /* PATH is present but the command never consults it -> no row. */
    char *abs_[] = { (char *)"sudo", (char *)"/bin/echo", NULL };
    OK(sw_audit_path_row_value(abs_, 1, env) == nil,
       "an absolute command -> nil even with PATH present");

    char *rel[] = { (char *)"sudo", (char *)"./x", NULL };
    OK(sw_audit_path_row_value(rel, 1, env) == nil,
       "a relative command with a slash -> nil even with PATH present");

    /* No command word at all (`sudo -v`) -> nothing to qualify. */
    char *none[] = { (char *)"sudo", NULL };
    OK(sw_audit_path_row_value(none, 1, env) == nil, "no command word -> nil");
    OK(sw_audit_path_row_value(NULL, 0, env) == nil, "NULL argv -> nil");
    OK(sw_audit_path_row_value(bare, -1, env) == nil, "negative optind -> nil");
}

int main(void) {
    @autoreleasepool {
        test_color_allowed();
        test_color_mode_default();
        test_command_line_plain();
        test_command_line_colored();
        test_command_line_nothing_to_show();
        test_frame_gutter();
        test_frame_value_colour();
        test_fail_soft_fallback();
        test_is_bare_name();
        test_path_row_value();
        SW_SUMMARY("audit plugin internals (colour gate, frame, command line, "
                   "fail-soft, path: row)");
    }
}
