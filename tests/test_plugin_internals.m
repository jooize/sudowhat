/*
 * Adversarial unit tests for the static helpers inside sudowhat_approval.m:
 *   - find_kv()                : the "key=value" lookup used to pull uid,
 *                                command, tty, cwd, TERM_PROGRAM from sudo's
 *                                NULL-terminated string arrays.
 *   - generate_verify_nonce()  : the channel-binding code shown in the prompt.
 *
 * Both are file-static, so we #include the .m directly to reach them without
 * modifying production code. This compiles the whole plugin into the test
 * binary (the exported plugin struct and open/check/close come along for the
 * ride but are never called); the sibling .m files it references are linked in
 * via the Makefile. If find_kv / generate_verify_nonce are later extracted to
 * shared/, swap this #include for a direct link against the extracted unit.
 */
#import "sw_test.h"
#include <stdarg.h>
#include "../plugin/sudowhat_approval.m"

static void test_find_kv_basic(void) {
    char *arr[] = { (char *)"uid=501", (char *)"gid=20", (char *)"tty=/dev/ttys001", NULL };
    OK(find_kv(arr, "uid") && strcmp(find_kv(arr, "uid"), "501") == 0, "find uid");
    OK(find_kv(arr, "gid") && strcmp(find_kv(arr, "gid"), "20") == 0, "find gid");
    OK(find_kv(arr, "tty") && strcmp(find_kv(arr, "tty"), "/dev/ttys001") == 0, "find tty");
}

static void test_find_kv_missing(void) {
    char *arr[] = { (char *)"uid=501", NULL };
    OK(find_kv(arr, "gid") == NULL, "missing key -> NULL");
    OK(find_kv(NULL, "uid") == NULL, "NULL array -> NULL");
    char *empty[] = { NULL };
    OK(find_kv(empty, "uid") == NULL, "empty array -> NULL");
}

static void test_find_kv_prefix_safety(void) {
    /* A longer key that merely shares a prefix must NOT match: "key" must not
     * match "keyboard=...". The '=' boundary check is what enforces this; if
     * it regressed, a lookup for "uid" could match "uidx=" and read the wrong
     * value - a security-relevant confusion. */
    char *arr[] = { (char *)"keyboard=evil", (char *)"key=good", NULL };
    OK(find_kv(arr, "key") && strcmp(find_kv(arr, "key"), "good") == 0,
       "prefix key does not match longer key");
    char *arr2[] = { (char *)"uidextra=999", (char *)"uid=501", NULL };
    OK(find_kv(arr2, "uid") && strcmp(find_kv(arr2, "uid"), "501") == 0,
       "uid does not match uidextra");
    /* key with no '=' at all must not match */
    char *arr3[] = { (char *)"uid", (char *)"uid=501", NULL };
    OK(find_kv(arr3, "uid") && strcmp(find_kv(arr3, "uid"), "501") == 0,
       "bare key (no =) skipped, real one found");
}

static void test_find_kv_empty_value(void) {
    char *arr[] = { (char *)"tty=", (char *)"uid=501", NULL };
    const char *v = find_kv(arr, "tty");
    OK(v != NULL && v[0] == '\0', "key= -> empty-string value, not NULL");
}

static void test_find_kv_first_match_wins(void) {
    char *arr[] = { (char *)"uid=1", (char *)"uid=2", NULL };
    OK(find_kv(arr, "uid") && strcmp(find_kv(arr, "uid"), "1") == 0,
       "first match wins on duplicate key");
}

static void test_find_kv_value_with_equals(void) {
    /* value may itself contain '=' (e.g. an env var) - only the first '='
     * splits. */
    char *arr[] = { (char *)"X=a=b=c", NULL };
    OK(find_kv(arr, "X") && strcmp(find_kv(arr, "X"), "a=b=c") == 0,
       "value containing = preserved");
}

static int in_alphabet(char c) {
    static const char *A = "3456789ACDEFHJKLMNPQRTVWXYZ";
    return strchr(A, c) != NULL;
}

static void test_nonce_alphabet_and_length(void) {
    /* Harsh: hammer it and assert every produced char is in the intended
     * alphabet, the forbidden look-alikes (0 1 2 B G I O S U) never appear
     * (note L is now allowed — uppercase-only — while 1 is dropped), length is
     * exactly outsz-1, and the buffer is NUL-terminated. Also check every
     * alphabet symbol shows up at least once (no off-by-one truncating the
     * arc4random_uniform range). */
    enum { N = 200000, LEN = 4 };
    int seen[256] = {0};
    int bad = 0, badlen = 0, notterm = 0, forbidden = 0;
    for (int i = 0; i < N; i++) {
        char buf[LEN + 1];
        memset(buf, '?', sizeof buf);
        generate_verify_nonce(buf, sizeof buf);
        if (buf[LEN] != '\0') notterm++;
        if (strlen(buf) != LEN) badlen++;
        for (int j = 0; j < LEN; j++) {
            unsigned char c = (unsigned char)buf[j];
            seen[c] = 1;
            if (!in_alphabet((char)c)) bad++;
            if (c=='0'||c=='1'||c=='2'||c=='B'||c=='G'||
                c=='I'||c=='O'||c=='S'||c=='U') forbidden++;
        }
    }
    OK(bad == 0, "all nonce chars in alphabet");
    OK(forbidden == 0, "no forbidden look-alike chars (0 1 2 B G I O S U)");
    OK(badlen == 0, "nonce length always outsz-1");
    OK(notterm == 0, "nonce always NUL-terminated");
    const char *A = "3456789ACDEFHJKLMNPQRTVWXYZ";
    int allseen = 1;
    for (const char *p = A; *p; p++) if (!seen[(unsigned char)*p]) allseen = 0;
    OK(allseen, "every alphabet symbol appears across 200k draws");
    /* the NUL slot of the alphabet must never be selected */
    OK(seen[0] == 0, "NUL never produced as a nonce char");
}

static void test_gate_variant_detection(void) {
    /* sudowhat_text_is_gate_variant decides whether the non-console step-aside
     * is safe: it must accept ONLY a /etc/pam.d/sudo_local that has both the
     * integrity requisite line and the console-gate sufficient line, at our own
     * baked module path (SUDOWHAT_PAM_PATH). Anything else -> deny. */
    NSString *pam = @SUDOWHAT_PAM_PATH;

    NSString *gate = [NSString stringWithFormat:
        @"# managed by nix\nauth requisite %@\nauth sufficient %@ console-gate\n",
        pam, pam];
    OK(sudowhat_text_is_gate_variant(gate), "gate variant accepted");

    /* The default console-only install: pam_permit, no password path. */
    NSString *permit = [NSString stringWithFormat:
        @"auth requisite %@\nauth sufficient pam_permit.so\n", pam];
    OK(!sudowhat_text_is_gate_variant(permit), "pam_permit variant rejected");

    /* A console-gate line pointing at some OTHER module must not count — this
     * is the coupling to what the installer actually wrote. */
    NSString *wrongPath = [NSString stringWithFormat:
        @"auth requisite %@\n"
        @"auth sufficient /usr/local/lib/pam/evil.so console-gate\n", pam];
    OK(!sudowhat_text_is_gate_variant(wrongPath),
       "console-gate at wrong module path rejected");

    /* Both lines are required: gate line without the integrity requisite. */
    NSString *gateOnly = [NSString stringWithFormat:
        @"auth sufficient %@ console-gate\n", pam];
    OK(!sudowhat_text_is_gate_variant(gateOnly),
       "console-gate without integrity requisite rejected");

    /* sufficient at our path but missing the console-gate argument: that is an
     * unconditional pass for everyone (passwordless), must be rejected. */
    NSString *noArg = [NSString stringWithFormat:
        @"auth requisite %@\nauth sufficient %@\n", pam, pam];
    OK(!sudowhat_text_is_gate_variant(noArg),
       "sufficient at our path without console-gate arg rejected");

    OK(!sudowhat_text_is_gate_variant(nil), "nil content rejected");
    OK(!sudowhat_text_is_gate_variant(@""), "empty content rejected");

    /* Whitespace-insensitive, comments and blank lines tolerated. */
    NSString *spaced = [NSString stringWithFormat:
        @"\n  auth\trequisite\t%@   \n# a comment\n"
        @"   auth   sufficient    %@    console-gate  \n", pam, pam];
    OK(sudowhat_text_is_gate_variant(spaced),
       "tabs/extra spaces/blank lines/comments tolerated");

    /* A commented-out gate line must NOT satisfy the check. */
    NSString *commented = [NSString stringWithFormat:
        @"auth requisite %@\n# auth sufficient %@ console-gate\n", pam, pam];
    OK(!sudowhat_text_is_gate_variant(commented),
       "commented-out console-gate line does not count");
}

/* The verify code is a channel-binding security signal the user compares
 * against the Touch ID sheet. It is written to the controlling terminal
 * (/dev/tty) — which a shell's `>`/`2>`/`&>` cannot touch — and to NOWHERE
 * else: when there is no controlling terminal, emit_verify_code stays silent
 * rather than fall back to sudo's stderr (which could clutter an error stream
 * or be slurped into a `2>file`). That is structural — emit_verify_code takes
 * no printf, so it has no channel but the tty. These tests pin the tty write
 * and the silent-on-no-tty behavior via the parameterized path. */

/* mkstemp template under $TMPDIR (falls back to /tmp). */
static void sw_tmpl(char *buf, size_t n, const char *tag) {
    const char *t = getenv("TMPDIR");
    if (t == NULL || t[0] == '\0') t = "/tmp";
    snprintf(buf, n, "%s/sw_verify_%s.XXXXXX", t, tag);
}

static NSString *sw_read_utf8(const char *path) {
    return [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:path]
                                     encoding:NSUTF8StringEncoding error:NULL];
}

static void test_verify_code_to_tty(void) {
    /* The exact line the user matches against the sheet, written verbatim. */
    char path[256];
    sw_tmpl(path, sizeof path, "tty");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the tty-write test");
    if (fd >= 0) close(fd);

    /* colorAllowed=YES, yet a regular file is not a tty -> isatty() gate keeps
     * the bytes plain, so no escape sequence can ever corrupt a captured log. */
    OK(write_verify_code_to_tty(path, "3SNJ", YES),
       "write_verify_code_to_tty succeeds on a writable path");
    EQ(sw_read_utf8(path), @"sudowhat: verify code 3SNJ in the prompt\n",
       "a non-tty stays plain even when color is allowed");
    unlink(path);

    /* Unopenable path -> NO (this is what drives the stderr fallback). */
    OK(!write_verify_code_to_tty("/no/such/dir/sw_tty", "3SNJ", YES),
       "write_verify_code_to_tty fails closed on an unopenable path");
}

static void test_emit_verify_code_tty_only(void) {
    /* (a) Writable tty path -> the code is written there, verbatim. */
    char path[256];
    sw_tmpl(path, sizeof path, "emit");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the emit test");
    if (fd >= 0) close(fd);

    emit_verify_code(path, "3SNJ", YES);
    EQ(sw_read_utf8(path), @"sudowhat: verify code 3SNJ in the prompt\n",
       "emit_verify_code wrote the line to the tty path");
    unlink(path);

    /* (b) Unopenable path (no controlling terminal) -> silent no-op. There is
     * no stderr fallback, and no printf parameter that could carry one, so
     * nothing is emitted anywhere; the call must simply return without a crash. */
    emit_verify_code("/no/such/dir/sw_tty", "3SNJ", YES);
    OK(1, "no controlling terminal -> silent (no fallback), no crash");
}

/* The bold rendering wraps ONLY the code in SGR 1 / reset, and sw_color_allowed
 * honours the env opt-outs. Color is a legibility aid on the tty echo, never a
 * trust signal (the anchor is the code matching the system-rendered Touch ID
 * sheet, which cannot be colored), so these only pin bytes and env logic. */
static void test_verify_line_format_and_color(void) {
    char buf[96];

    int n = format_verify_line(buf, sizeof buf, "3SNJ", NO);
    OK(n > 0 && strcmp(buf, "sudowhat: verify code 3SNJ in the prompt\n") == 0,
       "plain rendering carries no escape bytes");

    n = format_verify_line(buf, sizeof buf, "3SNJ", YES);
    OK(n > 0 && strcmp(buf,
       "sudowhat: verify code \033[1m3SNJ\033[0m in the prompt\n") == 0,
       "bold rendering wraps only the code in SGR 1 / reset");

    /* sw_color_allowed reads the captured invoking-context snapshot. */
    sw_invoking_ctx saved = g_inv;

    g_inv = (sw_invoking_ctx){ .have_term = 1, .no_color = 0 };
    snprintf(g_inv.term, sizeof g_inv.term, "%s", "xterm-256color");
    OK(sw_color_allowed(), "color allowed for a normal TERM with NO_COLOR unset");

    g_inv.no_color = 1;
    OK(!sw_color_allowed(), "NO_COLOR (any value) disables color");

    g_inv = (sw_invoking_ctx){ .have_term = 1 };
    snprintf(g_inv.term, sizeof g_inv.term, "%s", "dumb");
    OK(!sw_color_allowed(), "TERM=dumb disables color");

    g_inv = (sw_invoking_ctx){ .have_term = 0 };
    OK(!sw_color_allowed(), "absent TERM disables color");

    g_inv = saved;
}

/* The context terminal echo. echoCommand is baked at build time; the test binary
 * is compiled with no -DSW_ECHO_COMMAND, so it sees the header default
 * ("truncated"): echo an item iff the sheet replaced it with "(see terminal)".
 * emit_full_context is tty-only by design — unlike the verify code it has NO
 * stderr fallback, so a possibly confidential value can never leak into a
 * `2>file` capture. */
static void test_echo_command_mode(void) {
    OK(sw_echo_command_mode == SW_EC_truncated,
       "default build resolves echoCommand to truncated");
    OK(sw_should_echo_command(YES),
       "truncated mode echoes an item that overflowed to the terminal");
    OK(!sw_should_echo_command(NO),
       "truncated mode stays silent for an item that fit the sheet");
}

static void test_emit_full_context_to_tty(void) {
    char path[256];
    sw_tmpl(path, sizeof path, "fullctx");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the context echo test");
    if (fd >= 0) close(fd);

    /* All three items echoed -> three labelled lines, in order. */
    emit_full_context(path, @"root", @"/tmp", @"/bin/echo 'a b'", YES, YES, YES, NO);
    EQ(sw_read_utf8(path),
       @"sudowhat: user: root\nsudowhat: path: /tmp\nsudowhat: command: /bin/echo 'a b'\n",
       "emit_full_context writes user/path/command lines in order");
    unlink(path);

    /* Only the flagged items are written (path suppressed here). */
    char path2[256];
    sw_tmpl(path2, sizeof path2, "fullctx2");
    int fd2 = mkstemp(path2);
    OK(fd2 >= 0, "mkstemp created a second temp file");
    if (fd2 >= 0) close(fd2);
    emit_full_context(path2, @"root", @"/tmp", @"/bin/echo hi", NO, NO, YES, NO);
    EQ(sw_read_utf8(path2), @"sudowhat: command: /bin/echo hi\n",
       "only the flagged item is written");
    unlink(path2);

    /* Nothing flagged -> early no-op, nothing written (file untouched). */
    char path3[256];
    sw_tmpl(path3, sizeof path3, "fullctx3");
    int fd3 = mkstemp(path3);
    OK(fd3 >= 0, "mkstemp created a third temp file");
    if (fd3 >= 0) close(fd3);
    emit_full_context(path3, @"root", @"/tmp", @"/bin/echo", NO, NO, NO, NO);
    EQ(sw_read_utf8(path3), @"", "no flags set writes nothing");
    unlink(path3);

    /* Unopenable path -> silent no-op, no crash, no fallback channel. */
    emit_full_context("/no/such/dir/sw_fullctx", @"root", @"/tmp",
                      @"/bin/echo secret", YES, YES, YES, NO);
    OK(1, "unopenable tty is a silent no-op (no fallback, no crash)");
}

/* The echoColor gate. The test binary is compiled with no -DSW_ECHO_COLOR, so
 * it sees the header default ("off"). Even asking to colourise, a non-tty target
 * (the temp file) must render plain — the isatty() gate in emit_full_context is
 * authoritative, so a `2>file`-style redirect never gets escape sequences. */
static void test_echo_color_gate(void) {
    OK(sw_echo_color_mode == SW_ECOL_off,
       "default build resolves echoColor to off");
    OK(!sw_echo_color_allowed(),
       "off mode never permits colour (short-circuits before sw_color_allowed)");

    char path[256];
    sw_tmpl(path, sizeof path, "colorgate");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the colour-gate test");
    if (fd >= 0) close(fd);
    /* colorize=YES, but the temp file is not a tty -> plain, no SGR bytes. */
    emit_full_context(path, @"root", @"/tmp", @"/bin/echo 'a b'", YES, YES, YES, YES);
    EQ(sw_read_utf8(path),
       @"sudowhat: user: root\nsudowhat: path: /tmp\nsudowhat: command: /bin/echo 'a b'\n",
       "colorize=YES on a non-tty still renders plain (isatty gate)");
    unlink(path);
}

/* Policy deference: the pam_sudowhat auth marker tells the plugin whether sudo
 * ran the PAM auth stack (i.e. sudoers required authentication). These pin the
 * two security-critical pure helpers and the build defaults. */

static void test_integrity_line_detection(void) {
    /* sudowhat_text_has_integrity_line confirms pam_sudowhat's auth entry is
     * actually wired into sudo_local at OUR baked module path — the premise the
     * absent-marker skip relies on. Present in BOTH install variants; anything
     * else -> NO, so an unverifiable chain fails toward prompting. */
    NSString *pam = @SUDOWHAT_PAM_PATH;

    NSString *permit = [NSString stringWithFormat:
        @"auth requisite %@\nauth sufficient pam_permit.so\n", pam];
    OK(sudowhat_text_has_integrity_line(permit),
       "default console-only variant has the integrity line");

    NSString *gate = [NSString stringWithFormat:
        @"auth requisite %@\nauth sufficient %@ console-gate\n", pam, pam];
    OK(sudowhat_text_has_integrity_line(gate),
       "gate variant has the integrity line");

    NSString *none = @"auth sufficient pam_permit.so\n";
    OK(!sudowhat_text_has_integrity_line(none), "no integrity line -> NO");

    NSString *wrongPath = @"auth requisite /usr/local/lib/pam/evil.so\n";
    OK(!sudowhat_text_has_integrity_line(wrongPath),
       "requisite line at a different module path -> NO");

    NSString *wrongFlag = [NSString stringWithFormat:@"auth sufficient %@\n", pam];
    OK(!sudowhat_text_has_integrity_line(wrongFlag),
       "our path but control flag is not requisite -> NO");

    NSString *fourTok = [NSString stringWithFormat:
        @"auth requisite %@ console-gate\n", pam];
    OK(!sudowhat_text_has_integrity_line(fourTok),
       "requisite line with a trailing arg is not the integrity line -> NO");

    NSString *commented = [NSString stringWithFormat:@"# auth requisite %@\n", pam];
    OK(!sudowhat_text_has_integrity_line(commented),
       "commented-out integrity line does not count -> NO");

    NSString *spaced = [NSString stringWithFormat:
        @"\n  auth\trequisite\t%@   \n# a comment\n", pam];
    OK(sudowhat_text_has_integrity_line(spaced),
       "tabs/extra spaces/blank lines/comments tolerated");

    OK(!sudowhat_text_has_integrity_line(nil), "nil content -> NO");
    OK(!sudowhat_text_has_integrity_line(@""), "empty content -> NO");
}

static void test_defer_decision(void) {
    /* Fail-safe in every uncertain direction: only marker-absent AND
     * chain-intact AND deference-on skips the prompt. */
    OK(!sw_defer_decision(NO, NO, YES),
       "deference off -> prompt even when everything else says skip");
    OK(!sw_defer_decision(NO, YES, YES), "deference off -> prompt regardless");

    OK(!sw_defer_decision(YES, YES, YES),
       "marker present (sudo ran the auth stack) -> prompt");
    OK(!sw_defer_decision(YES, YES, NO),
       "marker present, chain unverified -> prompt");
    OK(!sw_defer_decision(YES, NO, NO),
       "marker absent but integrity line not wired -> prompt (absence untrusted)");
    OK(sw_defer_decision(YES, NO, YES),
       "marker absent AND integrity line wired -> SKIP (sudoers waived auth)");
}

static void test_policy_deference_defaults(void) {
    /* The test binary is compiled with no -DSW_POLICY_DEFERENCE / -DSW_ECHO_DEFERRED,
     * so it sees the header defaults: deference on, deferred echo off (silent). */
    OK(sw_policy_deference_mode == SW_PD_on,
       "default build resolves policyDeference to on");
    OK(sw_echo_deferred_mode == SW_ED_off,
       "default build resolves echoDeferred to off");
}

static void test_emit_deferred_context_off_default(void) {
    /* With the default echoDeferred=off, emit_deferred_context is a no-op even
     * when a controlling terminal is present — the safe default is silent. */
    sw_invoking_ctx saved = g_inv;

    char path[256];
    sw_tmpl(path, sizeof path, "deferred");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the deferred-echo test");
    if (fd >= 0) close(fd);

    g_inv = (sw_invoking_ctx){ .have_tty = 1 };
    emit_deferred_context(path, @"root", @"/tmp", @"/bin/echo hi");
    EQ(sw_read_utf8(path), @"", "echoDeferred=off writes nothing even with a tty");
    unlink(path);

    g_inv = saved;
}

static void test_nonce_edge_sizes(void) {
    char b1[1] = { '?' };
    generate_verify_nonce(b1, sizeof b1);
    OK(b1[0] == '\0', "outsz=1 -> empty string");

    char b2[2] = { '?', '?' };
    generate_verify_nonce(b2, sizeof b2);
    OK(b2[1] == '\0' && in_alphabet(b2[0]), "outsz=2 -> 1 char + NUL");

    char b0[1] = { 'Z' };
    generate_verify_nonce(b0, 0);   /* outsz==0 must be a no-op */
    OK(b0[0] == 'Z', "outsz=0 writes nothing");
}

int main(void) {
    @autoreleasepool {
        test_find_kv_basic();
        test_find_kv_missing();
        test_find_kv_prefix_safety();
        test_find_kv_empty_value();
        test_find_kv_first_match_wins();
        test_find_kv_value_with_equals();
        test_gate_variant_detection();
        test_nonce_alphabet_and_length();
        test_nonce_edge_sizes();
        test_verify_code_to_tty();
        test_emit_verify_code_tty_only();
        test_verify_line_format_and_color();
        test_echo_command_mode();
        test_emit_full_context_to_tty();
        test_echo_color_gate();
        test_integrity_line_detection();
        test_defer_decision();
        test_policy_deference_defaults();
        test_emit_deferred_context_off_default();
        SW_SUMMARY("plugin internals (find_kv, gate-variant, nonce, verify-channel, command-echo, policy-deference)");
    }
}
