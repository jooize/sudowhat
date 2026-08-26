/*
 * Adversarial unit tests for the static helpers inside sudowhat_approval.m:
 *   - find_kv()                : the "key=value" lookup used to pull uid,
 *                                command, tty, cwd, TERM_PROGRAM from sudo's
 *                                NULL-terminated string arrays.
 *   - generate_verify_nonce()  : the channel-binding code shown in the prompt.
 *   - sw_format_exec_line()    : the resolved exec: line, frame and value.
 *   - sw_confirm_*()           : the off-by-default exec_confirm gate and its
 *                                answer classifier.
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
    EQ(sw_read_utf8(path), @"sudowhat: verify:     3SNJ  (compare with the prompt)\n",
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
    EQ(sw_read_utf8(path), @"sudowhat: verify:     3SNJ  (compare with the prompt)\n",
       "emit_verify_code wrote the line to the tty path");
    unlink(path);

    /* (b) Unopenable path (no controlling terminal) -> silent no-op. There is
     * no stderr fallback, and no printf parameter that could carry one, so
     * nothing is emitted anywhere; the call must simply return without a crash. */
    emit_verify_code("/no/such/dir/sw_tty", "3SNJ", YES);
    OK(1, "no controlling terminal -> silent (no fallback), no crash");
}

/* The line is a field in the audit block's label gutter: "verify:" padded to
 * column 12, the code, then what to do with it. Styled, the label is bold like
 * the audit plugin's labels, the code carries the build-time verifyStyle
 * emphasis (bold here), and the trailing instruction is dim because it is our
 * own chrome. sw_color_allowed honours the env opt-outs. Color is a legibility
 * aid on the tty echo, never a trust signal (the anchor is the code matching the
 * system-rendered Touch ID sheet, which cannot be colored), so these only pin
 * bytes and env logic. */
static void test_verify_line_format_and_color(void) {
    char buf[128];

    int n = format_verify_line(buf, sizeof buf, "3SNJ", NO);
    OK(n > 0 && strcmp(buf, "sudowhat: verify:     3SNJ  (compare with the prompt)\n") == 0,
       "plain rendering carries no escape bytes");

    n = format_verify_line(buf, sizeof buf, "3SNJ", YES);
    OK(n > 0 && strcmp(buf,
       "sudowhat: \033[1mverify:\033[0m     \033[1m3SNJ\033[0m"
       "  \033[2m(compare with the prompt)\033[0m\n") == 0,
       "styled rendering: bold label, bold code, dim tail, same gutter");

    /* Layout is identical either way: strip every SGR sequence from the styled
     * line and the plain line comes back, byte for byte. */
    char plain[128], styled[128];
    format_verify_line(plain, sizeof plain, "3SNJ", NO);
    format_verify_line(styled, sizeof styled, "3SNJ", YES);
    char stripped[128];
    size_t si = 0;
    for (size_t i = 0; styled[i] != '\0' && si + 1 < sizeof stripped; i++) {
        if (styled[i] == '\033') {
            while (styled[i] != '\0' && styled[i] != 'm') i++;
            continue;                                   /* the for-loop eats 'm' */
        }
        stripped[si++] = styled[i];
    }
    stripped[si] = '\0';
    OK(strcmp(stripped, plain) == 0,
       "the styled line strips back to the plain line exactly");

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

/* The exec: line -- the RESOLVED command, this plugin's half of the display
 * carve-out (docs/design-resolved-exec.md). The audit plugin owns user:,
 * directory: and typed:, which are all sudo has produced before resolution;
 * this plugin owns verify:, the sheet, and exec:, which exist only after it.
 *
 * These pin three things: the frame (the shared 12-col gutter, so the line lands
 * in the same table as the audit plugin's rows), the VALUE (byte-identical to
 * the escape core's own rendering, so exec: and typed: cannot disagree about a
 * token), and the tty-or-nothing channel. */

/* The escape core's rendering, called directly, as the reference the exec: value
 * must match byte for byte -- including the argv[0] dedup. Deliberately NOT
 * routed through sw_exec_command_line: comparing that helper against itself
 * would prove nothing. */
static NSString *sw_core_line(const char *path, char * const argv[]) {
    size_t n = 0;
    while (argv != NULL && argv[n] != NULL) n++;

    const uint8_t *a[16];
    size_t l[16];
    if (n > 16) return nil;
    for (size_t i = 0; i < n; i++) {
        a[i] = (const uint8_t *)argv[i];
        l[i] = strlen(argv[i]);
    }

    uint8_t buf[1024];
    size_t needed = 0;
    if (sw_full_command_line((const uint8_t *)path, strlen(path),
                             n ? a : NULL, n ? l : NULL, n,
                             buf, sizeof buf, &needed) != SW_ESCAPE_OK) {
        return nil;
    }
    return [[NSString alloc] initWithBytes:buf length:needed
                                  encoding:NSUTF8StringEncoding];
}

static void test_exec_line_format(void) {
    const char *path = "/run/current-system/sw/bin/pinned";
    char *argv[] = { (char *)"pinned", (char *)"deploy", NULL };

    /* Plain: the provenance prefix, the label padded to the shared gutter, the
     * value. "exec:" is 5 characters, so 7 spaces of gap. */
    EQ(sw_format_exec_line(path, argv, NO),
       @"sudowhat: exec:       /run/current-system/sw/bin/pinned deploy\n",
       "plain exec: line, label padded to the gutter");

    /* The value starts in the same column as every audit-block row (10 bytes of
     * "sudowhat: " plus the 12-wide gutter). This is the whole reason the two
     * bundles duplicate the width instead of sharing it. */
    NSRange v = [sw_format_exec_line(path, argv, NO)
                    rangeOfString:@"/run/current-system"];
    OK(v.location == 22, "exec: value starts at the shared value column 22");

    /* Styled: our frame contributes the bold label and nothing else; the padding
     * stays outside the emphasis, as in the audit plugin's rows. */
    OK([sw_format_exec_line(path, argv, YES)
           hasPrefix:@"sudowhat: \033[1mexec:\033[0m       "],
       "styled exec: line bolds the label only, never the padding");

    /* No path -> nothing to render, so the write site shows nothing rather than
     * a frame with an empty value. */
    OK(sw_format_exec_line(NULL, argv, NO) == nil, "NULL path -> nil line");
}

static void test_exec_line_matches_escape_core(void) {
    /* (a) argv[0] duplicating the path's basename is dropped by the core, so
     * the resolved path is not printed twice. This is the sheet's dedup, from
     * the same token list. */
    const char *path = "/run/current-system/sw/bin/pinned";
    char *argv[] = { (char *)"pinned", (char *)"deploy", NULL };
    EQ(sw_format_exec_line(path, argv, NO),
       ([NSString stringWithFormat:@"sudowhat: exec:       %@\n",
                                   sw_core_line(path, argv)]),
       "exec: value is the escape core's line verbatim (argv[0] dedupped)");

    /* (b) An argv[0] that is NOT the basename is kept, exactly as the core has
     * it -- sudo -u somebody's `sh -c ...` must not lose a token. */
    const char *shPath = "/bin/sh";
    char *shArgv[] = { (char *)"-bash", (char *)"-c", (char *)"id", NULL };
    EQ(sw_format_exec_line(shPath, shArgv, NO),
       ([NSString stringWithFormat:@"sudowhat: exec:       %@\n",
                                   sw_core_line(shPath, shArgv)]),
       "a non-duplicate argv[0] is kept, exactly as the core renders it");

    /* (c) Hostile bytes: the core quotes and escapes them, and the exec: line
     * carries that rendering unchanged, so nothing a caller typed can forge a
     * second sudowhat line or emit a raw escape sequence. */
    const char *echoPath = "/bin/echo";
    char *evil[] = { (char *)"echo", (char *)"sudowhat: exec: /bin/true", NULL };
    EQ(sw_format_exec_line(echoPath, evil, NO),
       @"sudowhat: exec:       /bin/echo 'sudowhat: exec: /bin/true'\n",
       "a token spelled like one of our own lines lands quoted, as data");

    /* (d) Path only, no argv at all. */
    EQ(sw_format_exec_line(echoPath, NULL, NO),
       @"sudowhat: exec:       /bin/echo\n", "NULL run_argv -> path-only line");
}

static void test_emit_exec_line_tty_only(void) {
    /* (a) Writable path -> the line is written there, verbatim and plain (a
     * regular file is not a tty, so the isatty gate keeps the SGR out of a
     * captured log even with colour allowed). */
    char path[256];
    sw_tmpl(path, sizeof path, "exec");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the exec-line test");
    if (fd >= 0) close(fd);

    char *argv[] = { (char *)"pinned", (char *)"deploy", NULL };
    emit_exec_line(path, "/run/current-system/sw/bin/pinned", argv, YES);
    EQ(sw_read_utf8(path),
       @"sudowhat: exec:       /run/current-system/sw/bin/pinned deploy\n",
       "emit_exec_line wrote the resolved line to the tty path");
    OK([sw_read_utf8(path) rangeOfString:@"\033"].location == NSNotFound,
       "a non-tty stays plain even when colour is allowed");

    /* (b) A NULL command path is a silent skip, not a frame with nothing in it:
     * the file must be left exactly as (a) left it. */
    emit_exec_line(path, NULL, argv, YES);
    EQ(sw_read_utf8(path),
       @"sudowhat: exec:       /run/current-system/sw/bin/pinned deploy\n",
       "NULL command path writes nothing at all");
    unlink(path);

    /* (c) No controlling terminal -> silent no-op. There is no stderr fallback
     * and no printf parameter that could carry one, so the line appears on the
     * terminal that launched sudo or nowhere. */
    emit_exec_line("/no/such/dir/sw_tty", "/bin/echo", argv, YES);
    OK(1, "no controlling terminal -> silent (no fallback), no crash");
}

/* exec_confirm: the off-by-default post-resolution question on the
 * terminal-password path. The gate and the answer classifier are pure, so both
 * are pinned here without a terminal; the surrounding TOCTOU pin is the same
 * pattern the console path already uses. */

static void test_exec_confirm_default(void) {
    /* The test binary is compiled with no -DSW_EXEC_CONFIRM, so it sees the
     * header default: off. Off is the shipped default because it adds no new
     * decision -- with it off, the sheet or sudo's own password stays the only
     * one. */
    OK(sw_exec_confirm_mode == SW_EC_off,
       "default build resolves execConfirm to off");
}

static void test_confirm_gate(void) {
    OK(!sw_confirm_gate_active(NO, YES), "knob off -> no prompt, tty or not");
    OK(!sw_confirm_gate_active(NO, NO),  "knob off, no tty -> no prompt");
    OK(!sw_confirm_gate_active(YES, NO),
       "no controlling terminal -> no prompt (automation never blocks)");
    OK(sw_confirm_gate_active(YES, YES), "knob on AND a tty -> prompt");
}

static void test_confirm_answer_classifier(void) {
    /* Affirmative, any case, whitespace and the conversation's newline trimmed. */
    OK(sw_confirm_answer_is_yes("y"),      "y accepted");
    OK(sw_confirm_answer_is_yes("Y"),      "Y accepted");
    OK(sw_confirm_answer_is_yes("yes"),    "yes accepted");
    OK(sw_confirm_answer_is_yes("YES"),    "YES accepted");
    OK(sw_confirm_answer_is_yes("YeS"),    "mixed-case yes accepted");
    OK(sw_confirm_answer_is_yes(" y "),    "surrounding spaces trimmed");
    OK(sw_confirm_answer_is_yes("\ty\r\n"), "tab / CR / LF trimmed");

    /* Everything else declines. A stray Enter must never approve -- that is the
     * whole meaning of [y/N]. */
    OK(!sw_confirm_answer_is_yes("n"),     "n declines");
    OK(!sw_confirm_answer_is_yes("N"),     "N declines");
    OK(!sw_confirm_answer_is_yes("no"),    "no declines");
    OK(!sw_confirm_answer_is_yes(""),      "empty reply declines");
    OK(!sw_confirm_answer_is_yes("\n"),    "a bare newline declines");
    OK(!sw_confirm_answer_is_yes("   "),   "whitespace only declines");
    OK(!sw_confirm_answer_is_yes(NULL),    "NULL reply declines");
    OK(!sw_confirm_answer_is_yes("yes please"), "trailing words decline");
    OK(!sw_confirm_answer_is_yes("yep"),   "yep is not yes");
    OK(!sw_confirm_answer_is_yes("ye"),    "a truncated yes declines");
    OK(!sw_confirm_answer_is_yes("yy"),    "yy declines");
    OK(!sw_confirm_answer_is_yes("1"),     "1 declines");
}

/* The PRE-AUTH block (user/directory/typed) moved to the audit plugin
 * (plugin/sudowhat_audit.m) in v0.10.0, so the former emit_full_context /
 * echoCommand / echoColor tests are gone; what this plugin echoes is the
 * decision-adjacent pair, verify: and exec:, both covered above. The escaping
 * itself is exercised by tests/test_escape_core.m (the Rust core, byte-identical
 * to PromptFormatter). */

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
    /* The test binary is compiled with no -DSW_POLICY_DEFERENCE, so it sees the
     * header default: deference on. (The deferred-echo knob is gone — terminal
     * display is the audit plugin's job now, on every path including a NOPASSWD
     * skip.) */
    OK(sw_policy_deference_mode == SW_PD_on,
       "default build resolves policyDeference to on");
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
        test_exec_line_format();
        test_exec_line_matches_escape_core();
        test_emit_exec_line_tty_only();
        test_exec_confirm_default();
        test_confirm_gate();
        test_confirm_answer_classifier();
        test_integrity_line_detection();
        test_defer_decision();
        test_policy_deference_defaults();
        SW_SUMMARY("plugin internals (find_kv, gate-variant, nonce, "
                   "verify-channel, exec-line, exec-confirm, policy-deference)");
    }
}
