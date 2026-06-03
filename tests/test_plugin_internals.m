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
    static const char *A = "123456789ABCDEFGHJKMNPQRSTVWXYZ";
    return strchr(A, c) != NULL;
}

static void test_nonce_alphabet_and_length(void) {
    /* Harsh: hammer it and assert every produced char is in the intended
     * alphabet, the forbidden look-alikes (0 I L O U) never appear, length is
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
            if (c=='0'||c=='I'||c=='L'||c=='O'||c=='U') forbidden++;
        }
    }
    OK(bad == 0, "all nonce chars in alphabet");
    OK(forbidden == 0, "no forbidden look-alike chars (0 I L O U)");
    OK(badlen == 0, "nonce length always outsz-1");
    OK(notterm == 0, "nonce always NUL-terminated");
    const char *A = "123456789ABCDEFGHJKMNPQRSTVWXYZ";
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
 * against the Touch ID sheet. It must reach the human at the keyboard whatever
 * the command does with its fds, so it is written to the controlling terminal
 * (/dev/tty), which a shell's `>`/`2>`/`&>` cannot touch; only when there is no
 * controlling terminal does emit_verify_code fall back to sudo's stderr
 * (SUDO_CONV_ERROR_MSG, never INFO_MSG/stdout). These tests pin both branches:
 * the tty path is parameterized so we can aim it at a temp file with no real
 * tty, and the fallback is driven by an unopenable path. */
static int  g_cap_msg_type;
static char g_cap_buf[512];
static int capture_printf(int msg_type, const char *fmt, ...) {
    g_cap_msg_type = msg_type;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_cap_buf, sizeof g_cap_buf, fmt, ap);
    va_end(ap);
    return n;
}

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

    OK(write_verify_code_to_tty(path, "3SNJ"),
       "write_verify_code_to_tty succeeds on a writable path");
    EQ(sw_read_utf8(path), @"sudowhat: verify code 3SNJ in the prompt\n",
       "the controlling-terminal channel gets the exact verify line");
    unlink(path);

    /* Unopenable path -> NO (this is what drives the stderr fallback). */
    OK(!write_verify_code_to_tty("/no/such/dir/sw_tty", "3SNJ"),
       "write_verify_code_to_tty fails closed on an unopenable path");
}

static void test_emit_prefers_tty_then_stderr(void) {
    /* (a) tty path writable -> code goes to the tty, stderr fallback untouched. */
    char path[256];
    sw_tmpl(path, sizeof path, "emit");
    int fd = mkstemp(path);
    OK(fd >= 0, "mkstemp created a temp file for the emit test");
    if (fd >= 0) close(fd);

    g_cap_msg_type = -1; g_cap_buf[0] = '\0';
    emit_verify_code(capture_printf, path, "3SNJ");
    OK(g_cap_msg_type == -1, "stderr fallback NOT used when the tty write succeeds");
    EQ(sw_read_utf8(path), @"sudowhat: verify code 3SNJ in the prompt\n",
       "emit_verify_code wrote the line to the tty path");
    unlink(path);

    /* (b) tty unopenable -> fall back to sudo's stderr (ERROR_MSG), never stdout. */
    g_cap_msg_type = -1; g_cap_buf[0] = '\0';
    emit_verify_code(capture_printf, "/no/such/dir/sw_tty", "3SNJ");
    OK(g_cap_msg_type == SUDO_CONV_ERROR_MSG,
       "fallback uses ERROR_MSG/stderr (survives >), not INFO_MSG/stdout");
    OK(g_cap_msg_type != SUDO_CONV_INFO_MSG, "fallback is not on stdout");
    OK(strstr(g_cap_buf, "3SNJ") != NULL, "fallback line carries the code");

    /* (c) tty unopenable AND no printf -> silent no-op, never a crash. */
    g_cap_msg_type = -1;
    emit_verify_code(NULL, "/no/such/dir/sw_tty", "XXXX");
    OK(g_cap_msg_type == -1, "no tty + NULL printf is a silent no-op");
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
        test_emit_prefers_tty_then_stderr();
        SW_SUMMARY("plugin internals (find_kv, gate-variant, nonce, verify-channel)");
    }
}
