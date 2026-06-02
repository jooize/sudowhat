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
 * against the Touch ID sheet. sudo routes SUDO_CONV_INFO_MSG to stdout and
 * SUDO_CONV_ERROR_MSG to stderr, so emitting it on INFO_MSG would let the
 * ubiquitous `sudo cmd >file` / `sudo tee file >/dev/null` redirect swallow it,
 * leaving a bare prompt with nothing to compare. emit_verify_code must pin the
 * code to the error/stderr channel; this test fails if that regresses. */
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

static void test_verify_code_on_error_channel(void) {
    g_cap_msg_type = -1;
    g_cap_buf[0] = '\0';
    emit_verify_code(capture_printf, "3SNJ");
    OK(g_cap_msg_type == SUDO_CONV_ERROR_MSG,
       "verify code on ERROR_MSG/stderr (survives >/dev/null)");
    OK(g_cap_msg_type != SUDO_CONV_INFO_MSG,
       "verify code NOT on INFO_MSG/stdout");
    OK(strstr(g_cap_buf, "3SNJ") != NULL, "verify code value present in the line");
    OK(strstr(g_cap_buf, "verify code") != NULL, "line carries the 'verify code' label");

    /* A NULL printf (sudo didn't hand open() a callback) must be a silent
     * no-op, never a crash or a stray emission. */
    g_cap_msg_type = -1;
    emit_verify_code(NULL, "XXXX");
    OK(g_cap_msg_type == -1, "NULL printf_fn is a no-op");
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
        test_verify_code_on_error_channel();
        SW_SUMMARY("plugin internals (find_kv, gate-variant, nonce, verify-channel)");
    }
}
