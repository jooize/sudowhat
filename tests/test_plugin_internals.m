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
        test_nonce_alphabet_and_length();
        test_nonce_edge_sizes();
        SW_SUMMARY("plugin internals (find_kv, nonce)");
    }
}
