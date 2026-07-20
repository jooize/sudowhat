/*
 * Spike driver: runs pam_authenticate() against the throwaway `sudowhat-spike`
 * service (which loads spike_pam.so), then checks whether the marker the module
 * set with setenv() is visible here via getenv(). Same process throughout, so a
 * PASS confirms module-setenv -> caller-getenv works — the assumption the
 * production marker relies on.
 *
 * Build: clang spike_driver.c -lpam -o spike_driver
 */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SPIKE_MARKER_ENV "SUDOWHAT_SPIKE_MARKER"
#define SPIKE_SERVICE    "sudowhat-spike"

/* No interaction: the spike module needs no password. */
static int null_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata) {
    (void)num_msg; (void)msg; (void)resp; (void)appdata;
    return PAM_SUCCESS;
}

int main(void) {
    /* Start from a clean slate so a stray inherited value can't fake a PASS. */
    unsetenv(SPIKE_MARKER_ENV);

    struct pam_conv conv = { null_conv, NULL };
    pam_handle_t *pamh = NULL;

    int r = pam_start(SPIKE_SERVICE, NULL, &conv, &pamh);
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "pam_start(%s) failed: %d\n", SPIKE_SERVICE, r);
        fprintf(stderr, "Is /etc/pam.d/%s installed? (run-spike.sh installs it)\n",
                SPIKE_SERVICE);
        return 2;
    }

    r = pam_authenticate(pamh, 0);
    const char *marker = getenv(SPIKE_MARKER_ENV);

    printf("pam_authenticate -> %d (%s)\n", r, pam_strerror(pamh, r));
    printf("getenv(%s) -> %s\n", SPIKE_MARKER_ENV, marker ? marker : "(null)");

    int pass = (marker != NULL && strcmp(marker, "1") == 0);
    if (pass) {
        printf("\nSPIKE RESULT: PASS\n"
               "  A setenv() inside the PAM auth module is visible to getenv()\n"
               "  in the caller. The production marker mechanism is sound.\n");
    } else {
        printf("\nSPIKE RESULT: FAIL\n"
               "  The marker was NOT visible. The same-process assumption does\n"
               "  not hold as tested — do NOT rely on the getenv marker; report\n"
               "  this before deploying (a pid-keyed side channel is the fallback).\n");
    }

    pam_end(pamh, r);
    return pass ? 0 : 1;
}
