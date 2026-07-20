/*
 * Throwaway PAM auth module for the policy-deference spike.
 *
 * Proves the ONE runtime assumption the marker mechanism rests on: that a
 * setenv() made inside a PAM auth module is visible via getenv() in the process
 * that drove pam_authenticate() — i.e. openpam runs the module in the caller's
 * own process, sharing environ. pam_sudowhat does exactly this setenv in
 * production; the approval plugin reads it back in the same sudo process.
 *
 * This module belongs ONLY to the throwaway `sudowhat-spike` PAM service the
 * spike installs; it is never wired into sudo. It grants nothing on its own —
 * `sufficient` success here applies only to that isolated test service.
 *
 * Build: clang -bundle -Wl,-undefined,dynamic_lookup spike_pam.c -o spike_pam.so
 */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>

#define SPIKE_MARKER_ENV "SUDOWHAT_SPIKE_MARKER"

__attribute__((visibility("default")))
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char *argv[]) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    /* The whole point of the spike: set a process-global marker from inside the
     * module, exactly as pam_sudowhat's auth entry does in production. */
    setenv(SPIKE_MARKER_ENV, "1", 1);
    return PAM_SUCCESS;   /* isolated test service only — grants nothing real */
}

__attribute__((visibility("default")))
int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char *argv[]) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
