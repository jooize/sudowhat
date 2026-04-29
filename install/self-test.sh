#!/bin/bash
# Post-install sanity check. Confirms:
#   1. sudo can load the approval plugin (sudo -V succeeds and lists it).
#   2. The plugin actually runs in the auth chain (sudo -n with no cached
#      auth fails with our 'tsudo:' prefix in the error, not sudo's own
#      "a password is required").

set -euo pipefail

PLUGIN_DST="/usr/local/libexec/sudo/tsudo_approval.so"
PAM_DST="/usr/local/lib/pam/pam_tsudo.so"

[ -f "$PLUGIN_DST" ] || { echo "self-test: $PLUGIN_DST missing" >&2; exit 1; }
[ -f "$PAM_DST" ]    || { echo "self-test: $PAM_DST missing" >&2;    exit 1; }

# (1) sudo -V loads the approval plugin during startup; non-zero exit means
# sudo refused to load it.
if ! sudo -V >/dev/null 2>&1; then
    echo "self-test: 'sudo -V' failed; sudo refused to load the plugin" >&2
    exit 1
fi

# (2) Run a non-interactive sudo and look at its error output. We expect a
# failure because there's no cached auth and -n disables prompting; the
# important thing is the failure path runs through our plugin.
out="$(sudo -n /bin/echo tsudo-self-test 2>&1 || true)"

if printf '%s' "$out" | grep -qi 'tsudo:'; then
    echo "tsudo: install verified"
    exit 0
fi

# Acceptable alternative: our PAM module short-circuited and sudo exited
# without invoking the approval plugin. In that case the message is sudo's
# own "a password is required" — which is the stock behavior we DIDN'T
# want. So treat that as failure.
echo "self-test: sudo did not pass through our plugin; output was:" >&2
printf '%s\n' "$out" >&2
exit 1
