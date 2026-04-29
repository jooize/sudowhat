#!/bin/bash
# Post-install sanity check. We deliberately do NOT drive sudo through an
# end-to-end auth here: sudowhat's approval plugin pops a system-trusted
# Touch ID dialog and forcing that during `make install` is hostile.
#
# The checks below confirm that all four placed files are in place with
# expected content/permissions and that sudo can still parse its config.
# The user is expected to verify the live workflow with a manual
# `sudo /bin/echo hello` after install.

set -euo pipefail

PLUGIN_DST="/usr/local/libexec/sudo/sudowhat_approval.so"
PAM_DST="/usr/local/lib/pam/pam_sudowhat.so"
SUDO_CONF="/etc/sudo.conf"
SUDOERS_D="/etc/sudoers.d/sudowhat"
PAM_LOCAL="/etc/pam.d/sudo_local"

# (1) Files exist with expected modes.
[ -x "$PLUGIN_DST" ]                || { echo "self-test: $PLUGIN_DST missing or not executable" >&2; exit 1; }
[ -x "$PAM_DST" ]                   || { echo "self-test: $PAM_DST missing or not executable" >&2;    exit 1; }
[ -f "$SUDO_CONF" ]                 || { echo "self-test: $SUDO_CONF missing" >&2;                    exit 1; }
[ -f "$SUDOERS_D" ]                 || { echo "self-test: $SUDOERS_D missing" >&2;                    exit 1; }
[ -f "$PAM_LOCAL" ]                 || { echo "self-test: $PAM_LOCAL missing" >&2;                    exit 1; }

# (2) /etc/sudo.conf names our approval plugin at the expected path.
if ! grep -qF "sudowhat_approval_plugin /usr/local/libexec/sudo/sudowhat_approval.so" "$SUDO_CONF"; then
    echo "self-test: $SUDO_CONF does not name sudowhat_approval_plugin at the expected path" >&2
    exit 1
fi

# (3) /etc/pam.d/sudo_local references our PAM module at the expected path.
if ! grep -qF "/usr/local/lib/pam/pam_sudowhat.so" "$PAM_LOCAL"; then
    echo "self-test: $PAM_LOCAL does not reference pam_sudowhat.so at the expected path" >&2
    exit 1
fi

# (4) sudoers.d snippet parses (visudo run already validated it during
# install; re-check is cheap insurance).
if ! visudo -c -f "$SUDOERS_D" >/dev/null; then
    echo "self-test: $SUDOERS_D failed visudo -c" >&2
    exit 1
fi

# (5) sudo -V loads the approval plugin without erroring. Exit non-zero
# from sudo -V usually means a malformed sudo.conf or a plugin sudo
# refused to load.
if ! sudo -V >/dev/null 2>&1; then
    echo "self-test: 'sudo -V' failed; sudo refused to load its config" >&2
    exit 1
fi

echo "sudowhat: install verified (run 'sudo /bin/echo hello' to test the live prompt)"
