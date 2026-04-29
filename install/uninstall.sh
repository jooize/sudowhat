#!/bin/bash
# Uninstall sudowhat. Idempotent. Must run as root.
#
# Removes the two bundles, the sudo.conf Plugin line, the sudoers.d snippet,
# and the pam.d/sudo_local file. Leaves any pre-existing /etc/sudo.conf in
# place (only our line is removed).
#
# Also removes any leftover files from the project's prior name (tsudo)
# in case the user upgraded from <= v0.2.0 without first uninstalling.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: must run as root" >&2
    exit 1
fi

PLUGIN_DST="/usr/local/libexec/sudo/sudowhat_approval.so"
PAM_DST="/usr/local/lib/pam/pam_sudowhat.so"
SUDO_CONF="/etc/sudo.conf"
SUDOERS_D="/etc/sudoers.d/sudowhat"
PAM_LOCAL="/etc/pam.d/sudo_local"

LEGACY_PLUGIN="/usr/local/libexec/sudo/tsudo_approval.so"
LEGACY_PAM="/usr/local/lib/pam/pam_tsudo.so"
LEGACY_SUDOERS_D="/etc/sudoers.d/tsudo"

rm -f "$PLUGIN_DST" "$PAM_DST" "$LEGACY_PLUGIN" "$LEGACY_PAM"

if [ -f "$SUDO_CONF" ]; then
    # Strip our and the legacy Plugin lines. grep -v with -F to avoid
    # regex pitfalls.
    for label in sudowhat_approval_plugin tsudo_approval_plugin; do
        if grep -qF "$label" "$SUDO_CONF"; then
            tmp="$(mktemp)"
            grep -vF "$label" "$SUDO_CONF" > "$tmp" || true
            cat "$tmp" > "$SUDO_CONF"
            rm -f "$tmp"
        fi
    done
fi

rm -f "$SUDOERS_D" "$LEGACY_SUDOERS_D"
rm -f "$PAM_LOCAL"

echo "sudowhat: uninstalled"
