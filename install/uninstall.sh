#!/bin/bash
# Uninstall tsudo. Idempotent. Must run as root.
#
# Removes the two bundles, the sudo.conf Plugin line, the sudoers.d snippet,
# and the pam.d/sudo_local file. Leaves any pre-existing /etc/sudo.conf in
# place (only our line is removed).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: must run as root" >&2
    exit 1
fi

PLUGIN_DST="/usr/local/libexec/sudo/tsudo_approval.so"
PAM_DST="/usr/local/lib/pam/pam_tsudo.so"
SUDO_CONF="/etc/sudo.conf"
SUDOERS_D="/etc/sudoers.d/tsudo"
PAM_LOCAL="/etc/pam.d/sudo_local"

rm -f "$PLUGIN_DST" "$PAM_DST"

if [ -f "$SUDO_CONF" ]; then
    # Strip our exact Plugin line. grep -v with -F to avoid regex pitfalls.
    if grep -qF "tsudo_approval_plugin" "$SUDO_CONF"; then
        tmp="$(mktemp)"
        grep -vF "tsudo_approval_plugin" "$SUDO_CONF" > "$tmp" || true
        cat "$tmp" > "$SUDO_CONF"
        rm -f "$tmp"
    fi
fi

rm -f "$SUDOERS_D"
rm -f "$PAM_LOCAL"

echo "tsudo: uninstalled"
