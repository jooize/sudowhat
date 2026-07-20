#!/bin/bash
# Uninstall sudowhat. Idempotent. Must run as root.
#
# Removes the three bundles, both sudo.conf Plugin lines, the sudoers.d snippet,
# and the pam.d/sudo_local file. Leaves any pre-existing /etc/sudo.conf in
# place (only our lines are removed).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: must run as root" >&2
    exit 1
fi

PLUGIN_DST="/usr/local/libexec/sudo/sudowhat_approval.so"
AUDIT_DST="/usr/local/libexec/sudo/sudowhat_audit.so"
PAM_DST="/usr/local/lib/pam/pam_sudowhat.so"
SUDO_CONF="/etc/sudo.conf"
SUDOERS_D="/etc/sudoers.d/sudowhat"
PAM_LOCAL="/etc/pam.d/sudo_local"

rm -f "$PLUGIN_DST" "$AUDIT_DST" "$PAM_DST"

if [ -f "$SUDO_CONF" ]; then
    if grep -qE "sudowhat_(approval|audit)_plugin" "$SUDO_CONF"; then
        tmp="$(mktemp)"
        grep -vE "sudowhat_(approval|audit)_plugin" "$SUDO_CONF" > "$tmp" || true
        cat "$tmp" > "$SUDO_CONF"
        rm -f "$tmp"
    fi
fi

rm -f "$SUDOERS_D"
rm -f "$PAM_LOCAL"

echo "sudowhat: uninstalled"
