#!/bin/bash
# Install tsudo. Idempotent. Must run as root.
#
# On any failure after a partial change, rolls back so the system is left
# with stock sudo behavior, never half-installed.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_DIR/build/tsudo_approval.so"
PAM_SRC="$REPO_DIR/build/pam_tsudo.so"
PLUGIN_DST="/usr/local/libexec/sudo/tsudo_approval.so"
PAM_DST="/usr/local/lib/pam/pam_tsudo.so"
SUDO_CONF="/etc/sudo.conf"
SUDO_CONF_LINE="Plugin tsudo_approval_plugin /usr/local/libexec/sudo/tsudo_approval.so"
SUDOERS_D="/etc/sudoers.d/tsudo"
PAM_LOCAL="/etc/pam.d/sudo_local"

if [ ! -f "$PLUGIN_SRC" ] || [ ! -f "$PAM_SRC" ]; then
    echo "install.sh: build artifacts missing; run 'make sign' first" >&2
    exit 1
fi

# Track what we changed so we can roll back.
ROLLBACK=()
add_rollback() { ROLLBACK+=("$1"); }
rollback() {
    echo "install.sh: rolling back" >&2
    for ((i=${#ROLLBACK[@]}-1; i>=0; i--)); do
        eval "${ROLLBACK[i]}" || true
    done
}
trap 'rollback' ERR

# (1) Ensure target directories exist.
install -m 0755 -d /usr/local/libexec/sudo
install -m 0755 -d /usr/local/lib/pam

# (2) Install the plugin and PAM module bundles.
[ -f "$PLUGIN_DST" ] || add_rollback "rm -f '$PLUGIN_DST'"
install -m 0755 "$PLUGIN_SRC" "$PLUGIN_DST"

[ -f "$PAM_DST" ] || add_rollback "rm -f '$PAM_DST'"
install -m 0755 "$PAM_SRC" "$PAM_DST"

# (3) sudo.conf: append our Plugin line if missing.
if [ ! -f "$SUDO_CONF" ]; then
    add_rollback "rm -f '$SUDO_CONF'"
    : > "$SUDO_CONF"
    chmod 0644 "$SUDO_CONF"
fi
if ! grep -qF "tsudo_approval_plugin" "$SUDO_CONF"; then
    cp "$SUDO_CONF" "$SUDO_CONF.tsudo-bak"
    add_rollback "mv -f '$SUDO_CONF.tsudo-bak' '$SUDO_CONF'"
    printf '%s\n' "$SUDO_CONF_LINE" >> "$SUDO_CONF"
fi

# (4) sudoers.d entry — validated with visudo before the file is left in place.
if [ ! -f "$SUDOERS_D" ]; then
    add_rollback "rm -f '$SUDOERS_D'"
    install -m 0440 "$REPO_DIR/config/sudoers.d/tsudo.sample" "$SUDOERS_D"
    visudo -c -f "$SUDOERS_D"
fi

# (5) pam.d/sudo_local — Apple's stock /etc/pam.d/sudo includes this file.
if [ ! -f "$PAM_LOCAL" ]; then
    add_rollback "rm -f '$PAM_LOCAL'"
    install -m 0644 "$REPO_DIR/config/pam.d/sudo_local.sample" "$PAM_LOCAL"
fi

# (6) Self-test. Failure here triggers rollback via trap.
"$REPO_DIR/install/self-test.sh"

trap - ERR
echo "tsudo: installed"
