#!/bin/bash
# Install sudowhat. Idempotent. Must run as root.
#
# On any failure after a partial change, rolls back so the system is left
# with stock sudo behavior, never half-installed.
#
# Removes any leftover files from the project's prior name (tsudo) before
# installing under the new name, so users upgrading from <= v0.2.0 do not
# end up with both sets of bundles or a stale Plugin line in /etc/sudo.conf.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_DIR/build/sudowhat_approval.so"
PAM_SRC="$REPO_DIR/build/pam_sudowhat.so"
PLUGIN_DST="/usr/local/libexec/sudo/sudowhat_approval.so"
PAM_DST="/usr/local/lib/pam/pam_sudowhat.so"
SUDO_CONF="/etc/sudo.conf"
SUDO_CONF_LINE="Plugin sudowhat_approval_plugin /usr/local/libexec/sudo/sudowhat_approval.so"
SUDOERS_D="/etc/sudoers.d/sudowhat"
PAM_LOCAL="/etc/pam.d/sudo_local"

# Pre-rename artifacts the project used to install under the "tsudo" brand.
# Removed unconditionally before this run touches anything (no rollback for
# legacy cleanup; if you had v0.2.0 working, the next legitimate install
# replaces it anyway).
LEGACY_PLUGIN="/usr/local/libexec/sudo/tsudo_approval.so"
LEGACY_PAM="/usr/local/lib/pam/pam_tsudo.so"
LEGACY_SUDOERS_D="/etc/sudoers.d/tsudo"
LEGACY_PLUGIN_LABEL="tsudo_approval_plugin"

if [ ! -f "$PLUGIN_SRC" ] || [ ! -f "$PAM_SRC" ]; then
    echo "install.sh: build artifacts missing; run 'make sign' first" >&2
    exit 1
fi

# --- Legacy cleanup (pre-rename tsudo_* artifacts) ---------------------------
rm -f "$LEGACY_PLUGIN" "$LEGACY_PAM" "$LEGACY_SUDOERS_D"
if [ -f "$SUDO_CONF" ] && grep -qF "$LEGACY_PLUGIN_LABEL" "$SUDO_CONF"; then
    tmp="$(mktemp)"
    grep -vF "$LEGACY_PLUGIN_LABEL" "$SUDO_CONF" > "$tmp" || true
    cat "$tmp" > "$SUDO_CONF"
    rm -f "$tmp"
fi

# --- New install (tracked for rollback) -------------------------------------
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
if ! grep -qF "sudowhat_approval_plugin" "$SUDO_CONF"; then
    cp "$SUDO_CONF" "$SUDO_CONF.sudowhat-bak"
    add_rollback "mv -f '$SUDO_CONF.sudowhat-bak' '$SUDO_CONF'"
    printf '%s\n' "$SUDO_CONF_LINE" >> "$SUDO_CONF"
fi

# (4) sudoers.d entry — validated with visudo before the file is left in
# place. Always overwrite: this file is ours, idempotent reinstalls should
# refresh it with current content.
if [ -f "$SUDOERS_D" ]; then
    cp "$SUDOERS_D" "$SUDOERS_D.sudowhat-bak"
    add_rollback "mv -f '$SUDOERS_D.sudowhat-bak' '$SUDOERS_D'"
else
    add_rollback "rm -f '$SUDOERS_D'"
fi
install -m 0440 "$REPO_DIR/config/sudoers.d/sudowhat.sample" "$SUDOERS_D"
visudo -c -f "$SUDOERS_D"

# (5) pam.d/sudo_local — Apple's stock /etc/pam.d/sudo includes this file.
# Always overwrite: a stale or recovery-stub sudo_local would leave sudo
# in a permissive or broken state, so this file must reflect our current
# fail-closed config.
if [ -f "$PAM_LOCAL" ]; then
    cp "$PAM_LOCAL" "$PAM_LOCAL.sudowhat-bak"
    add_rollback "mv -f '$PAM_LOCAL.sudowhat-bak' '$PAM_LOCAL'"
else
    add_rollback "rm -f '$PAM_LOCAL'"
fi
install -m 0644 "$REPO_DIR/config/pam.d/sudo_local.sample" "$PAM_LOCAL"

# (6) Self-test. Failure here triggers rollback via trap.
"$REPO_DIR/install/self-test.sh"

trap - ERR
echo "sudowhat: installed"
