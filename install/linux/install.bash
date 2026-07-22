#!/usr/bin/env bash
# Install the sudowhat Linux audit plugin (terminal command display) to
# /usr/local/libexec/sudo, then PRINT the /etc/sudo.conf you must write.
#
# Linux is DISPLAY-ONLY. There is no biometric, no approval plugin, no PAM
# module, and no code-signing. sudo's own enforcement — it refuses to load a
# plugin, or read sudo.conf, that is not root-owned and writable only by its
# owner (sudo.conf(5)) — is the entire trust model. The plugin fails soft: no
# controlling tty or no command word means it shows nothing, never breaking sudo.
#
# This script deliberately does NOT write /etc/sudo.conf itself: a wrong
# sudo.conf can break every sudo on the box (see the sudoers-plugins note below),
# so it prints the exact file for you to review and install. Mirrors
# install/install-binaries.bash on macOS.
#
# Flags:
#   --print   Print the install commands and the sudo.conf without running
#             anything. Does not require root.

set -euo pipefail

PRINT_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_ONLY=1 ;;
        *) echo "install.bash: unknown arg '$arg'" >&2; exit 1 ;;
    esac
done

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
AUDIT_SRC="$REPO_DIR/linux/sudowhat_audit/target/release/libsudowhat_audit.so"
AUDIT_DST="/usr/local/libexec/sudo/sudowhat_audit.so"

if [ ! -f "$AUDIT_SRC" ]; then
    echo "install.bash: build artifact missing; run 'make build-linux' first" >&2
    echo "  (expected: $AUDIT_SRC)" >&2
    exit 1
fi

print_sudo_conf() {
    cat <<EOF

# Write to /etc/sudo.conf (root-owned, mode 0644; sudo requires it owned by
# uid 0 and writable only by its owner). CRITICAL: adding ANY Plugin line stops
# sudo from auto-loading its default sudoers policy, so the three stock sudoers
# plugins MUST be present too, or sudo loses its policy and every sudo fails.
# Bare 'sudoers.so' resolves relative to sudo's own plugin dir.

Plugin sudoers_policy sudoers.so
Plugin sudoers_io     sudoers.so
Plugin sudoers_audit  sudoers.so
Plugin sudowhat_audit_plugin $AUDIT_DST

# A ready-to-review copy of this file is in config/linux/sudo.conf.sample.
EOF
}

if [ "$PRINT_ONLY" -eq 1 ]; then
    cat <<EOF
# Run as root:

install -m 0755 -d /usr/local/libexec/sudo
install -m 0755 '$AUDIT_SRC' '$AUDIT_DST'
EOF
    print_sudo_conf
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install.bash: must run as root (or use --print)" >&2
    exit 1
fi

install -m 0755 -d /usr/local/libexec/sudo
install -m 0755 "$AUDIT_SRC" "$AUDIT_DST"

echo "sudowhat: installed audit plugin to $AUDIT_DST"
echo "sudowhat: /etc is unchanged — write the following to /etc/sudo.conf yourself:"
print_sudo_conf
