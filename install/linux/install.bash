#!/usr/bin/env bash
# Install the sudowhat Linux audit plugin (terminal command display) to
# /usr/local/libexec/sudo, then PRINT the /etc/sudo.conf you must write.
#
# Linux is DISPLAY-ONLY. There is no biometric, no approval plugin, no PAM
# module, and no code-signing. The trust model: sudo perm-checks /etc/sudo.conf
# only — a config not root-owned, or group/other-writable, is ignored,
# fail-closed (sudo.conf(5)). sudo does NOT perm-check the plugin .so; the .so
# is protected by ordinary permissions on its root-owned install path, which
# this script enforces (install -o 0 -g 0, mode 0644) and then verifies with a
# fail-closed permission walk. The plugin fails soft: no controlling tty or no
# command word means it shows nothing, never breaking sudo.
#
# This script deliberately does NOT write /etc/sudo.conf itself: a wrong
# sudo.conf can break every sudo on the box (see the sudoers-plugins note below),
# so it prints the exact file for you to review and install. Mirrors
# install/install-binaries.bash on macOS.
#
# Flags:
#   --print   Print the install commands and the sudo.conf without running
#             anything. Does not require root.
#   --verify  Run only the fail-closed permission walk over the installed
#             path (no install). Does not require root. Exit 1 on violation.

set -euo pipefail

PRINT_ONLY=0
VERIFY_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_ONLY=1 ;;
        --verify) VERIFY_ONLY=1 ;;
        *) echo "install.bash: unknown arg '$arg'" >&2; exit 1 ;;
    esac
done

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
AUDIT_SRC="$REPO_DIR/linux/sudowhat_audit/target/release/libsudowhat_audit.so"
AUDIT_DST="/usr/local/libexec/sudo/sudowhat_audit.so"

if [ "$VERIFY_ONLY" -eq 0 ] && [ ! -f "$AUDIT_SRC" ]; then
    echo "install.bash: build artifact missing; run 'make build-linux' first" >&2
    echo "  (expected: $AUDIT_SRC)" >&2
    exit 1
fi

print_sudo_conf() {
    cat <<EOF

# Write to /etc/sudo.conf (root-owned, mode 0644; sudo IGNORES a sudo.conf not
# owned by uid 0 or writable by group/other). CRITICAL: adding ANY Plugin line stops
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

# Fail-closed verification of the .so's protection: sudo does NOT perm-check
# the plugin .so, so the install path's ordinary permissions are the whole
# defence. Walk every directory from /usr/local down to the .so and assert
# root-owned with no group/other write; exit 1 naming the offender.
verify_perms() {
    local path fail=0
    for path in /usr/local /usr/local/libexec /usr/local/libexec/sudo "$AUDIT_DST"; do
        local st
        # stat -c: uid, group-write bit (0/1 via %A parsing is fragile; use octal)
        st="$(stat -c '%u %a' -- "$path" 2>/dev/null)" || {
            echo "install.bash: FAIL: cannot stat $path" >&2
            fail=1
            continue
        }
        local uid="${st%% *}" mode="${st#* }"
        if [ "$uid" -ne 0 ]; then
            echo "install.bash: FAIL: $path is owned by uid $uid, not root — sudo does not perm-check the plugin .so, so this path MUST be root-owned" >&2
            fail=1
        fi
        # group (second-to-last octal digit) or other (last) write bit set?
        local grp="${mode: -2:1}" oth="${mode: -1:1}"
        if [ $((grp & 2)) -ne 0 ] || [ $((oth & 2)) -ne 0 ]; then
            echo "install.bash: FAIL: $path is group/other-writable (mode $mode) — anyone with that write bit can replace the plugin" >&2
            fail=1
        fi
    done
    if [ "$fail" -ne 0 ]; then
        echo "install.bash: plugin path verification FAILED — fix the permissions above before adding the plugin to /etc/sudo.conf" >&2
        exit 1
    fi
    echo "sudowhat: verified root-owned, non-writable path to $AUDIT_DST"
}

if [ "$VERIFY_ONLY" -eq 1 ]; then
    if [ ! -f "$AUDIT_DST" ]; then
        echo "install.bash: nothing installed at $AUDIT_DST" >&2
        exit 1
    fi
    verify_perms
    exit 0
fi

if [ "$PRINT_ONLY" -eq 1 ]; then
    cat <<EOF
# Run as root:

install -m 0755 -o 0 -g 0 -d /usr/local/libexec/sudo
install -m 0644 -o 0 -g 0 '$AUDIT_SRC' '$AUDIT_DST'
chown 0:0 '$AUDIT_DST'
chmod 0644 '$AUDIT_DST'

# Then verify the whole path is root-owned and not group/other-writable
# (sudo does NOT perm-check the plugin .so — these perms are the defence):
stat -c '%A %u %n' /usr/local /usr/local/libexec /usr/local/libexec/sudo '$AUDIT_DST'
EOF
    print_sudo_conf
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install.bash: must run as root (or use --print)" >&2
    exit 1
fi

install -m 0755 -o 0 -g 0 -d /usr/local/libexec/sudo
# 0644 suffices: dlopen only needs read. Belt and braces after install(1):
# re-assert owner and mode explicitly, then verify the whole path fail-closed.
install -m 0644 -o 0 -g 0 "$AUDIT_SRC" "$AUDIT_DST"
chown 0:0 "$AUDIT_DST"
chmod 0644 "$AUDIT_DST"
verify_perms

echo "sudowhat: installed audit plugin to $AUDIT_DST"
echo "sudowhat: /etc is unchanged — write the following to /etc/sudo.conf yourself:"
print_sudo_conf
