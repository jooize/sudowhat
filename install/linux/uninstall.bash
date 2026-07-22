#!/usr/bin/env bash
# Uninstall the sudowhat Linux audit plugin. Idempotent. Must run as root.
#
# IMPORTANT ORDER: remove the audit Plugin line from /etc/sudo.conf BEFORE the
# .so, or sudo may error trying to load a plugin that no longer exists. sudo.conf
# is not written by install.bash (see install/linux/install.bash), so this script
# does not rewrite it either — it removes only our .so and tells you exactly what
# to take out of sudo.conf. Leave the three stock `sudoers.so` lines in place
# (removing every Plugin line is fine too — sudo then auto-loads sudoers again).
#
# Flags:
#   --print   Print what would be done without running anything. Not root-gated.

set -euo pipefail

PRINT_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_ONLY=1 ;;
        *) echo "uninstall.bash: unknown arg '$arg'" >&2; exit 1 ;;
    esac
done

AUDIT_DST="/usr/local/libexec/sudo/sudowhat_audit.so"

print_sudo_conf_note() {
    cat <<EOF

# First remove this line from /etc/sudo.conf (if present):

Plugin sudowhat_audit_plugin $AUDIT_DST

# Keep the three 'Plugin sudoers_* sudoers.so' lines, OR remove every Plugin
# line so sudo auto-loads its default sudoers policy again. Then remove the .so.
EOF
}

if [ "$PRINT_ONLY" -eq 1 ]; then
    print_sudo_conf_note
    echo ""
    echo "# Run as root:"
    echo "rm -f '$AUDIT_DST'"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.bash: must run as root (or use --print)" >&2
    exit 1
fi

if [ -f "/etc/sudo.conf" ] && grep -qF "sudowhat_audit_plugin" "/etc/sudo.conf"; then
    echo "uninstall.bash: WARNING — /etc/sudo.conf still references the audit plugin." >&2
    echo "  Remove the 'Plugin sudowhat_audit_plugin ...' line BEFORE relying on sudo." >&2
    print_sudo_conf_note >&2
fi

rm -f "$AUDIT_DST"
echo "sudowhat: removed $AUDIT_DST"
