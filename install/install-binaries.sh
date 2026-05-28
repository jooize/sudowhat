#!/bin/bash
# Install only the sudowhat plugin and PAM bundles to /usr/local.
# Does NOT touch /etc — prints the snippets you need to add yourself.
#
# For users who manage /etc declaratively (nix-darwin, home-manager,
# Ansible, Chef) and want the .so bundles in /usr/local while keeping
# /etc under their configuration tool's control.
#
# nix-darwin users with the flake module don't need this — the module
# installs everything from the Nix store and writes /etc declaratively.
#
# Flags:
#   --print   Print the install commands and /etc snippets without
#             running anything. Does not require root.

set -euo pipefail

PRINT_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_ONLY=1 ;;
        *) echo "install-binaries.sh: unknown arg '$arg'" >&2; exit 1 ;;
    esac
done

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_DIR/build/sudowhat_approval.so"
PAM_SRC="$REPO_DIR/build/pam_sudowhat.so"
PLUGIN_DST="/usr/local/libexec/sudo/sudowhat_approval.so"
PAM_DST="/usr/local/lib/pam/pam_sudowhat.so"

if [ ! -f "$PLUGIN_SRC" ] || [ ! -f "$PAM_SRC" ]; then
    echo "install-binaries.sh: build artifacts missing; run 'make sign' first" >&2
    exit 1
fi

print_etc_snippets() {
    cat <<EOF

# Add to /etc/sudo.conf (create the file if missing):

Plugin sudowhat_approval_plugin $PLUGIN_DST

# Write to /etc/sudoers.d/sudowhat (mode 0440):

Defaults timestamp_timeout=0

# Write to /etc/pam.d/sudo_local (mode 0644):

auth    requisite     $PAM_DST
auth    sufficient    pam_permit.so

# Apple's stock /etc/pam.d/sudo already includes sudo_local, so no
# changes to /etc/pam.d/sudo are needed.
EOF
}

if [ "$PRINT_ONLY" -eq 1 ]; then
    cat <<EOF
# Run as root:

install -m 0755 -d /usr/local/libexec/sudo
install -m 0755 -d /usr/local/lib/pam
install -m 0755 '$PLUGIN_SRC' '$PLUGIN_DST'
install -m 0755 '$PAM_SRC' '$PAM_DST'
EOF
    print_etc_snippets
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install-binaries.sh: must run as root (or use --print)" >&2
    exit 1
fi

install -m 0755 -d /usr/local/libexec/sudo
install -m 0755 -d /usr/local/lib/pam
install -m 0755 "$PLUGIN_SRC" "$PLUGIN_DST"
install -m 0755 "$PAM_SRC" "$PAM_DST"

echo "sudowhat: installed binaries to /usr/local"
echo "sudowhat: /etc is unchanged — apply the following yourself:"
print_etc_snippets
