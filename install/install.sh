#!/bin/bash
# Install sudowhat. Idempotent. Must run as root.
#
# On any failure after a partial change, rolls back so the system is left
# with stock sudo behavior, never half-installed.
#
# Flags:
#   --force   Bypass the preflight check that refuses to clobber /etc files
#             managed by another configuration manager (e.g. nix-darwin
#             symlinks into /nix/store). Without --force the install aborts
#             with a clear message so the user can decide how to proceed.

set -euo pipefail

FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        *) echo "install.sh: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

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

if [ ! -f "$PLUGIN_SRC" ] || [ ! -f "$PAM_SRC" ]; then
    echo "install.sh: build artifacts missing; run 'make sign' first" >&2
    exit 1
fi

# Preflight: refuse to clobber /etc files that another configuration
# manager owns. Detection is "is the path a symlink whose target is
# inside /nix/store" — that's the nix-darwin signature; same pattern
# would catch other store-based managers if they appear. Without this
# guard, a 'make install' on nix-darwin would silently replace the
# nix-darwin symlink with a regular file, and the next 'darwin-rebuild
# switch' aborts (or worse, the user's nix-darwin config and the
# installed file drift out of sync). --force bypasses for users who
# really mean it.
if [ "$FORCE" -ne 1 ]; then
    CONFLICTS=()
    for path in "$SUDO_CONF" "$SUDOERS_D" "$PAM_LOCAL"; do
        if [ -L "$path" ]; then
            target="$(readlink "$path")"
            case "$target" in
                /nix/store/*) CONFLICTS+=("$path -> $target") ;;
            esac
        fi
    done
    if [ "${#CONFLICTS[@]}" -gt 0 ]; then
        cat >&2 <<EOF
install.sh: refusing to overwrite /etc files managed by another tool.

The following paths are symlinks into /nix/store, which means a
configuration manager (nix-darwin, home-manager, or similar) owns
them. Overwriting them with regular files would break that
ownership and the next rebuild would either revert sudowhat's
changes or abort with a conflict.

EOF
        for c in "${CONFLICTS[@]}"; do
            printf '  %s\n' "$c" >&2
        done
        cat >&2 <<EOF

Options:
  1. Use the nix-darwin module. Add this repo's flake to your
     darwin configuration and set 'services.sudowhat.enable = true;'
     (see README.md and flake.nix). The module installs the .so
     bundles from the Nix store and writes the three /etc files
     declaratively, so there is no conflict to resolve.
  2. Run 'sudo make install-binaries' to install only the .so
     bundles to /usr/local and manage the /etc files yourself
     (or 'make print-install-binaries' to just print the commands
     and snippets without running anything).
  3. Re-run with 'sudo make install-force' to override this check
     and clobber the symlinks anyway. Your configuration manager's
     next rebuild may then conflict or revert the change.
EOF
        exit 1
    fi
fi

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
