#!/usr/bin/env bash
#
# Policy-deference spike runner. Builds a throwaway PAM module + driver, installs
# an ISOLATED test PAM service (/etc/pam.d/sudowhat-spike, removed on exit), and
# checks that a setenv() in the auth module is visible to getenv() in the driver
# (same process). This never touches sudo, sudo.conf, /etc/pam.d/sudo, or
# sudo_local, and grants no access — the `sufficient` success applies only to the
# isolated test service. See spike/README.md.
#
# Run from a REAL terminal (needs one sudo to write the test service file):
#   ./spike/run-spike.sh          # zsh/bash
# fish users: bash ./spike/run-spike.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
svc="/etc/pam.d/sudowhat-spike"
mod="${here}/spike_pam.so"
drv="${here}/spike_driver"

echo "== Building spike module + driver =="
clang -bundle -Wl,-undefined,dynamic_lookup "${here}/spike_pam.c" -o "${mod}"
clang "${here}/spike_driver.c" -lpam -o "${drv}"
echo "  built ${mod}"
echo "  built ${drv}"

installed=0
# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
    if [ "${installed}" -eq 1 ]; then
        sudo rm -f "${svc}" && echo "== Removed ${svc} =="
    fi
    rm -f "${mod}" "${drv}"
}
trap cleanup EXIT

echo
echo "== Installing throwaway PAM service ${svc} (needs one sudo) =="
printf 'auth sufficient %s\n' "${mod}" | sudo tee "${svc}" >/dev/null
installed=1
echo "  wrote: auth sufficient ${mod}"

echo
echo "== Running spike =="
set +e
"${drv}"
rc=$?
set -e

echo
if [ "${rc}" -eq 0 ]; then
    echo "Spike PASSED (exit 0). The marker mechanism's same-process assumption holds."
else
    echo "Spike did NOT pass (exit ${rc}). See output above."
fi
exit "${rc}"
