#!/usr/bin/env bash
# test_deploy.bash - the screen nix/bin/deploy shows before it asks.
#
# Runs the real script against a scratch git repo and a scratch flake, so
# nothing outside a mktemp dir is read or written. A stub `sudo` sits first
# on PATH: if a case ever answered yes by mistake, the stub refuses instead
# of reaching the real one.
#
# The question itself needs a terminal (deploy refuses without one), so that
# case runs under script(1) and skips by name where no pty can be opened (a
# sandboxed runner). Prints one TAP 14 stream, like the test binaries
# (tests/sw_test.h), and exits non-zero if any point failed.
set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="${here}/../nix/bin/deploy"

N=0 PASS=0 FAIL=0 SKIP=0
SKIPPED=()
printf 'TAP version 14\n'
point() { # <ok|not ok> <name> [directive]
  N=$((N + 1))
  if [[ $# -ge 3 ]]; then
    printf '%s %d - %s # %s\n' "$1" "${N}" "$2" "$3"
  else
    printf '%s %d - %s\n' "$1" "${N}" "$2"
  fi
}
ok() { # <name> <command...>
  local name="$1"
  shift
  if "$@"; then
    PASS=$((PASS + 1)); point ok "${name}"
  else
    FAIL=$((FAIL + 1)); point 'not ok' "${name}"
  fi
}
skip() { # <name> <reason>
  SKIP=$((SKIP + 1)); SKIPPED+=("$1 ($2)")
  point ok "$1" "skip $2"
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/sw-test-deploy.XXXXXX")"
trap 'rm -rf -- "${tmp}"' EXIT

# A scratch git repo with one release tag, isolated from every git config.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
repo="${tmp}/repo"
mkdir -p -- "${repo}/nix"
printf '{ version = "1.2.3"; }\n' >"${repo}/nix/package.nix"
git -C "${repo}" init -q
git -C "${repo}" add nix/package.nix
git -C "${repo}" commit -q -m release
git -C "${repo}" tag v1.2.3
rev="$(git -C "${repo}" rev-parse HEAD)"

# The flake path holds a space, so a row that ends with it shows it whole.
flake_dir="${tmp}/sys flake"
mkdir -p -- "${flake_dir}"
export NIX_DARWIN_FLAKE="${flake_dir}/flake.nix"
old_rev=0123456789abcdef0123456789abcdef01234567
printf '  sudowhat.url = "git+file:///x/sudowhat?ref=refs/tags/v1.2.2&rev=%s";\n' \
  "${old_rev}" >"${NIX_DARWIN_FLAKE}"

stub="${tmp}/stub"
mkdir -p -- "${stub}"
printf '#!/bin/sh\necho "stub sudo: refusing $*" >&2\nexit 99\n' >"${stub}/sudo"
chmod 755 -- "${stub}/sudo"
export PATH="${stub}:${PATH}"

line_of() { # <file> <label>: the first line that starts with <label>
  grep -m1 -- "^$2" "$1" || true
}
ends_with() { [[ "$1" == *"$2" ]]; }
lacks() { [[ "$1" != *"$2"* ]]; }

# --- the header rows, in a dry run -------------------------------------------
out="${tmp}/dry.out"
rc=0
(cd -- "${repo}" && /bin/bash "${DEPLOY}" --dry-run) >"${out}" 2>&1 || rc=$?
ok "a dry run exits 0" test "${rc}" -eq 0
target="$(line_of "${out}" 'Target:')"
ok "the target row leads with the rev" ends_with "${target%  v1.2.3}" "${rev:0:10}"
ok "the target row ends with the tag" ends_with "${target}" "  v1.2.3"
head_row="$(line_of "${out}" 'HEAD:')"
ok "the HEAD row names no tag" lacks "${head_row}" "v1.2.3"
ok "the HEAD row says it sits at the target" ends_with "${head_row}" "(at the target)"
pinned="$(line_of "${out}" 'Pinned:')"
ok "the pinned row ends with the ref" ends_with "${pinned}" "  ref=refs/tags/v1.2.2"
ok "the pinned row leaves the flake path out" lacks "${pinned}" "${flake_dir}"
flake_row="$(line_of "${out}" 'Flake:')"
ok "the flake path ends a row of its own" test "${flake_row}" = "Flake:   ${NIX_DARWIN_FLAKE}"
ok "no label announces the command lines" lacks "$(cat -- "${out}")" "Will run as root"

# --- the question ------------------------------------------------------------
# Off a terminal there is nobody to ask: exit 2, and no question is printed.
rc=0
(cd -- "${repo}" && /bin/bash "${DEPLOY}") </dev/null >"${out}" 2>&1 || rc=$?
ok "off a terminal it declines with exit 2" test "${rc}" -eq 2
ok "off a terminal it prints no question" lacks "$(cat -- "${out}")" "[y/N]"
# A refusal prints no rows: neither the header nor the command lines.
ok "off a terminal it prints no header row" lacks "$(cat -- "${out}")" "HEAD:"
ok "off a terminal it prints no command line" lacks "$(cat -- "${out}")" "  sudo "

# The question's only arguments are colour variables, so no value can reach
# it. Checked on the source, which every runner can read.
only_colours() { # <the printf's argument line>
  # The $ in the pattern is literal: it matches "$C_X" in the source.
  # shellcheck disable=SC2016
  [[ -n "$1" ]] &&
    test -z "$(printf '%s\n' "$1" | tr ' ' '\n' | grep -vE '^("\$C_[A-Z]+")?$')"
}
q_args="$(grep -A1 -F "run the lines above? [" "${DEPLOY}" | tail -n1 || true)"
ok "the question's printf takes only colour arguments" only_colours "${q_args}"

# On a terminal: answer n, then read the question line back. The line starts
# with the question; after it the terminal may show the echoed answer, or the
# decline line when the typed-ahead answer was echoed before the question.
QUESTION="run the lines above? [y/N] "
DECLINE="aborted; flake pin unchanged"
bare_question() { # <the line holding [y/N]>
  [[ "$1" == "${QUESTION}"* ]] || return 1
  case "${1#"${QUESTION}"}" in
    ''|n|"${DECLINE}") return 0 ;;
  esac
  return 1
}
pty_ok=0
script -q /dev/null /usr/bin/true </dev/null >/dev/null 2>&1 && pty_ok=1
if (( pty_ok )); then
  rc=0
  (cd -- "${repo}" && printf 'n\n' | script -q /dev/null /bin/bash "${DEPLOY}") \
    >"${out}" 2>&1 || rc=$?
  plain="$(sed -e $'s/\033\\[[0-9;]*m//g' -e $'s/\r$//' -- "${out}")"
  q="$(printf '%s\n' "${plain}" | grep -F '[y/N]' || true)"
  ok "on a terminal the question is asked" test -n "${q}"
  ok "the question line holds no value" bare_question "${q}"
  ok "an n answer aborts" lacks "${plain}" "stub sudo"
  ok "and says so in the decline shape" grep -qF -- "${DECLINE}" <<<"${plain}"
  ok "and the flake keeps its pin" grep -qF "rev=${old_rev}" "${NIX_DARWIN_FLAKE}"

  # An answer that is not one is not acted on: one "not an answer" line,
  # the question again, and the next answer decides.
  (cd -- "${repo}" && printf 'x\nn\n' | script -q /dev/null /bin/bash "${DEPLOY}") \
    >"${out}" 2>&1 || true
  plain="$(sed -e $'s/\033\\[[0-9;]*m//g' -e $'s/\r$//' -- "${out}")"
  ok "an unknown answer says it is not one" grep -qx 'not an answer' <<<"${plain}"
  ok "and asks again" test "$(grep -cF '[y/N]' <<<"${plain}")" -eq 2
  ok "then the n declines" grep -qF -- "${DECLINE}" <<<"${plain}"

  # NO_COLOR keeps every escape byte off the terminal.
  (cd -- "${repo}" && printf 'n\n' | NO_COLOR=1 script -q /dev/null /bin/bash "${DEPLOY}") \
    >"${out}" 2>&1 || true
  ok "NO_COLOR prints no escape byte" lacks "$(cat -- "${out}")" $'\033'
else
  for name in "on a terminal the question is asked" \
              "the question line holds no value" \
              "an n answer aborts" "and says so in the decline shape" \
              "and the flake keeps its pin" "an unknown answer says it is not one" \
              "and asks again" "then the n declines" "NO_COLOR prints no escape byte"; do
    skip "${name}" "no pty here (script cannot open one; a sandboxed runner?)"
  done
fi

printf '1..%d\n' "${N}"
printf '# test_deploy (nix/bin/deploy screen): %d passed, %d failed, %d skipped, 0 todo\n' \
  "${PASS}" "${FAIL}" "${SKIP}"
if (( ${#SKIPPED[@]} > 0 )); then
  for s in "${SKIPPED[@]}"; do
    printf '#   skipped: %s\n' "${s}"
  done
fi
(( FAIL == 0 ))
