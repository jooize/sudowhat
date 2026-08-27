#!/usr/bin/env bash
# Verify the built Linux audit plugin .so is loadable by sudo AND fully
# hardened. Regression guard for the v0.11.0-v0.14.0 load fault: sudo writes
# event_alloc into the plugin's exported struct after dlopen
# (load_plugins.c, API >= 1.17), so the `sudowhat_audit_plugin` object must
# live in writable .data. A plain Rust `pub static` lands in .data.rel.ro,
# which the loader seals read-only (GNU_RELRO) before sudo's write — sudo
# then SIGSEGVs on EVERY invocation. lib.rs forces writable placement via an
# UnsafeCell wrapper; this script asserts the artifact actually got it, in
# BOTH build pipelines (make in a Debian container, nix), so a toolchain or
# flag divergence fails closed instead of shipping a sudo-breaking .so.
#
# Asserts:
#   1. GNU_RELRO segment present (full RELRO hardening intact)
#   2. DF_BIND_NOW / DF_1_NOW present (eager binding; RELRO is effective)
#   3. sudowhat_audit_plugin lies OUTSIDE every GNU_RELRO range (writable)
#
# No TLS-reloc assertion: the 2026-08 diagnosis showed the artifact's
# R_*_TLSDESC entries are resolved eagerly during dlopen and were never the
# crash mechanism (a plain dlopen driver loads the .so clean).
#
# Usage: verify-plugin-so.bash <path-to-libsudowhat_audit.so>
# Exit:  0 all assertions hold; 1 usage/missing input; 2 verification failed.
# Arch-agnostic: parses readelf field positions common to aarch64/x86_64.

set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob

if [ "$#" -ne 1 ] || [ "${1#-}" != "$1" ]; then
    echo "usage: verify-plugin-so.bash <path-to-libsudowhat_audit.so>" >&2
    exit 1
fi
SO="$1"

if [[ ! -f "$SO" ]]; then
    echo "verify-plugin-so: no such file: $SO" >&2
    exit 1
fi
if ! command -v readelf >/dev/null 2>&1; then
    echo "verify-plugin-so: readelf not found (install binutils)" >&2
    exit 1
fi

fail=0

# Capture each readelf view once; piping readelf straight into an
# early-exiting consumer (grep -q, awk exit) dies of SIGPIPE under pipefail.
segments="$(readelf -lW -- "$SO")"
dynamic="$(readelf -dW -- "$SO")"
symbols="$(readelf -sW -- "$SO")"

# --- 1. GNU_RELRO present ----------------------------------------------------
# readelf -lW row: GNU_RELRO <Offset> <VirtAddr> <PhysAddr> <FileSiz> <MemSiz> ...
relro_rows="$(awk '$1 == "GNU_RELRO" {print $3, $6}' <<< "$segments")"
if [[ -z "$relro_rows" ]]; then
    echo "verify-plugin-so: FAIL: no GNU_RELRO segment (hardening lost)" >&2
    fail=1
fi

# --- 2. eager binding flagged ------------------------------------------------
if ! grep -Eq '\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*\bNOW\b' <<< "$dynamic"; then
    echo "verify-plugin-so: FAIL: no DF_BIND_NOW/DF_1_NOW (lazy binding; RELRO ineffective)" >&2
    fail=1
fi

# --- 3. exported plugin struct outside GNU_RELRO -----------------------------
# readelf -sW row: <Num>: <Value> <Size> <Type> <Bind> <Vis> <Ndx> <Name>
sym_addr="$(awk '$8 == "sudowhat_audit_plugin" && $4 == "OBJECT" && !found {print $2; found=1}' <<< "$symbols")"
if [[ -z "$sym_addr" ]]; then
    echo "verify-plugin-so: FAIL: exported symbol sudowhat_audit_plugin not found" >&2
    fail=1
elif [[ -n "$relro_rows" ]]; then
    sym=$((16#${sym_addr#0x}))
    while IFS=' ' read -r vaddr memsiz; do
        lo=$((16#${vaddr#0x}))
        hi=$((lo + 16#${memsiz#0x}))
        if (( sym >= lo && sym < hi )); then
            printf 'verify-plugin-so: FAIL: sudowhat_audit_plugin (0x%x) inside GNU_RELRO [0x%x, 0x%x) — sealed read-only; sudo writes event_alloc into it after dlopen and would SIGSEGV\n' \
                "$sym" "$lo" "$hi" >&2
            fail=1
        fi
    done <<< "$relro_rows"
fi

if (( fail )); then
    echo "verify-plugin-so: $SO FAILED verification" >&2
    exit 2
fi
echo "verify-plugin-so: $SO ok (GNU_RELRO + BIND_NOW + writable plugin struct)"
