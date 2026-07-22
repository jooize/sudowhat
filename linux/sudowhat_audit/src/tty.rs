//! tty.rs — write a pre-assembled block to the controlling terminal, and ONLY
//! there. A direct Rust port of `sw_audit_write_tty` in plugin/sudowhat_audit.m:
//! open /dev/tty with `O_WRONLY | O_NOCTTY | O_CLOEXEC`, gate on `isatty()`, and
//! never fall back to stderr (the tty-only-signals invariant — a captured
//! `2>file` must never receive a possibly-confidential command).
//!
//! The libc calls are hand-declared here rather than pulled from the `libc`
//! crate so this crate keeps ZERO external dependencies (matching escape_core's
//! offline/reproducible ethos). `std` is available, so errno is read via
//! `std::io::Error::last_os_error()` — no `__errno_location` shim needed.

use std::ffi::CString;
use std::io::Error;
use std::os::raw::{c_char, c_int};

// EINTR is 4 on both Linux and Darwin.
const EINTR: c_int = 4;

// open() O_* flags, declared per target. Linux uses the asm-generic <asm/fcntl.h>
// values shared by x86, x86_64, arm, aarch64, riscv, loongarch, powerpc, s390x
// and every other arch that did not override the generic header. The Darwin
// values are provided too so this file compiles and links on the macOS dev host
// (where the artifact is a .dylib used only to validate the ABI, never shipped).
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
mod oflags {
    use std::os::raw::c_int;
    pub const O_WRONLY: c_int = 0o1;
    pub const O_NOCTTY: c_int = 0o400; // asm-generic 00000400
    pub const O_CLOEXEC: c_int = 0o2000000; // asm-generic 02000000
}

// A few Linux arches (mips*, sparc*) give O_NOCTTY / O_CLOEXEC different bit
// values in their own <asm/fcntl.h>. Refuse to compile there rather than open
// the tty with wrong flags (which could, e.g., fail to set close-on-exec).
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    )
))]
compile_error!(
    "sudowhat_audit: O_NOCTTY/O_CLOEXEC differ from the asm-generic values on \
     this Linux arch (mips*/sparc*); add its <asm/fcntl.h> constants to \
     src/tty.rs before building for it."
);

#[cfg(target_os = "macos")]
mod oflags {
    use std::os::raw::c_int;
    pub const O_WRONLY: c_int = 0x0001;
    pub const O_NOCTTY: c_int = 0x20000;
    pub const O_CLOEXEC: c_int = 0x1000000;
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("sudowhat_audit: unsupported target OS (needs Linux, or macOS to build the ABI check)");

use oflags::{O_CLOEXEC, O_NOCTTY, O_WRONLY};

// Minimal libc surface. `open` is variadic in C (`int open(const char *, int,
// ...)`), but the trailing mode argument is only consulted when O_CREAT is set,
// which we never set — so the 2-argument declaration is correct and portable on
// the calling conventions we target.
unsafe extern "C" {
    fn open(path: *const c_char, oflag: c_int) -> c_int;
    fn write(fd: c_int, buf: *const u8, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn isatty(fd: c_int) -> c_int;
}

/// Write `block` to `tty_path` (always "/dev/tty" in production). The bytes are
/// already escape_core-escaped, so they carry no raw control byte regardless of
/// what the user typed. Fails soft in every direction: an empty block, a path
/// with an interior NUL, no controlling terminal, a non-tty target, or any
/// write error all mean "write nothing" — never a panic, never a crash of sudo.
pub fn write_tty(tty_path: &str, block: &str) {
    let bytes = block.as_bytes();
    if bytes.is_empty() {
        return;
    }
    // An interior NUL cannot be a real tty path; refuse rather than truncate.
    let cpath = match CString::new(tty_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // O_NOCTTY: never acquire a controlling terminal as a side effect.
    // O_CLOEXEC: never leak the fd into the exec'd target.
    // SAFETY: cpath is a valid NUL-terminated C string; no O_CREAT, so open()
    // needs no mode argument.
    let fd = unsafe { open(cpath.as_ptr(), O_WRONLY | O_NOCTTY | O_CLOEXEC) };
    if fd < 0 {
        return;
    }

    // Only ever write an actual terminal. isatty() != 1 → close and bail.
    // SAFETY: fd is a descriptor we just opened and own.
    if unsafe { isatty(fd) } != 1 {
        // SAFETY: fd is valid and owned.
        unsafe { close(fd) };
        return;
    }

    let total = bytes.len();
    let mut off = 0usize;
    while off < total {
        // SAFETY: bytes[off..] is in bounds; we ask to write at most the
        // remaining length starting at that offset.
        let w = unsafe { write(fd, bytes.as_ptr().add(off), total - off) };
        if w < 0 {
            if Error::last_os_error().raw_os_error() == Some(EINTR) {
                continue; // interrupted before any byte moved — retry
            }
            break; // any other error: stop, fail soft
        }
        if w == 0 {
            break; // no progress; avoid spinning
        }
        off += w as usize;
    }

    // SAFETY: fd is valid and owned; nothing else touches it after this.
    unsafe { close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_block_is_noop() {
        // Returns before opening anything; must not touch /dev/tty.
        write_tty("/dev/tty", "");
    }

    #[test]
    fn non_tty_target_writes_nothing() {
        // /dev/null opens fine but isatty() is false → nothing written, no panic.
        write_tty("/dev/null", "sudowhat: test\n");
    }

    #[test]
    fn nonexistent_path_is_silent() {
        // open() fails → silent return, no panic.
        write_tty("/nonexistent/sudowhat/tty", "sudowhat: test\n");
    }

    #[test]
    fn interior_nul_is_rejected() {
        write_tty("/dev/t\0ty", "sudowhat: test\n");
    }
}
