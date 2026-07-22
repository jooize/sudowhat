//! sudowhat audit plugin — Linux (sudo plugin API: SUDO_AUDIT_PLUGIN, type 3).
//!
//! The pure-Rust twin of plugin/sudowhat_audit.m. sudo calls an audit plugin's
//! open() before any other plugin API function — in particular before the policy
//! plugin's check_policy, where PAM collects the password — so this plugin prints
//!
//!   user / directory / command
//!
//! to the controlling terminal FIRST, before sudo's native `pam_unix`
//! `[sudo] password:` prompt. A Linux user then sees the exact command they are
//! about to authorise. No verify code (there is no GUI sheet to channel-bind),
//! no approval plugin, no PAM module — sudo's own authentication is untouched.
//! See docs/design-linux-port.md.
//!
//! ## Trust model (Linux) — documented, not engineered
//!
//! Integrity is sudo's OWN enforcement: sudo refuses to load a plugin, or read
//! /etc/sudo.conf, that is not owned by uid 0 and writable only by its owner
//! (sudo.conf(5)), fail-closed. We add nothing on top. There is NO code-signing
//! anchor and NO tamper-evidence claim here — Linux gets the UX, not the
//! tamper-evidence (docs/design-terminal-mode.md). This plugin is display =
//! disclosure, never authentication: if it is absent or misconfigured it simply
//! shows nothing and can never weaken auth. Accordingly it FAILS SOFT — any
//! problem (no tty, no command, bad UTF-8) means "show nothing", and open()
//! always returns 1 (loaded), never -1 (a display convenience must not DoS sudo).
//!
//! ## Structure
//!
//! This file is the thin FFI shell: it vendors the `struct audit_plugin` layout
//! (plugin/sudo_plugin.h), converts sudo's raw `char * const[]` context arrays
//! into Rust, and delegates. The interesting logic is pure and host-testable in
//! `display.rs` (assemble the block, byte-for-byte identical to the macOS plugin,
//! via escape_core); the /dev/tty write lives in `tty.rs`.

mod display;
mod tty;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_void};

// --- sudo plugin API constants (vendored from plugin/sudo_plugin.h) ----------

const SUDO_AUDIT_PLUGIN: c_uint = 3;
const SUDO_API_VERSION_MAJOR: c_uint = 1;
const SUDO_API_VERSION_MINOR: c_uint = 18;
const SUDO_API_VERSION: c_uint = (SUDO_API_VERSION_MAJOR << 16) | SUDO_API_VERSION_MINOR;

// --- Build-time master switch for terminal display ---------------------------
//
// Chosen by SW_AUDIT_DISPLAY at compile time (set by the Makefile's
// SUDOWHAT_AUDIT_DISPLAY / the nixos module's services.sudowhat.auditDisplay),
// mirroring the macOS bundle's -DSW_AUDIT_DISPLAY. Default on; the only value
// that disables display is "off"; anything else normalises to on (the Makefile /
// nix enum validate the surface, so unknown values do not reach here). Evaluated
// at compile time via option_env!, so no runtime env is consulted — and rustc's
// fingerprint tracks option_env!, so changing the knob triggers a rebuild.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
const AUDIT_DISPLAY_ON: bool = match option_env!("SW_AUDIT_DISPLAY") {
    Some(s) => !str_eq(s, "off"),
    None => true,
};

// Build-time colour policy (SW_AUDIT_ECHO_COLOR: "off" | "anomalies"). Parsed so
// the option surface is stable across platforms, but — exactly as on macOS — the
// anomaly colouriser is a documented fast-follow (the escape_core port of
// colorizeEscaped: is not done yet), so this currently has no effect on output;
// the bold label emphasis is governed independently by display::color_allowed.
// TODO(colorize fast-follow): route escaped bytes through the Rust colouriser
// when ECHO_COLOR_ANOMALIES is set.
#[allow(dead_code)]
const ECHO_COLOR_ANOMALIES: bool = match option_env!("SW_AUDIT_ECHO_COLOR") {
    Some(s) => str_eq(s, "anomalies"),
    None => true, // default anomalies
};

// --- struct audit_plugin (vendored layout, plugin/sudo_plugin.h) -------------
//
// Members are typed as Option<unsafe extern "C" fn …>, so the optional tail is
// None and the whole static holds no raw pointers — it is Sync by construction
// (fn pointers and c_uint are Sync), needing no `unsafe impl Sync`. sudo reads
// these members by offset at API >= 1.15, so the FULL layout must be present;
// the members we do not implement are None, never omitted.

type OpenFn = unsafe extern "C" fn(
    c_uint,               // version
    OpaqueFn,             // conversation
    OpaqueFn,             // plugin_printf
    *const *const c_char, // settings
    *const *const c_char, // user_info
    c_int,                // submit_optind
    *const *const c_char, // submit_argv
    *const *const c_char, // submit_envp
    *const *const c_char, // plugin_options
    *mut *const c_char,   // errstr
) -> c_int;

type CloseFn = unsafe extern "C" fn(c_int, c_int);

type AcceptFn = unsafe extern "C" fn(
    *const c_char,        // plugin_name
    c_uint,               // plugin_type
    *const *const c_char, // command_info
    *const *const c_char, // run_argv
    *const *const c_char, // run_envp
    *mut *const c_char,   // errstr
) -> c_int;

type RejectErrorFn = unsafe extern "C" fn(
    *const c_char,        // plugin_name
    c_uint,               // plugin_type
    *const c_char,        // audit_msg
    *const *const c_char, // command_info
    *mut *const c_char,   // errstr
) -> c_int;

// Opaque function-pointer slots we never call or provide. Every C function
// pointer is the same size, so the exact signature is immaterial for layout;
// these keep the struct honest without pulling in types we do not use.
type OpaqueFn = Option<unsafe extern "C" fn() -> c_int>;
type RegisterHooksFn = unsafe extern "C" fn(c_int, OpaqueFn);
type EventAllocFn = unsafe extern "C" fn() -> *mut c_void;

#[repr(C)]
pub struct AuditPlugin {
    type_: c_uint,
    version: c_uint,
    open: Option<OpenFn>,
    close: Option<CloseFn>,
    accept: Option<AcceptFn>,
    reject: Option<RejectErrorFn>,
    error: Option<RejectErrorFn>,
    show_version: Option<unsafe extern "C" fn(c_int) -> c_int>,
    register_hooks: Option<RegisterHooksFn>,
    deregister_hooks: Option<RegisterHooksFn>,
    event_alloc: Option<EventAllocFn>,
}

// --- context-array helpers ---------------------------------------------------

/// Convert a raw NUL-terminated `char * const[]` (starting at `start`) into owned
/// lossy-UTF-8 Strings. A null array, or `start < 0`, yields an empty vec.
/// Invalid UTF-8 degrades to U+FFFD (like escape_core), never a panic.
///
/// # Safety
/// `arr` must be null or a valid NUL-terminated array of valid C strings.
unsafe fn collect(arr: *const *const c_char, start: c_int) -> Vec<String> {
    let mut v = Vec::new();
    if arr.is_null() || start < 0 {
        return v;
    }
    let mut i = start as isize;
    loop {
        // SAFETY: caller guarantees a NUL-terminated array; we stop at the
        // first null element before dereferencing past the end.
        let p = unsafe { *arr.offset(i) };
        if p.is_null() {
            break;
        }
        // SAFETY: p is a valid C string per the caller's guarantee.
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
        v.push(String::from_utf8_lossy(bytes).into_owned());
        i += 1;
    }
    v
}

// --- plugin API implementation ----------------------------------------------

/// Audit open(): runs before any auth. Returns 1 (loaded) on every path — a
/// display convenience must never abort sudo. Only an unknown API generation
/// declines cleanly (0). Never returns -1.
///
/// # Safety
/// Called by sudo with its documented audit-plugin open() ABI.
unsafe extern "C" fn sudowhat_audit_open(
    version: c_uint,
    _conversation: OpaqueFn,
    _plugin_printf: OpaqueFn,
    settings: *const *const c_char,
    user_info: *const *const c_char,
    submit_optind: c_int,
    submit_argv: *const *const c_char,
    submit_envp: *const *const c_char,
    _plugin_options: *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    // Unknown API generation → decline cleanly (sudo continues without us).
    if (version >> 16) != SUDO_API_VERSION_MAJOR {
        return 0;
    }
    if !AUDIT_DISPLAY_ON {
        return 1;
    }

    // SAFETY: sudo passes NUL-terminated arrays of C strings for these.
    let user_info_v = unsafe { collect(user_info, 0) };
    let user_info_r: Vec<&str> = user_info_v.iter().map(String::as_str).collect();

    // Root exemption, matching the macOS plugin: a uid-0 caller is not
    // escalating, and root contexts generally have no controlling tty anyway.
    // Unclassifiable uid → also no display (fail soft).
    match display::find_kv(&user_info_r, "uid") {
        None => return 1,
        Some(u) => {
            if display::parse_uid(u) == 0 {
                return 1;
            }
        }
    }

    // SAFETY: as above.
    let settings_v = unsafe { collect(settings, 0) };
    let settings_r: Vec<&str> = settings_v.iter().map(String::as_str).collect();

    // The command as typed: submit_argv[submit_optind..].
    // SAFETY: as above; collect() honours submit_optind and the array's NUL.
    let argv_v = unsafe { collect(submit_argv, submit_optind) };
    let argv_r: Vec<&str> = argv_v.iter().map(String::as_str).collect();

    // Colour is cosmetic; reading the (spoofable) envp is safe — the worst a
    // liar gains is the wrong emphasis. tty.rs's isatty() is the final gate.
    // SAFETY: as above.
    let envp_v = unsafe { collect(submit_envp, 0) };
    let envp_r: Vec<&str> = envp_v.iter().map(String::as_str).collect();
    let color = display::color_allowed(&envp_r);

    if let Some(block) = display::build_block(&settings_r, &user_info_r, &argv_r, color) {
        tty::write_tty("/dev/tty", &block);
    }
    1
}

/// close(): open() holds no persistent state, so there is nothing to release.
///
/// # Safety
/// Called by sudo per the audit-plugin ABI.
unsafe extern "C" fn sudowhat_audit_close(_status_type: c_int, _status: c_int) {}

/// accept(): return 1 (success). Wired rather than NULL so it can host the
/// future resolved-path last-look; today it does nothing.
///
/// # Safety
/// Called by sudo per the audit-plugin ABI.
unsafe extern "C" fn sudowhat_audit_accept(
    _plugin_name: *const c_char,
    _plugin_type: c_uint,
    _command_info: *const *const c_char,
    _run_argv: *const *const c_char,
    _run_envp: *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    1
}

/// reject(): return 1 (success).
///
/// # Safety
/// Called by sudo per the audit-plugin ABI.
unsafe extern "C" fn sudowhat_audit_reject(
    _plugin_name: *const c_char,
    _plugin_type: c_uint,
    _audit_msg: *const c_char,
    _command_info: *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    1
}

/// error(): return 1 (success).
///
/// # Safety
/// Called by sudo per the audit-plugin ABI.
unsafe extern "C" fn sudowhat_audit_error(
    _plugin_name: *const c_char,
    _plugin_type: c_uint,
    _audit_msg: *const c_char,
    _command_info: *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    1
}

/// The exported plugin symbol sudo dlsym()s. The optional tail (show_version,
/// register_hooks, deregister_hooks, event_alloc) is None.
#[unsafe(no_mangle)]
pub static sudowhat_audit_plugin: AuditPlugin = AuditPlugin {
    type_: SUDO_AUDIT_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(sudowhat_audit_open),
    close: Some(sudowhat_audit_close),
    accept: Some(sudowhat_audit_accept),
    reject: Some(sudowhat_audit_reject),
    error: Some(sudowhat_audit_error),
    show_version: None,
    register_hooks: None,
    deregister_hooks: None,
    event_alloc: None,
};
