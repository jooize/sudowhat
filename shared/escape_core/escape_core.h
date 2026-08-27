/*
 * escape_core.h — C ABI for the Rust escape/display core (shared/escape_core).
 *
 * Hand-written (no cbindgen) so the header is reviewed and the build stays
 * deterministic. Must stay in sync with the #[no_mangle] signatures in
 * src/lib.rs. The audit bundle (plugin/sudowhat_audit.m) is the only in-tree
 * caller; tests/test_escape_core.m links the same functions to assert they
 * escape byte-for-byte identically to the ObjC SudoWhatPromptFormatter.
 *
 * Buffer contract (every function below):
 *   - *needed is ALWAYS set to the full output length in bytes (excluding the
 *     NUL terminator).
 *   - If out != NULL and out_cap >= *needed + 1: the output plus a trailing NUL
 *     is written and SW_ESCAPE_OK is returned.
 *   - Otherwise nothing is written and SW_ESCAPE_TRUNCATED is returned; the
 *     caller may allocate *needed + 1 bytes and call again.
 *   Probe for the size by calling once with out=NULL, out_cap=0.
 *
 * Invalid UTF-8 in the input is replaced with U+FFFD, never rejected: a display
 * path degrades to a visible replacement glyph rather than hiding the command.
 */

#ifndef SUDOWHAT_ESCAPE_CORE_H
#define SUDOWHAT_ESCAPE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SW_ESCAPE_OK        0
#define SW_ESCAPE_TRUNCATED 1

/* Escape control / homoglyph / bidi / zero-width characters to visible \xNN /
 * \uNNNN text. */
int sw_escape_control(const uint8_t *input, size_t input_len,
                      uint8_t *out, size_t out_cap, size_t *needed);

/* Shell-quote (and escape) a single token. */
int sw_quote_token(const uint8_t *input, size_t input_len,
                   uint8_t *out, size_t out_cap, size_t *needed);

/* Full, untruncated command line: quoted path + argv, dropping argv[0] when it
 * duplicates the path or its basename. argv[i] is argv_lens[i] bytes long;
 * pass argv=NULL (or argv_count=0) for a path-only line. */
int sw_full_command_line(const uint8_t *path, size_t path_len,
                         const uint8_t *const *argv,
                         const size_t *argv_lens, size_t argv_count,
                         uint8_t *out, size_t out_cap, size_t *needed);

/* The same line as sw_full_command_line, with SGR colour layered on by role:
 * the program's directory part plain cyan and its basename bold cyan, option
 * flags bold blue, every other token plain, the quotes the renderer itself
 * added dim, and anomalous spans (deceptive Unicode, control-byte escapes,
 * shell metacharacters, notable whitespace runs) in the fixed anomaly palette
 * on top. The flag mark is openly lexical (a rendered token starting with '-'),
 * so it colours every flag alike rather than guessing which one matters, and a
 * token that needed quoting renders '...' and never borrows the look.
 * Still ONE logical line - nothing is wrapped, elided or
 * reordered - and the colour is purely additive: strip the SGR and the bytes are
 * exactly sw_full_command_line's.
 *
 * This is the approval plugin's execute: line, the resolved command.
 *
 * Identical parameters and buffer contract. The caller decides whether colour is
 * permitted at all (build-time knob plus the NO_COLOR / TERM / isatty gates) and
 * MUST fall back to sw_full_command_line on anything but SW_ESCAPE_OK - a
 * display tool degrades to the plain line, never to showing nothing. */
int sw_full_command_line_colored(const uint8_t *path, size_t path_len,
                                 const uint8_t *const *argv,
                                 const size_t *argv_lens, size_t argv_count,
                                 uint8_t *out, size_t out_cap, size_t *needed);

/* The same line again, rendered by the same walk with a flat dim base: every
 * routine token - program dirname, program basename, flags, values - takes dim
 * instead of its role colour, while the anomaly spans keep the full-strength
 * palette above. Identical parameters and buffer contract, and the same
 * round-trip invariant: strip the SGR and the bytes are sw_full_command_line's.
 *
 * The audit plugin's input: line uses this one, so the pre-resolution line
 * reads quiet under the resolved execute: line and its anomaly spans pop
 * harder against the dim base. The caller MUST fall back to
 * sw_full_command_line on anything but SW_ESCAPE_OK, exactly as above. */
int sw_full_command_line_colored_dim(const uint8_t *path, size_t path_len,
                                     const uint8_t *const *argv,
                                     const size_t *argv_lens, size_t argv_count,
                                     uint8_t *out, size_t out_cap,
                                     size_t *needed);

#ifdef __cplusplus
}
#endif

#endif /* SUDOWHAT_ESCAPE_CORE_H */
