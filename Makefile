# sudowhat
#
# Builds two ad-hoc-signable Mach-O bundles:
#   build/sudowhat_approval.so    - sudo approval plugin (LAContext / AS prompt)
#   build/pam_sudowhat.so         - PAM auth module (integrity check)
#
# Release build (Developer ID, enforces team-ID requirement):
#   make SUDOWHAT_TEAM_ID=XXXXXXXXXX DEVELOPER_NAME="Your Name" sign
#
# Dev build (ad-hoc, signature-integrity only - default):
#   make sign

SUDOWHAT_TEAM_ID ?= -

# Build-time master switch for terminal command display via the audit plugin:
# "on" (default - show user/directory/input on the controlling terminal before
# the password prompt / Touch ID sheet, on every path) or "off" (never display).
# The
# nix module exposes the same names via services.sudowhat.auditDisplay. Passed as
# a bare token to -DSW_AUDIT_DISPLAY (audit bundle only). An unknown value
# normalizes to "on" with a warning, rather than failing.
SUDOWHAT_AUDIT_DISPLAY ?= on
SUDOWHAT_VALID_AUDIT_DISPLAY := on off
ifeq ($(filter $(SUDOWHAT_AUDIT_DISPLAY),$(SUDOWHAT_VALID_AUDIT_DISPLAY)),)
  $(warning sudowhat: unknown SUDOWHAT_AUDIT_DISPLAY '$(SUDOWHAT_AUDIT_DISPLAY)', falling back to on)
  override SUDOWHAT_AUDIT_DISPLAY := on
endif

# Build-time policy for colouring the terminal command display: "on"
# (default) or "off". The nix module exposes the same names via
# services.sudowhat.echoColor. Passed as a bare token to -DSW_ECHO_COLOR in the
# GLOBAL CFLAGS below, because it governs BOTH command values - the audit
# bundle's `input:` and the approval bundle's `execute:`. They are one display to
# a reader, so one token settles both; each bundle carries its own copy of the
# token machinery (separate Mach-O images, no shared translation unit). Under
# "on" the command line is highlighted by role
# (program dirname plain cyan, basename bold cyan, option flags dim, values
# plain) with deceptive Unicode / control-byte escapes, shell metacharacters and
# notable whitespace in a fixed reviewed palette on top - sudowhat's threat
# model. It stays ONE line: the SGR goes around the already-escaped tokens, so
# stripping it returns the plain line byte for byte, and the isatty / NO_COLOR /
# TERM=dumb gates keep it off non-terminals. An unknown value normalizes to
# "on" with a warning, rather than failing.
SUDOWHAT_ECHO_COLOR ?= on
SUDOWHAT_VALID_ECHO_COLOR := off on
ifeq ($(filter $(SUDOWHAT_ECHO_COLOR),$(SUDOWHAT_VALID_ECHO_COLOR)),)
  $(warning sudowhat: unknown SUDOWHAT_ECHO_COLOR '$(SUDOWHAT_ECHO_COLOR)', falling back to on)
  override SUDOWHAT_ECHO_COLOR := on
endif

# Master switch for policy deference: "on" (default) skips the console user's
# Touch ID prompt when sudoers itself waived authentication for the invocation
# (a NOPASSWD rule, Defaults !authenticate, or a valid timestamp cache), so a
# NOPASSWD command just runs; "off" always prompts, as before the feature. The
# nix module exposes the same names via services.sudowhat.policyDeference. Passed
# as a bare token to -DSW_POLICY_DEFERENCE. An unknown value normalizes to "on"
# with a warning, rather than failing.
SUDOWHAT_POLICY_DEFERENCE ?= on
SUDOWHAT_VALID_DEFERENCE := on off
ifeq ($(filter $(SUDOWHAT_POLICY_DEFERENCE),$(SUDOWHAT_VALID_DEFERENCE)),)
  $(warning sudowhat: unknown SUDOWHAT_POLICY_DEFERENCE '$(SUDOWHAT_POLICY_DEFERENCE)', falling back to on)
  override SUDOWHAT_POLICY_DEFERENCE := on
endif

# Master switch for the post-resolution run confirmation: "off" (default) prints
# the resolved `execute:` line on the terminal-password path and allows, a
# last-look before exec; "on" additionally asks one `run? [y/N]` there via sudo's
# conversation API, so the decision completes after the resolved path is visible
# -- the same guarantee biometric mode gives. Tty-gated either way, so a piped or
# automated invocation behaves identically with it on or off, and asked only when
# sudo actually ran the PAM auth stack for that invocation, so a NOPASSWD caller
# is never re-gated. The nix module
# exposes the same names via services.sudowhat.execConfirm. Passed as a bare
# token to -DSW_EXEC_CONFIRM. An unknown value normalizes to "off" with a
# warning, rather than failing.
SUDOWHAT_EXEC_CONFIRM ?= off
SUDOWHAT_VALID_EXEC_CONFIRM := on off
ifeq ($(filter $(SUDOWHAT_EXEC_CONFIRM),$(SUDOWHAT_VALID_EXEC_CONFIRM)),)
  $(warning sudowhat: unknown SUDOWHAT_EXEC_CONFIRM '$(SUDOWHAT_EXEC_CONFIRM)', falling back to off)
  override SUDOWHAT_EXEC_CONFIRM := off
endif

# Build-time master switch for the informational `execute:` echo (the resolved
# command line the approval plugin prints): "on" (default - print it on the root
# bypass, the non-console step-aside last-look, the policy-deference skip and
# the console biometric pre-sheet) or "off" (print none of them; the bundle
# loads and gates exactly as before). It is a DISPLAY knob and pairs with
# SUDOWHAT_AUDIT_DISPLAY -- one per line family -- so it fails toward disclosure
# the same way: an unknown value normalizes to "on" with a warning, rather than
# failing. The nix module exposes the same names via services.sudowhat.
# execDisplay. Passed as a bare token to -DSW_EXEC_DISPLAY (approval bundle
# only, the sole consumer). Note "off" does NOT silence the confirm ceremony's
# own copy of the line under SUDOWHAT_EXEC_CONFIRM=on -- see the SW_EXEC_DISPLAY
# comment in plugin/sudowhat_approval.m.
SUDOWHAT_EXEC_DISPLAY ?= on
SUDOWHAT_VALID_EXEC_DISPLAY := on off
ifeq ($(filter $(SUDOWHAT_EXEC_DISPLAY),$(SUDOWHAT_VALID_EXEC_DISPLAY)),)
  $(warning sudowhat: unknown SUDOWHAT_EXEC_DISPLAY '$(SUDOWHAT_EXEC_DISPLAY)', falling back to on)
  override SUDOWHAT_EXEC_DISPLAY := on
endif

CC      ?= clang
CFLAGS  = -O2 -g -Wall -Wextra -Wpedantic -fobjc-arc -fPIC \
          -Iplugin -Ipam -Ishared -Ishared/escape_core \
          -DSUDOWHAT_TEAM_ID='"$(SUDOWHAT_TEAM_ID)"' \
          -DSW_ECHO_COLOR=$(SUDOWHAT_ECHO_COLOR) \
          -DSW_POLICY_DEFERENCE=$(SUDOWHAT_POLICY_DEFERENCE) \
          -DSW_EXEC_CONFIRM=$(SUDOWHAT_EXEC_CONFIRM)
LDFLAGS = -bundle \
          -framework Foundation \
          -framework CoreFoundation \
          -framework Security \
          -framework SystemConfiguration \
          -framework LocalAuthentication

# The audit bundle is a lean ObjC shell + Rust staticlib: Foundation (strings,
# NSFileManager) and Security (code-signature check). No LocalAuthentication (no
# biometrics) and no SystemConfiguration (no SessionGuard — display is
# unconditional). The Rust staticlib links in as a plain archive.
AUDIT_LDFLAGS = -bundle \
                -framework Foundation \
                -framework CoreFoundation \
                -framework Security

# Rust escape/display core (shared/escape_core). No external dependencies, so it
# builds offline and reproducibly. CARGO_HOME defaults to a project-local dir so
# the build stays inside the sandbox / Nix build tree; an ambient CARGO_HOME (a
# dev machine, Nix) is respected when set.
ESCAPE_CORE_DIR = shared/escape_core
ESCAPE_CORE_LIB = $(ESCAPE_CORE_DIR)/target/release/libescape_core.a
CARGO ?= cargo

# SignatureVerifier is one shared source (shared/SignatureVerifier.m) compiled
# once per bundle with a distinct class name baked in via -DSW_SIGVERIFIER_CLASS
# (see shared/SignatureVerifier.h). The two objects must stay separate so each
# bundle registers its own class and sudo can load both without an Objective-C
# duplicate-class collision.
PLUGIN_OBJS = plugin/sudowhat_approval.o \
              plugin/PromptFormatter.o \
              build/plugin_SignatureVerifier.o \
              build/plugin_SessionGuard.o

PAM_OBJS    = pam/pam_sudowhat.o \
              pam/SudoConfChecker.o \
              build/pam_SignatureVerifier.o \
              build/pam_SessionGuard.o

# The audit bundle: its ObjC shell + a per-target SignatureVerifier (third class
# name). No SessionGuard (display is unconditional). The Rust staticlib is a
# separate link input, not an object.
AUDIT_OBJS  = plugin/sudowhat_audit.o \
              build/audit_SignatureVerifier.o

.PHONY: all sign install install-force install-binaries print-install-binaries uninstall test test-unit clean \
        build-linux test-linux install-linux uninstall-linux

TEST_CFLAGS = $(CFLAGS) -Itests
TEST_FRAMEWORKS = -framework Foundation -framework CoreFoundation \
                  -framework Security -framework SystemConfiguration \
                  -framework LocalAuthentication

all: build/sudowhat_approval.so build/pam_sudowhat.so build/sudowhat_audit.so

build:
	mkdir -p build

# Rust escape/display core. --locked pins to the committed Cargo.lock; --offline
# forbids any network fetch (the crate has no dependencies, so both always hold).
$(ESCAPE_CORE_LIB): $(ESCAPE_CORE_DIR)/src/lib.rs $(ESCAPE_CORE_DIR)/Cargo.toml \
		$(ESCAPE_CORE_DIR)/Cargo.lock
	cd $(ESCAPE_CORE_DIR) && \
	    CARGO_HOME=$${CARGO_HOME:-$(CURDIR)/.cargo-home} \
	    $(CARGO) build --release --offline --locked

# Per-bundle class name for the shared SignatureVerifier. Target-specific
# CFLAGS propagate to every prerequisite object, so the bundle's caller
# (sudowhat_approval.o / pam_sudowhat.o) sees the same -D when it includes
# SignatureVerifier.h - without it the header's #error guard fails the build.
#
# The approval bundle also gets the one display knob that is genuinely its own
# (execDisplay - only this bundle prints the resolved execute: line), the mirror
# of what auditDisplay is to the audit bundle below.
build/sudowhat_approval.so: CFLAGS += -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier \
                                      -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard \
                                      -DSW_EXEC_DISPLAY=$(SUDOWHAT_EXEC_DISPLAY)
build/pam_sudowhat.so:      CFLAGS += -DSW_SIGVERIFIER_CLASS=SudoWhatPamSigVerifier \
                                      -DSW_SESSIONGUARD_CLASS=SudoWhatPamSessionGuard
# The audit bundle gets the third SignatureVerifier class name plus the one
# display knob that is genuinely its own (auditDisplay - only this bundle draws
# the pre-auth block). echoColor is NOT here: it governs both bundles' command
# values, so it lives in the global CFLAGS above. Target-specific CFLAGS
# propagate to prerequisites, so plugin/sudowhat_audit.o and
# build/audit_SignatureVerifier.o both see these.
build/sudowhat_audit.so:    CFLAGS += -DSW_SIGVERIFIER_CLASS=SudoWhatAuditSigVerifier \
                                      -DSW_AUDIT_DISPLAY=$(SUDOWHAT_AUDIT_DISPLAY)

# The approval bundle links the Rust staticlib too: its `execute:` line renders
# the resolved command through the same escape core the audit bundle uses, so the
# two plugins cannot disagree on how a token is spelled. Each bundle gets its own
# copy of the archive (they are separate Mach-O images), which is the same
# deliberate duplication as the per-bundle SignatureVerifier class.
build/sudowhat_approval.so: $(PLUGIN_OBJS) $(ESCAPE_CORE_LIB) | build
	$(CC) $(LDFLAGS) -o $@ $(PLUGIN_OBJS) $(ESCAPE_CORE_LIB)

# The audit bundle links the Rust staticlib (a plain archive) after its objects.
build/sudowhat_audit.so: $(AUDIT_OBJS) $(ESCAPE_CORE_LIB) | build
	$(CC) $(AUDIT_LDFLAGS) -o $@ $(AUDIT_OBJS) $(ESCAPE_CORE_LIB)

# -undefined dynamic_lookup: the PAM module calls back into the host's PAM
# library (pam_get_user, …). Those symbols are provided by sudo (the PAM host)
# at load time, so leave them undefined at link and bind them at dlopen — this
# also avoids statically binding to nixpkgs' openpam libpam, which would risk
# operating on a pam_handle_t the host created with a different PAM at runtime.
build/pam_sudowhat.so: $(PAM_OBJS) | build
	$(CC) $(LDFLAGS) -Wl,-undefined,dynamic_lookup -o $@ $(PAM_OBJS)

# Two objects from one source, each with its own class name. The explicit -D
# here keeps these rules correct even when built directly (not via a .so).
build/plugin_SignatureVerifier.o: shared/SignatureVerifier.m shared/SignatureVerifier.h shared/Constants.h | build
	$(CC) $(CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier -c shared/SignatureVerifier.m -o $@

build/pam_SignatureVerifier.o: shared/SignatureVerifier.m shared/SignatureVerifier.h shared/Constants.h | build
	$(CC) $(CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatPamSigVerifier -c shared/SignatureVerifier.m -o $@

build/audit_SignatureVerifier.o: shared/SignatureVerifier.m shared/SignatureVerifier.h shared/Constants.h | build
	$(CC) $(CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatAuditSigVerifier -c shared/SignatureVerifier.m -o $@

# SessionGuard is one shared source compiled once per bundle with a distinct
# class name (same rationale as SignatureVerifier above): both bundles load
# into the same sudo process. The plugin's console guard and the PAM
# console-gate therefore run identical session logic from one source.
build/plugin_SessionGuard.o: shared/SessionGuard.m shared/SessionGuard.h shared/Constants.h | build
	$(CC) $(CFLAGS) -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard -c shared/SessionGuard.m -o $@

build/pam_SessionGuard.o: shared/SessionGuard.m shared/SessionGuard.h shared/Constants.h | build
	$(CC) $(CFLAGS) -DSW_SESSIONGUARD_CLASS=SudoWhatPamSessionGuard -c shared/SessionGuard.m -o $@

%.o: %.m
	$(CC) $(CFLAGS) -c $< -o $@

sign: all
	@if [ "$(SUDOWHAT_TEAM_ID)" = "-" ]; then \
		echo "ad-hoc signing build/*.so (dev mode)"; \
		codesign --force --sign - build/sudowhat_approval.so build/pam_sudowhat.so build/sudowhat_audit.so; \
	else \
		if [ -z "$$DEVELOPER_NAME" ]; then \
			echo "DEVELOPER_NAME must be set for release builds" >&2; \
			exit 1; \
		fi; \
		echo "Developer ID signing as team $(SUDOWHAT_TEAM_ID)"; \
		codesign --force --options runtime \
		    --sign "Developer ID Application: $$DEVELOPER_NAME ($(SUDOWHAT_TEAM_ID))" \
		    build/sudowhat_approval.so build/pam_sudowhat.so build/sudowhat_audit.so; \
	fi

install: sign
	./install/install.bash

# install-force: bypass the preflight that refuses to clobber /etc files
# owned by another configuration manager (e.g. nix-darwin symlinks into
# /nix/store). Use only when you know the override is what you want.
install-force: sign
	./install/install.bash --force

# install-binaries: install only the .so bundles to /usr/local; leaves
# /etc alone and prints the snippets the user must add themselves. For
# users managing /etc declaratively (nix-darwin, home-manager, Ansible).
install-binaries: sign
	./install/install-binaries.bash

# print-install-binaries: print the install-binaries commands and /etc
# snippets without running anything. Does not require root.
print-install-binaries: all
	./install/install-binaries.bash --print

uninstall:
	./install/uninstall.bash

test: install
	./install/self-test.bash

# test-unit: offline unit tests for the pure helpers (no root, no install).
# Builds standalone test executables and runs them; non-zero exit on failure.
# test_escape_core is the cross-language guard: it links the Rust staticlib and
# asserts it escapes byte-identically to the ObjC PromptFormatter.
test-unit: build/test_prompt_formatter build/test_plugin_internals \
		build/test_escape_core build/test_audit_internals
	@build/test_prompt_formatter
	@build/test_plugin_internals
	@build/test_escape_core
	@build/test_audit_internals

build/test_prompt_formatter: tests/test_prompt_formatter.m tests/sw_test.h \
		plugin/PromptFormatter.m plugin/PromptFormatter.h | build
	$(CC) $(TEST_CFLAGS) -framework Foundation -o $@ \
	    tests/test_prompt_formatter.m plugin/PromptFormatter.m

# Links the Rust escape_core staticlib (so the C-ABI functions are callable) plus
# PromptFormatter (the ObjC reference) and compares their output byte-for-byte.
build/test_escape_core: tests/test_escape_core.m tests/sw_test.h \
		plugin/PromptFormatter.m plugin/PromptFormatter.h \
		$(ESCAPE_CORE_DIR)/escape_core.h $(ESCAPE_CORE_LIB) | build
	$(CC) $(TEST_CFLAGS) -framework Foundation -o $@ \
	    tests/test_escape_core.m plugin/PromptFormatter.m $(ESCAPE_CORE_LIB)

# Includes plugin/sudowhat_approval.m directly to reach its static helpers, so
# that file is compiled into the binary - do NOT also pass it as a source. Links
# the Rust staticlib because the approval plugin now renders its `execute:` line
# through escape_core, exactly as the bundle does.
build/test_plugin_internals: tests/test_plugin_internals.m tests/sw_test.h \
		plugin/sudowhat_approval.m plugin/PromptFormatter.m \
		shared/SignatureVerifier.m shared/SessionGuard.m \
		$(ESCAPE_CORE_DIR)/escape_core.h $(ESCAPE_CORE_LIB) | build
	$(CC) $(TEST_CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier \
	    -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard \
	    $(TEST_FRAMEWORKS) -o $@ \
	    tests/test_plugin_internals.m plugin/PromptFormatter.m \
	    shared/SignatureVerifier.m shared/SessionGuard.m \
	    $(ESCAPE_CORE_LIB)

# Includes plugin/sudowhat_audit.m directly to reach its static helpers, so that
# file is compiled into the binary - do NOT also pass it as a source. Its own
# binary rather than part of test_plugin_internals: the two plugins cannot share
# a translation unit (each has a file-static find_kv, and each needs a different
# -DSW_SIGVERIFIER_CLASS). Links the Rust staticlib, where the colouriser lives.
build/test_audit_internals: tests/test_audit_internals.m tests/sw_test.h \
		plugin/sudowhat_audit.m shared/SignatureVerifier.m \
		$(ESCAPE_CORE_DIR)/escape_core.h $(ESCAPE_CORE_LIB) | build
	$(CC) $(TEST_CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatAuditSigVerifier \
	    -framework Foundation -framework CoreFoundation -framework Security \
	    -o $@ tests/test_audit_internals.m shared/SignatureVerifier.m \
	    $(ESCAPE_CORE_LIB)

# --- Linux port (Phase 2): terminal command display via a pure-Rust audit
# plugin (linux/sudowhat_audit, a cdylib reusing shared/escape_core). Every
# target here is guarded by `uname -s` so a macOS `make` never runs them and the
# macOS build above is byte-for-byte unchanged. On Linux they build / test /
# install the single display-only .so (no approval plugin, no PAM module, no
# code-signing — see docs/design-linux-port.md).
UNAME_S := $(shell uname -s)
LINUX_AUDIT_DIR = linux/sudowhat_audit

# build-linux: compile the cdylib with the same display knobs the macOS bundle
# takes (SUDOWHAT_AUDIT_DISPLAY / SUDOWHAT_ECHO_COLOR, validated above). --locked
# pins the committed Cargo.lock; --offline forbids any network fetch (both crates
# have no dependencies, so both always hold).
build-linux:
ifeq ($(UNAME_S),Linux)
	cd $(LINUX_AUDIT_DIR) && \
	    CARGO_HOME=$${CARGO_HOME:-$(CURDIR)/.cargo-home} \
	    SW_AUDIT_DISPLAY=$(SUDOWHAT_AUDIT_DISPLAY) \
	    SW_AUDIT_ECHO_COLOR=$(SUDOWHAT_ECHO_COLOR) \
	    $(CARGO) build --release --offline --locked
else
	@echo "build-linux: skipped (host is $(UNAME_S), not Linux)"
endif

# test-linux: the pure display.rs / tty.rs unit tests. They are host-portable
# (cargo builds a test executable, not the cdylib), but this target is
# Linux-guarded for consistency; on the macOS dev host run them directly with
# `cd $(LINUX_AUDIT_DIR) && cargo test`.
test-linux:
ifeq ($(UNAME_S),Linux)
	cd $(LINUX_AUDIT_DIR) && \
	    CARGO_HOME=$${CARGO_HOME:-$(CURDIR)/.cargo-home} \
	    $(CARGO) test --offline --locked
else
	@echo "test-linux: skipped (host is $(UNAME_S), not Linux)"
endif

# install-linux: build then install the .so to /usr/local and PRINT the
# /etc/sudo.conf to write (install/linux/install.bash does not touch /etc itself).
install-linux: build-linux
ifeq ($(UNAME_S),Linux)
	./install/linux/install.bash
else
	@echo "install-linux: skipped (host is $(UNAME_S), not Linux)"
endif

uninstall-linux:
ifeq ($(UNAME_S),Linux)
	./install/linux/uninstall.bash
else
	@echo "uninstall-linux: skipped (host is $(UNAME_S), not Linux)"
endif

clean:
	rm -rf build $(PLUGIN_OBJS) $(PAM_OBJS) $(AUDIT_OBJS)
	rm -rf $(ESCAPE_CORE_DIR)/target .cargo-home
	rm -rf $(LINUX_AUDIT_DIR)/target
