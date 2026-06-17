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

# Build-time emphasis preset for the verify-code tty echo. One of a fixed set of
# named styles (the nix module exposes the same names via
# services.sudowhat.verifyStyle). Passed as a bare token to -DSW_VERIFY_STYLE,
# where the plugin maps it to a reviewed SGR sequence. An unknown value
# normalizes to bold — the safe, theme-independent baseline — with a warning,
# rather than failing the build.
SUDOWHAT_VERIFY_STYLE ?= bold
SUDOWHAT_VALID_STYLES := plain bold red green yellow blue magenta cyan random
ifeq ($(filter $(SUDOWHAT_VERIFY_STYLE),$(SUDOWHAT_VALID_STYLES)),)
  $(warning sudowhat: unknown SUDOWHAT_VERIFY_STYLE '$(SUDOWHAT_VERIFY_STYLE)', falling back to bold)
  override SUDOWHAT_VERIFY_STYLE := bold
endif

CC      ?= clang
CFLAGS  = -O2 -g -Wall -Wextra -Wpedantic -fobjc-arc -fPIC \
          -Iplugin -Ipam -Ishared \
          -DSUDOWHAT_TEAM_ID='"$(SUDOWHAT_TEAM_ID)"' \
          -DSW_VERIFY_STYLE=$(SUDOWHAT_VERIFY_STYLE)
LDFLAGS = -bundle \
          -framework Foundation \
          -framework CoreFoundation \
          -framework Security \
          -framework SystemConfiguration \
          -framework LocalAuthentication

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

.PHONY: all sign install install-force install-binaries print-install-binaries uninstall test test-unit clean

TEST_CFLAGS = $(CFLAGS) -Itests
TEST_FRAMEWORKS = -framework Foundation -framework CoreFoundation \
                  -framework Security -framework SystemConfiguration \
                  -framework LocalAuthentication

all: build/sudowhat_approval.so build/pam_sudowhat.so

build:
	mkdir -p build

# Per-bundle class name for the shared SignatureVerifier. Target-specific
# CFLAGS propagate to every prerequisite object, so the bundle's caller
# (sudowhat_approval.o / pam_sudowhat.o) sees the same -D when it includes
# SignatureVerifier.h - without it the header's #error guard fails the build.
build/sudowhat_approval.so: CFLAGS += -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier \
                                      -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard
build/pam_sudowhat.so:      CFLAGS += -DSW_SIGVERIFIER_CLASS=SudoWhatPamSigVerifier \
                                      -DSW_SESSIONGUARD_CLASS=SudoWhatPamSessionGuard

build/sudowhat_approval.so: $(PLUGIN_OBJS) | build
	$(CC) $(LDFLAGS) -o $@ $(PLUGIN_OBJS)

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
		codesign --force --sign - build/sudowhat_approval.so build/pam_sudowhat.so; \
	else \
		if [ -z "$$DEVELOPER_NAME" ]; then \
			echo "DEVELOPER_NAME must be set for release builds" >&2; \
			exit 1; \
		fi; \
		echo "Developer ID signing as team $(SUDOWHAT_TEAM_ID)"; \
		codesign --force --options runtime \
		    --sign "Developer ID Application: $$DEVELOPER_NAME ($(SUDOWHAT_TEAM_ID))" \
		    build/sudowhat_approval.so build/pam_sudowhat.so; \
	fi

install: sign
	./install/install.sh

# install-force: bypass the preflight that refuses to clobber /etc files
# owned by another configuration manager (e.g. nix-darwin symlinks into
# /nix/store). Use only when you know the override is what you want.
install-force: sign
	./install/install.sh --force

# install-binaries: install only the .so bundles to /usr/local; leaves
# /etc alone and prints the snippets the user must add themselves. For
# users managing /etc declaratively (nix-darwin, home-manager, Ansible).
install-binaries: sign
	./install/install-binaries.sh

# print-install-binaries: print the install-binaries commands and /etc
# snippets without running anything. Does not require root.
print-install-binaries: all
	./install/install-binaries.sh --print

uninstall:
	./install/uninstall.sh

test: install
	./install/self-test.sh

# test-unit: offline unit tests for the pure helpers (no root, no install).
# Builds standalone test executables and runs them; non-zero exit on failure.
test-unit: build/test_prompt_formatter build/test_plugin_internals
	@build/test_prompt_formatter
	@build/test_plugin_internals

build/test_prompt_formatter: tests/test_prompt_formatter.m tests/sw_test.h \
		plugin/PromptFormatter.m plugin/PromptFormatter.h | build
	$(CC) $(TEST_CFLAGS) -framework Foundation -o $@ \
	    tests/test_prompt_formatter.m plugin/PromptFormatter.m

# Includes plugin/sudowhat_approval.m directly to reach its static helpers, so
# that file is compiled into the binary - do NOT also pass it as a source.
build/test_plugin_internals: tests/test_plugin_internals.m tests/sw_test.h \
		plugin/sudowhat_approval.m plugin/PromptFormatter.m \
		shared/SignatureVerifier.m shared/SessionGuard.m | build
	$(CC) $(TEST_CFLAGS) -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier \
	    -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard \
	    $(TEST_FRAMEWORKS) -o $@ \
	    tests/test_plugin_internals.m plugin/PromptFormatter.m \
	    shared/SignatureVerifier.m shared/SessionGuard.m

clean:
	rm -rf build $(PLUGIN_OBJS) $(PAM_OBJS)
