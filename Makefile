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

CC      ?= clang
CFLAGS  = -O2 -g -Wall -Wextra -Wpedantic -fobjc-arc -fPIC \
          -Iplugin -Ipam -Ishared \
          -DSUDOWHAT_TEAM_ID='"$(SUDOWHAT_TEAM_ID)"'
LDFLAGS = -bundle \
          -framework Foundation \
          -framework CoreFoundation \
          -framework Security \
          -framework SystemConfiguration \
          -framework LocalAuthentication

PLUGIN_OBJS = plugin/sudowhat_approval.o \
              plugin/PromptFormatter.o \
              plugin/SignatureVerifier.o \
              plugin/SessionGuard.o

PAM_OBJS    = pam/pam_sudowhat.o \
              pam/SudoConfChecker.o \
              pam/SignatureVerifier.o

.PHONY: all sign install install-force install-binaries print-install-binaries uninstall test test-unit clean

TEST_CFLAGS = $(CFLAGS) -Itests
TEST_FRAMEWORKS = -framework Foundation -framework CoreFoundation \
                  -framework Security -framework SystemConfiguration \
                  -framework LocalAuthentication

all: build/sudowhat_approval.so build/pam_sudowhat.so

build:
	mkdir -p build

build/sudowhat_approval.so: $(PLUGIN_OBJS) | build
	$(CC) $(LDFLAGS) -o $@ $(PLUGIN_OBJS)

build/pam_sudowhat.so: $(PAM_OBJS) | build
	$(CC) $(LDFLAGS) -o $@ $(PAM_OBJS)

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
		plugin/SignatureVerifier.m plugin/SessionGuard.m | build
	$(CC) $(TEST_CFLAGS) $(TEST_FRAMEWORKS) -o $@ \
	    tests/test_plugin_internals.m plugin/PromptFormatter.m \
	    plugin/SignatureVerifier.m plugin/SessionGuard.m

clean:
	rm -rf build $(PLUGIN_OBJS) $(PAM_OBJS)
