{
  lib,
  stdenv,
  darwin,
  apple-sdk_15,
  darwinMinVersionHook,
  openpam,
  # cargo + rustc build the escape_core staticlib (the audit plugin's memory-safe
  # escape/display core). The crate has no dependencies, so the build is offline
  # and reproducible — no registry fetch, no vendoring, no crane needed.
  cargo,
  rustc,
  teamId ? "-",
  # Emphasis preset for the verify-code tty echo. One of the names in the
  # Makefile's SUDOWHAT_VALID_STYLES; the nix module validates this with an
  # enum, so an out-of-set value is caught at eval time rather than reaching
  # the Makefile's bold fallback. See services.sudowhat.verifyStyle.
  verifyStyle ? "bold",
  # Colouring of the audit plugin's terminal command display: "anomalies"
  # (default) or "off". One of the Makefile's SUDOWHAT_VALID_ECHO_COLOR;
  # validated by the nix module's enum. See services.sudowhat.echoColor.
  echoColor ? "anomalies",
  # Master switch for policy deference: "on" (default) or "off". One of the
  # Makefile's SUDOWHAT_VALID_DEFERENCE; validated by the nix module's enum.
  # See services.sudowhat.policyDeference.
  policyDeference ? "on",
  # Master switch for terminal command display via the audit plugin: "on"
  # (default) or "off". One of the Makefile's SUDOWHAT_VALID_AUDIT_DISPLAY;
  # validated by the nix module's enum. See services.sudowhat.auditDisplay.
  auditDisplay ? "on",
  # Master switch for the informational resolved-command echo via the approval
  # plugin: "on" (default) or "off". One of the Makefile's
  # SUDOWHAT_VALID_EXEC_DISPLAY; validated by the nix module's enum. macOS only
  # (the approval plugin does not exist in the Linux port).
  # See services.sudowhat.execDisplay.
  execDisplay ? "on",
  # Master switch for the post-resolution run confirmation on the
  # terminal-password path: "off" (default) or "on". One of the Makefile's
  # SUDOWHAT_VALID_EXEC_CONFIRM; validated by the nix module's enum. macOS only
  # (the approval plugin does not exist in the Linux port).
  # See services.sudowhat.execConfirm.
  execConfirm ? "off",
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "sudowhat";
  version = "0.13.0";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ darwin.sigtool cargo rustc ];

  # Modern nixpkgs ships unified apple-sdk packages instead of per-framework
  # derivations. SDK 15 + a 15.0 deployment-target hook are needed for
  # LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion (the
  # iPhone-as-companion variant introduced in macOS 15) which the plugin
  # requests by name. Without the hook, nixpkgs's default deployment target
  # is below 15.0 and clang refuses the symbol under -Werror=unguarded-
  # availability-new.
  buildInputs = [
    apple-sdk_15
    (darwinMinVersionHook "15.0")
    # apple-sdk_15 ships /usr/include but strips the OpenPAM headers
    # (<security/pam_appl.h> etc.) that the PAM module needs. nixpkgs
    # ships them as openpam, which provides the same interface Apple's
    # PAM module API is built on.
    openpam
  ];

  # The two .so bundles each embed the *other's* expected install path at
  # compile time (for mutual signature verification). Rewrite the defaults
  # in Constants.h so the binaries point at their own $out store paths
  # instead of /usr/local. Constants.h has #ifndef guards but going through
  # -DSUDOWHAT_PLUGIN_PATH=... requires shell-escaping nested quotes through
  # make recipes, which is fragile; substituteInPlace is the readable path.
  postPatch = ''
    substituteInPlace shared/Constants.h \
      --replace-fail '/usr/local/libexec/sudo/sudowhat_approval.so' \
                     "$out/libexec/sudo/sudowhat_approval.so" \
      --replace-fail '/usr/local/lib/pam/pam_sudowhat.so' \
                     "$out/lib/pam/pam_sudowhat.so" \
      --replace-fail '/usr/local/libexec/sudo/sudowhat_audit.so' \
                     "$out/libexec/sudo/sudowhat_audit.so"
  '';

  makeFlags = [
    "SUDOWHAT_TEAM_ID=${teamId}"
    "SUDOWHAT_VERIFY_STYLE=${verifyStyle}"
    "SUDOWHAT_ECHO_COLOR=${echoColor}"
    "SUDOWHAT_POLICY_DEFERENCE=${policyDeference}"
    "SUDOWHAT_AUDIT_DISPLAY=${auditDisplay}"
    "SUDOWHAT_EXEC_DISPLAY=${execDisplay}"
    "SUDOWHAT_EXEC_CONFIRM=${execConfirm}"
  ];

  buildPhase = ''
    runHook preBuild
    # A writable, isolated CARGO_HOME inside the sandbox (nix's HOME is not
    # writable). The escape_core build is offline with a pinned Cargo.lock, so
    # nothing is fetched — this only needs to be somewhere cargo may scribble.
    export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
    # 'make sign' builds all three bundles (the Rust staticlib + the audit /
    # approval / pam Mach-O bundles), then ad-hoc-signs them via codesign, which
    # darwin.sigtool provides as a sandbox-safe shim.
    make $makeFlags sign
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -m 0755 -d $out/libexec/sudo $out/lib/pam
    install -m 0755 build/sudowhat_approval.so $out/libexec/sudo/sudowhat_approval.so
    install -m 0755 build/sudowhat_audit.so    $out/libexec/sudo/sudowhat_audit.so
    install -m 0755 build/pam_sudowhat.so      $out/lib/pam/pam_sudowhat.so
    runHook postInstall
  '';

  meta = {
    description = "Sudo approval plugin for macOS that shows the exact command in the Touch ID prompt";
    homepage = "https://github.com/jooize/sudowhat";
    license = lib.licenses.mit;
    platforms = lib.platforms.darwin;
  };
})
