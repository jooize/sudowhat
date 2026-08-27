{
  lib,
  stdenv,
  # cargo + rustc build the pure-Rust audit plugin (linux/sudowhat_audit) and its
  # escape_core path dependency. Both crates have zero external dependencies and
  # pin a committed Cargo.lock, so the build is fully offline and reproducible —
  # no registry fetch, no vendoring, no crane needed.
  cargo,
  rustc,
  # readelf for install/linux/verify-plugin-so.bash (postInstall guard).
  binutils,
  # Master switch for terminal command display: "on" (default) or "off". One of
  # the Makefile's SUDOWHAT_VALID_AUDIT_DISPLAY; validated by the nixos module's
  # enum. See services.sudowhat.auditDisplay.
  auditDisplay ? "on",
  # Colouring of the terminal command display: "on" (default) or "off".
  # Parsed for a stable option surface, but the anomaly colouriser is a
  # documented fast-follow (renders plain today), exactly as on macOS. Validated
  # by the nixos module's enum. See services.sudowhat.echoColor.
  echoColor ? "on",
}:

# Linux is DISPLAY-ONLY: one pure-Rust cdylib, no approval plugin, no PAM module,
# no code-signing. sudo perm-checks /etc/sudo.conf only; the .so is protected by
# ordinary permissions on its root-owned store/install path — sudo does NOT
# perm-check the .so itself (see docs/design-linux-port.md).
stdenv.mkDerivation (finalAttrs: {
  pname = "sudowhat";
  version = "0.15.0";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ cargo rustc binutils ];

  # Build only the Linux audit target. The default `make` (all) would try to
  # compile the macOS ObjC bundles (clang -bundle -framework Foundation) and
  # fail, so drive `build-linux` explicitly. CARGO_HOME must be writable inside
  # the sandbox (nix's HOME is not); the build is offline with pinned lockfiles,
  # so nothing is fetched — this is only somewhere cargo may scribble.
  buildPhase = ''
    runHook preBuild
    export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
    make \
      SUDOWHAT_AUDIT_DISPLAY=${auditDisplay} \
      SUDOWHAT_ECHO_COLOR=${echoColor} \
      build-linux
    runHook postBuild
  '';

  # cargo emits libsudowhat_audit.so; sudo.conf references sudowhat_audit.so, so
  # install under the un-prefixed name (matching the macOS bundle's filename and
  # the config/linux/sudo.conf.sample path). 0644 — dlopen only needs read, and
  # the store strips write bits, so this lands as 0444 (matching the
  # nixos-module's stated trust anchor).
  installPhase = ''
    runHook preInstall
    install -m 0755 -d $out/libexec/sudo
    install -m 0644 linux/sudowhat_audit/target/release/libsudowhat_audit.so \
      $out/libexec/sudo/sudowhat_audit.so
    runHook postInstall
  '';

  # Regression guard for the v0.11.0-v0.14.0 load fault: the exported plugin
  # struct must sit in writable .data (sudo writes event_alloc into it after
  # dlopen), with GNU_RELRO + BIND_NOW intact. Fails the build otherwise, so a
  # toolchain/flag divergence between this pipeline and the Makefile's cannot
  # ship a sudo-breaking .so.
  postInstall = ''
    bash ./install/linux/verify-plugin-so.bash $out/libexec/sudo/sudowhat_audit.so
  '';

  meta = {
    description = "Terminal command display for sudo via an audit plugin (Linux; display-only, no tamper-evidence)";
    homepage = "https://github.com/jooize/sudowhat";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
})
