{
  lib,
  stdenv,
  darwin,
  apple-sdk_15,
  darwinMinVersionHook,
  openpam,
  teamId ? "-",
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "sudowhat";
  version = "0.5.0";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ darwin.sigtool ];

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
                     "$out/lib/pam/pam_sudowhat.so"
  '';

  makeFlags = [ "SUDOWHAT_TEAM_ID=${teamId}" ];

  buildPhase = ''
    runHook preBuild
    # 'make sign' builds all then ad-hoc-signs both bundles via codesign,
    # which darwin.sigtool provides as a sandbox-safe shim.
    make $makeFlags sign
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -m 0755 -d $out/libexec/sudo $out/lib/pam
    install -m 0755 build/sudowhat_approval.so $out/libexec/sudo/sudowhat_approval.so
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
