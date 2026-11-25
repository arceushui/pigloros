# #444 parts (a) and (b): the minimal NixOS 26.05 guest booted under QEMU TCG.
#
# The guest enables the mountfsd activation boundary with the public dev/test
# root-hash certificate (owner decision D2, 2026-11-15), records its packaged
# state once at boot, runs the part (b) MountImage cases and powers off. It
# has no network device, and the host runs QEMU in an empty network namespace.
#
# dev-trust/root-hash-dev-test.crt is a self-signed RSA-2048 certificate with
# only a CN, so its kernel key description is "<CN>: <subjectKeyIdentifier>"
# (ADR-087 Part C.2). It is not a release certificate: only this evidence
# kernel trusts it. Its private key is committed beside it, as public as the
# certificate (#444 owner decision Q1, 2026-11-16), so that anyone can rebuild
# the signed evidence images; root-hash-untrusted-dev-test is a second public
# pair that no kernel trusts.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  repository = ../../..;

  # #444 part (b) driver: the production admission, registry and activation
  # library calls behind the pos-sandboxd `test-support` feature. The
  # official Rust 1.97.1 binaries (rust-toolchain.toml), which nixpkgs pins
  # by SHA-256 as rust_1_97's bootstrap compiler, build it; only the Cargo
  # workspace and the fixtures it compiles in are in its source.
  rustToolchain = pkgs.rust_1_97.packages.prebuilt;
  rustPlatform = pkgs.makeRustPlatform { inherit (rustToolchain) rustc cargo; };
  source = lib.fileset.toSource {
    root = repository;
    fileset = lib.fileset.unions [
      (repository + "/Cargo.toml")
      (repository + "/Cargo.lock")
      (repository + "/apps")
      (repository + "/crates")
      (repository + "/plugins")
      # pos-reference's test-support fixtures embed these at compile time.
      (repository + "/fixtures/conformance")
    ];
  };
  conformance = rustPlatform.buildRustPackage {
    pname = "pos-sandboxd-conformance";
    version = "0";
    src = source;
    cargoLock.lockFile = repository + "/Cargo.lock";
    cargoBuildFlags = [
      "--package"
      "pos-sandboxd"
      "--bin"
      "pos-sandboxd-conformance"
    ];
    buildFeatures = [ "test-support" ];
    auditable = false;
    doCheck = false;
    meta.mainProgram = "pos-sandboxd-conformance";
  };

  # The image's /adapter (#444 owner decision, 2026-11-25): its first mode,
  # honest, reads one EAI1 attempt and writes one EAO1 observation. It runs
  # inside the activated EROFS root, which holds nothing but the image's own
  # files, so it is linked statically and needs no loader or library there.
  # glibc.static with crt-static (not pkgsStatic, which would build a musl
  # rustc and std from source): the adapter only uses std, so the result has
  # no PT_INTERP. buildRustPackage always passes `--target`, so RUSTFLAGS
  # should reach neither build scripts nor proc macros; as an environment
  # variable it replaces, not merges with, any rustflags in a cargo config.
  # build-images.sh refuses an adapter that is not a loadable static ELF file
  # of the architecture. The static pos-sandboxd launcher is built by the
  # piece that uses it.
  adapter = rustPlatform.buildRustPackage {
    pname = "pos-sandbox-evidence-adapter";
    version = "0";
    src = source;
    cargoLock.lockFile = repository + "/Cargo.lock";
    cargoBuildFlags = [
      "--package"
      "pos-sandbox-evidence-adapter"
      "--bin"
      "pos-sandbox-evidence-adapter"
    ];
    # Not buildInputs: the wrapper would then put the static libc.a ahead of
    # libc.so for the dynamically linked build scripts, which then segfault
    # (the first QEMU run, 2026-11-25). Only the final link gets the path.
    env.RUSTFLAGS = "-C target-feature=+crt-static -C link-arg=-L${pkgs.glibc.static}/lib";
    auditable = false;
    doCheck = false;
    meta.mainProgram = "pos-sandbox-evidence-adapter";
  };

  # The provider executable: the real pos-sandboxd binary, which the staged
  # SIC1 installs as its kind-11 object and which the composed runtime runs
  # as (`provider-runtime`). The provider also binds it into each attempt unit
  # as /.pigloros/release-launcher (`launch-barrier`), where no loader exists,
  # so it is linked statically like the adapter.
  launcher = rustPlatform.buildRustPackage {
    pname = "pos-sandboxd";
    version = "0";
    src = source;
    cargoLock.lockFile = repository + "/Cargo.lock";
    cargoBuildFlags = [
      "--package"
      "pos-sandboxd"
      "--bin"
      "pos-sandboxd"
    ];
    buildInputs = [ pkgs.glibc.static ];
    env.RUSTFLAGS = "-C target-feature=+crt-static";
    auditable = false;
    doCheck = false;
    meta.mainProgram = "pos-sandboxd";
  };

  # The canonical SPI1 file of the staged provider installation: R11 §11
  # SPI1-A (256 attempt slots, the key file runtime-attestation.ed25519), as
  # the provider's own tests read it.
  spi1 = pkgs.runCommand "piglor-qemu-evidence-spi1" { nativeBuildInputs = [ pkgs.xxd ]; } ''
    printf '%s' 828764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e6564323535313958209d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003 \
      | xxd -r -p >"$out"
  '';

  # The part (b) SIM1 DDIs for this architecture, built offline from the
  # committed public dev/test key pairs.
  images =
    pkgs.runCommand "piglor-qemu-evidence-images"
      {
        nativeBuildInputs = [
          config.systemd.package
          pkgs.erofs-utils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
        ];
        TRUSTED_KEY = ../dev-trust/root-hash-dev-test.key;
        TRUSTED_CERTIFICATE = ../dev-trust/root-hash-dev-test.crt;
        UNTRUSTED_KEY = ../dev-trust/root-hash-untrusted-dev-test.key;
        UNTRUSTED_CERTIFICATE = ../dev-trust/root-hash-untrusted-dev-test.crt;
        ADAPTER = "${adapter}/bin/pos-sandbox-evidence-adapter";
      }
      ''
        bash ${./build-images.sh} ${
          if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86-64"
        } "$out"
      '';

  collector = pkgs.writeShellApplication {
    name = "piglor-qemu-evidence";
    runtimeInputs = [
      config.systemd.package
      conformance
      pkgs.coreutils
      pkgs.findutils
      pkgs.gawk
      pkgs.gzip
      pkgs.iproute2
      pkgs.keyutils
      pkgs.lvm2
      pkgs.util-linux
    ];
    runtimeEnv.PIGLOR_EVIDENCE_IMAGES = images;
    runtimeEnv.PIGLOR_EVIDENCE_SPI1 = spi1;
    runtimeEnv.PIGLOR_EVIDENCE_LAUNCHER = "${launcher}/bin/pos-sandboxd";
    text = builtins.readFile ./collect-evidence.sh;
  };

  # ADR-069 R13 §2.3 and §4: QEMU is started with `-accel tcg` only. The
  # qemu-vm runner hard-codes the `kvm:tcg` fallback list in its -machine
  # option, so derive a runner whose only change is that accelerator. The
  # replacement fails the build if the upstream text changes.
  runner = "run-${config.system.name}-vm";
  accelerator =
    if pkgs.stdenv.hostPlatform.isAarch64 then
      {
        from = "-machine virt,gic-version=max,accel=kvm:tcg";
        to = "-machine virt,gic-version=max -accel tcg";
      }
    else
      {
        from = "-machine accel=kvm:tcg";
        to = "-accel tcg";
      };
  tcgVm = pkgs.runCommand "piglor-qemu-evidence-vm-tcg" { } ''
    mkdir -p "$out/bin"
    cp ${config.system.build.vm}/bin/${runner} "$out/bin/${runner}"
    chmod u+w "$out/bin/${runner}"
    substituteInPlace "$out/bin/${runner}" \
      --replace-fail ${lib.escapeShellArg accelerator.from} ${lib.escapeShellArg accelerator.to}
  '';
in
{
  imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

  piglor.mountfsdActivation = {
    enable = true;
    rootHashCertificate = ../dev-trust/root-hash-dev-test.crt;
  };

  # Recorded by the host so the checker can find the collector in the closure.
  system.build.piglorQemuEvidenceCollector = collector;
  system.build.piglorQemuEvidenceConformance = conformance;
  system.build.piglorQemuEvidenceImages = images;
  system.build.piglorQemuEvidenceVm = tcgVm;

  system.stateVersion = "26.05";
  # Part (b) activates loop, dm-verity and EROFS devices; load the modules
  # up front rather than on the first request.
  boot.kernelModules = [
    "loop"
    "dm_verity"
    "erofs"
    # ADR-069 R14: the modules whose fallback tunnel devices show what
    # net.core.fb_tunnels_only_for_init_net does to a new network namespace.
    "ipip"
    "sit"
    "ip6_tunnel"
    "ip_gre"
  ];
  networking.hostName = "piglor-qemu-evidence";
  networking.useDHCP = false;
  documentation.enable = false;

  virtualisation = {
    diskImage = null;
    memorySize = 2048;
    cores = 2;
    graphics = false;
    qemu.networkingOptions = lib.mkForce [ ];
    # -nic none: without it QEMU adds its default user-mode NIC.
    # -no-reboot turns a guest reboot or panic into a QEMU exit.
    # The QMP socket in the runner's working directory lets the host read
    # the accelerator QEMU reports.
    qemu.options = [
      "-nic none"
      "-no-reboot"
      "-qmp unix:qmp.sock,server=on,wait=off"
    ];
  };

  systemd.services.piglor-qemu-evidence = {
    description = "Record #444 packaged-closure evidence";
    wantedBy = [ "multi-user.target" ];
    # Not After=multi-user.target: the target is ordered after the units it
    # wants, so that would be an ordering cycle.
    after = [ "systemd-mountfsd.socket" ];
    unitConfig = {
      RequiresMountsFor = [ "/tmp/xchg" ];
      SuccessAction = "poweroff";
      FailureAction = "poweroff";
    };
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${lib.getExe collector} /tmp/xchg/guest";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };
}
