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
  conformance = rustPlatform.buildRustPackage {
    pname = "pos-sandboxd-conformance";
    version = "0";
    src = lib.fileset.toSource {
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
      pkgs.keyutils
      pkgs.lvm2
      pkgs.util-linux
    ];
    runtimeEnv.PIGLOR_EVIDENCE_IMAGES = images;
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
