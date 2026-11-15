# #444 part (a): the minimal NixOS 26.05 guest booted under QEMU TCG.
#
# The guest enables the mountfsd activation boundary with the public dev/test
# root-hash certificate (owner decision D2, 2026-11-15), records its packaged
# state once at boot and powers off. It has no network device, and the host
# runs QEMU in an empty network namespace.
#
# dev-trust/root-hash-dev-test.crt is a self-signed RSA-2048 certificate with
# only a CN, so its kernel key description is "<CN>: <subjectKeyIdentifier>"
# (ADR-087 Part C.2). It is not a release certificate: only this evidence
# kernel trusts it, and its private key was not kept.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  collector = pkgs.writeShellApplication {
    name = "piglor-qemu-evidence";
    runtimeInputs = [
      config.systemd.package
      pkgs.coreutils
      pkgs.findutils
      pkgs.gawk
      pkgs.gzip
      pkgs.keyutils
    ];
    text = builtins.readFile ./collect-evidence.sh;
  };
in
{
  imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

  piglor.mountfsdActivation = {
    enable = true;
    rootHashCertificate = ../dev-trust/root-hash-dev-test.crt;
  };

  system.stateVersion = "26.05";
  networking.hostName = "piglor-qemu-evidence";
  networking.useDHCP = false;
  documentation.enable = false;

  virtualisation = {
    diskImage = null;
    memorySize = 2048;
    cores = 2;
    graphics = false;
    qemu.networkingOptions = lib.mkForce [ ];
    # TCG only: the later -machine accel= replaces the default kvm:tcg list.
    # -no-reboot turns a guest reboot or panic into a QEMU exit.
    # -nic none: without it QEMU adds its default user-mode NIC.
    qemu.options = [
      "-machine accel=tcg"
      "-nic none"
      "-no-reboot"
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
