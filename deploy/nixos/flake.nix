{
  description = "PiglorOS NixOS 26.05 mountfsd activation seam and its QEMU TCG evidence guest";

  # nixos-26.05 channel head of 2026-11-13. The tarball URL avoids the GitHub
  # API rate limit on shared hosted runners; flake.lock pins its narHash.
  inputs.nixpkgs.url = "https://github.com/NixOS/nixpkgs/archive/f1e5c356f35d07e7b71a6b5e6c9338e0b029e0c0.tar.gz";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;

      # ADR-087 §5: the same provider boundary on both supported architectures.
      architectures = {
        x86_64 = "x86_64-linux";
        aarch64 = "aarch64-linux";
      };

      evidenceGuest =
        system:
        lib.nixosSystem {
          modules = [
            self.nixosModules.mountfsd-activation
            ./qemu-evidence/guest.nix
            { nixpkgs.hostPlatform = system; }
          ];
        };

      guests = lib.mapAttrs (_: evidenceGuest) architectures;
    in
    {
      nixosModules.mountfsd-activation = ./modules/mountfsd-activation.nix;

      nixosConfigurations = lib.mapAttrs' (
        architecture: guest: lib.nameValuePair "qemu-evidence-${architecture}" guest
      ) guests;

      # The store identities that scripts/qemu-closure-evidence.sh records.
      qemuEvidence = lib.mapAttrs (
        _: guest:
        let
          inherit (guest) config;
        in
        {
          vm = "${config.system.build.vm}";
          toplevel = "${config.system.build.toplevel}";
          kernel = "${config.boot.kernelPackages.kernel}";
          systemd = "${config.systemd.package}";
          qemu = "${config.virtualisation.qemu.package}";
          trustedCertificate = "${config.piglor.mountfsdActivation.rootHashCertificateFile}";
          kernelConfig = "${config.boot.kernelPackages.kernel.configfile}";
          collector = "${config.system.build.piglorQemuEvidenceCollector}";
          collectorUnit = "${config.systemd.units."piglor-qemu-evidence.service".unit}";
        }
      ) guests;
    };
}
