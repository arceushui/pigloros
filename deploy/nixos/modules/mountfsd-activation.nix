# The host side of the ADR-087 systemd mountfsd SIM1 activation boundary.
#
# - §5: the packaged systemd build with mountfsd enabled and its socket active.
# - Part C.1: the root-hash certificate is compiled into the kernel's
#   .builtin_trusted_keys, and dm-verity has neither the secondary nor the
#   platform keyring fallback.
# - Part C.3: `systemd.allow_userspace_verity=0` vetoes systemd's userspace
#   signature path, so kernel verification is the only activation path.
#
# The certificate is the only input. The release appliance passes the offline
# release certificate (Part C.4); CI passes the public dev/test certificate.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.piglor.mountfsdActivation;
in
{
  options.piglor.mountfsdActivation = {
    enable = lib.mkEnableOption "the systemd mountfsd SIM1 activation boundary";

    rootHashCertificate = lib.mkOption {
      type = lib.types.path;
      description = ''
        PEM X.509 certificate compiled into the kernel's .builtin_trusted_keys
        through CONFIG_SYSTEM_TRUSTED_KEYS (ADR-087 Part C.1).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # ADR-087's kernel facts are audited against the Linux 6.12 LTS line.
    boot.kernelPackages = pkgs.linuxPackages_6_12;

    boot.kernelPatches = [
      {
        name = "piglor-dm-verity-builtin-keyring";
        patch = null;
        structuredExtraConfig = with lib.kernel; {
          DM_VERITY_VERIFY_ROOTHASH_SIG = yes;
          # Both depend on keyrings that this configuration leaves disabled;
          # `option` accepts their absence, never an enabled value.
          DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING = option no;
          DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING = option no;
          SYSTEM_TRUSTED_KEYS = freeform "${cfg.rootHashCertificate}";
        };
      }
    ];

    boot.kernelParams = [ "systemd.allow_userspace_verity=0" ];

    # NixOS 26.05 has no mountfsd module. Enable the packaged upstream units
    # and set nothing on them except the sockets.target link; #444 evidence
    # records every unit file and drop-in and rejects an environment override.
    systemd.additionalUpstreamSystemUnits = [
      "systemd-mountfsd.service"
      "systemd-mountfsd.socket"
    ];
    systemd.sockets.systemd-mountfsd.wantedBy = [ "sockets.target" ];
  };
}
