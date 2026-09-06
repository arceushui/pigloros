{
  description = "Throwaway ADR-069 pinned-host feasibility evidence";

  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/6713828a351efa628b025a1adf7f43cbf8597513";

  outputs = { nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          prototype = pkgs.rustPlatform.buildRustPackage {
            pname = "sandbox-provider-feasibility";
            version = "0.0.0";
            src = pkgs.lib.cleanSource ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = false;
          };
        in
        {
          sandbox-provider-host-profile = pkgs.testers.runNixOSTest {
            name = "sandbox-provider-host-profile";

            nodes.machine = { pkgs, ... }: {
              boot.kernelPackages = pkgs.linuxPackages_6_12;
              boot.kernelModules = [ "dm_verity" ];

              environment.systemPackages = [
                prototype
                pkgs.cryptsetup
                pkgs.iproute2
                pkgs.jq
                pkgs.nftables
                pkgs.util-linux
              ];

              virtualisation = {
                cores = 2;
                memorySize = 3072;
                restrictNetwork = true;
              };
            };

            testScript = ''
              start_all()
              machine.wait_for_unit("multi-user.target")

              systemd_version = machine.succeed("systemd --version | head -1").strip()
              kernel_release = machine.succeed("uname -r").strip()
              architecture = machine.succeed("uname -m").strip()
              controllers = machine.succeed("cat /sys/fs/cgroup/cgroup.controllers").strip()

              assert systemd_version.startswith("systemd 260 "), systemd_version
              assert kernel_release.startswith("6.12."), kernel_release
              assert {"cpu", "memory", "pids"}.issubset(set(controllers.split())), controllers
              machine.succeed("test -e /sys/fs/cgroup/cgroup.kill")
              machine.succeed("test -e /sys/module/dm_verity")
              machine.succeed("test -e /dev/mapper/control")
              machine.succeed("! ip route show default | grep -q .")

              print(
                  "PINNED_HOST_IDENTITY;"
                  f"architecture={architecture};"
                  f"kernel={kernel_release};"
                  f"systemd={systemd_version};"
                  f"controllers={controllers};"
                  "cgroup_kill=present;dm_verity=present;mapper_control=present;"
                  "vm_external_route=absent"
              )

              initial = machine.succeed(
                  "sandbox-provider-feasibility "
                  "--privileged --offline --attempt-id pinnedvm"
              ).strip()
              print(f"PINNED_INITIAL_PROBE;{initial}")
              assert "network_isolation=isolated-no-host-net" in initial, initial
              assert "typed-create-read-delete-ok" in initial, initial
              assert "typed-default-drop-allow-read-back-delete-ok" in initial, initial
              assert "retained-fd-full-set-child-exit-drop-ok" in initial, initial
              assert "host-capability-present" in initial, initial

              namespace = machine.succeed(
                  "sandbox-provider-feasibility --namespace-entry-lifecycle"
              ).strip()
              print(f"PINNED_NAMESPACE_PROBE;{namespace}")
              assert (
                  namespace
                  == "namespace_entry_lifecycle="
                     "retained-fd-full-set-entered-post-exit-fd-ok-"
                     "post-drop-process-absent"
              ), namespace

              limits = machine.succeed(
                  "sandbox-provider-feasibility --privileged --offline "
                  "--cgroup-limits --attempt-id pinnedlimits"
              ).strip()
              print(f"PINNED_LIMIT_READBACK;{limits}")
              assert "memory-cpu-pids-io-read-back-ok" in limits, limits
              assert "unit_absent=true" in limits, limits
            '';
          };
        }
      );
    };
}
