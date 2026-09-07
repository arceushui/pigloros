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
      mkPrototype = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "sandbox-provider-feasibility";
        version = "0.0.0";
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        doCheck = false;
      };
      mkStaticPrototype = pkgs: pkgs.pkgsStatic.rustPlatform.buildRustPackage {
        pname = "sandbox-provider-feasibility-static";
        version = "0.0.0";
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        doCheck = false;
      };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          sandbox-provider-feasibility-static = mkStaticPrototype pkgs;
          busybox-static = pkgs.pkgsStatic.busybox;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          prototype = mkPrototype pkgs;
          staticPrototype = mkStaticPrototype pkgs;
        in
        {
          sandbox-provider-host-profile = pkgs.testers.runNixOSTest {
            name = "sandbox-provider-host-profile";

            # GitHub's native Arm runner has no /dev/kvm. NixOS tests fall back
            # to same-architecture TCG when KVM is not forced, so make that
            # supported execution mode explicit without weakening the guest
            # architecture, kernel, or systemd assertions below.
            requiredFeatures.kvm = system == "x86_64-linux";

            nodes.machine = { pkgs, ... }: {
              boot.kernelPackages = pkgs.linuxPackages_6_12;
              boot.kernelModules = [ "dm_verity" ];

              environment.systemPackages = [
                prototype
                staticPrototype
                pkgs.b3sum
                pkgs.cryptsetup
                pkgs.curl
                pkgs.erofs-utils
                pkgs.iproute2
                pkgs.jq
                pkgs.lvm2
                pkgs.nix
                pkgs.nftables
                pkgs.openssl
                pkgs.util-linux
              ];

              virtualisation = {
                cores = 2;
                memorySize = 3072;
                restrictNetwork = true;
              };
            };

            testScript = ''
              import os
              import socket
              import time
              from http.server import BaseHTTPRequestHandler, HTTPServer

              class IsolationEndpoint(BaseHTTPRequestHandler):
                  def do_GET(self):
                      self.send_response(200)
                      self.end_headers()
                      self.wfile.write(b"host-reachable")

              if os.fork() == 0:
                  HTTPServer(("", 8000), IsolationEndpoint).serve_forever()

              for _ in range(50):
                  try:
                      with socket.create_connection(("127.0.0.1", 8000), timeout=1):
                          break
                  except OSError:
                      time.sleep(0.1)
              else:
                  raise AssertionError("host isolation endpoint did not start")

              start_all()
              machine.wait_for_unit("multi-user.target")

              systemd_version = machine.succeed("systemctl --version | head -1").strip()
              kernel_release = machine.succeed("uname -r").strip()
              architecture = machine.succeed("uname -m").strip()
              controllers = machine.succeed("cat /sys/fs/cgroup/cgroup.controllers").strip()

              assert systemd_version.startswith("systemd 260 "), systemd_version
              assert kernel_release.startswith("6.12."), kernel_release
              assert {"cpu", "memory", "pids"}.issubset(set(controllers.split())), controllers
              machine.succeed("test -e /sys/module/dm_verity")
              machine.succeed("test -e /dev/mapper/control")
              machine.fail(
                  "curl --fail --silent --show-error --connect-timeout 2 "
                  "http://10.0.2.2:8000"
              )

              print(
                  "PINNED_HOST_IDENTITY;"
                  f"architecture={architecture};"
                  f"kernel={kernel_release};"
                  f"systemd={systemd_version};"
                  f"controllers={controllers};"
                  "dm_verity=present;mapper_control=present;"
                  "vm_external_egress=blocked"
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

              machine.copy_from_host(
                  "${./prove-sim1-image.sh}",
                  "/tmp/prove-sim1-image.sh",
              )
              sim1 = machine.succeed(
                  "chmod 0755 /tmp/prove-sim1-image.sh && "
                  "STATIC_TRUE=${pkgs.pkgsStatic.busybox}/bin/true "
                  "STATIC_PROTOTYPE=${staticPrototype}/bin/sandbox-provider-feasibility "
                  "/tmp/prove-sim1-image.sh"
              ).strip()
              print(f"PINNED_SIM1_PROOF;{sim1}")
              assert "valid_signature=provider-verified" in sim1, sim1
              assert "valid_image=activated-and-executed" in sim1, sim1
              assert "invalid_root_hash=rejected" in sim1, sim1
              assert "invalid_signature=rejected-before-unit" in sim1, sim1
              assert "residual_mount=absent" in sim1, sim1
              machine.copy_from_machine(
                  "/tmp/pigloros-sim1-evidence",
                  "sim1-evidence",
              )

              machine.succeed(
                  "nix --extra-experimental-features nix-command "
                  "path-info --json --recursive /run/current-system "
                  ">/tmp/guest-system-closure.json"
              )
              closure_roots = machine.succeed(
                  "nix --extra-experimental-features nix-command "
                  "path-info --json /run/current-system"
              )
              closure = machine.succeed(
                  "cat /tmp/guest-system-closure.json"
              )
              closure_roots = __import__("json").loads(closure_roots)
              closure = __import__("json").loads(closure)
              closure_paths = set(closure)
              expected_roots = set(closure_roots)
              assert len(expected_roots) == 1, expected_roots
              assert expected_roots.issubset(closure_paths), (
                  expected_roots,
                  closure_paths,
              )
              for path, entry in closure.items():
                  assert entry.get("narHash"), entry
                  assert set(entry.get("references", [])).issubset(
                      closure_paths
                  ), (path, entry)
              machine.copy_from_machine(
                  "/tmp/guest-system-closure.json",
                  "runtime-identity",
              )
              machine.succeed(
                  "nix --extra-experimental-features nix-command "
                  "path-info --json /run/current-system "
                  ">/tmp/guest-system-root.json"
              )
              machine.copy_from_machine(
                  "/tmp/guest-system-root.json",
                  "runtime-identity",
              )

              namespace = machine.succeed(
                  "sandbox-provider-feasibility --namespace-entry-lifecycle"
              ).strip()
              print(f"PINNED_NAMESPACE_PROBE;{namespace}")
              assert (
                  namespace
                  == "namespace_entry_lifecycle="
                     "retained-fd-full-set-each-entered-separately-post-exit-fd-ok-"
                     "post-drop-process-absent"
              ), namespace

              limits = machine.succeed(
                  "sandbox-provider-feasibility --privileged --offline "
                  "--cgroup-limits --attempt-id pinnedlimits"
              ).strip()
              print(f"PINNED_LIMIT_READBACK;{limits}")
              assert (
                  "memory-swap-cpu-pids-io-cgroup-kill-exercised-ok" in limits
              ), limits
              assert "io_weight=default 200" in limits, limits
              assert "cgroup_kill_exercised=true" in limits, limits
              assert "unit_absent=true" in limits, limits

              def record_fields(record):
                  return dict(
                      field.split("=", 1)
                      for field in record.split(";")
                      if "=" in field
                  )

              def percentile_95(records, field):
                  values = sorted(int(record_fields(record)[field]) for record in records)
                  return values[28]

              for mode in ["normal", "cancel", "forced"]:
                  cleanup_samples = []
                  for sample in range(1, 31):
                      cleanup = machine.succeed(
                          "sandbox-provider-feasibility --privileged --offline "
                          f"--cleanup-sample --cleanup-mode {mode} "
                          f"--attempt-id p{mode}{sample}"
                      ).strip()
                      assert f"cleanup_sample={mode}" in cleanup, cleanup
                      assert "unit_absent=true" in cleanup, cleanup
                      cleanup_samples.append(cleanup)
                      print(
                          "PINNED_CLEANUP_SAMPLE;"
                          f"mode={mode};ordinal={sample};{cleanup}"
                      )
                  launch_p95 = percentile_95(cleanup_samples, "launch_us")
                  cleanup_p95 = percentile_95(cleanup_samples, "cleanup_us")
                  assert launch_p95 <= 2_000_000, launch_p95
                  cleanup_limit = 5_000_000 if mode == "forced" else 2_000_000
                  assert cleanup_p95 <= cleanup_limit, cleanup_p95
                  print(
                      "PINNED_CLEANUP_P95;"
                      f"mode={mode};samples=30;launch_us_p95={launch_p95};"
                      f"cleanup_us_p95={cleanup_p95}"
                  )

              lifecycle_samples = []
              for sample in range(1, 31):
                  lifecycle_output = machine.succeed(
                      "sandbox-provider-feasibility --privileged --offline "
                      f"--attempt-id plife{sample}"
                  )
                  attempt_lines = [
                      line
                      for line in lifecycle_output.splitlines()
                      if line.startswith("attempt=")
                  ]
                  assert len(attempt_lines) == 1, lifecycle_output
                  lifecycle_samples.append(attempt_lines[0])
                  print(
                      "PINNED_LIFECYCLE_SAMPLE;"
                      f"ordinal={sample};{attempt_lines[0]}"
                  )
              total_p95 = percentile_95(lifecycle_samples, "total_us")
              assert total_p95 <= 2_000_000, total_p95
              print(
                  "PINNED_LIFECYCLE_P95;"
                  f"samples=30;total_us_p95={total_p95}"
              )
            '';
          };
        }
      );
    };
}
