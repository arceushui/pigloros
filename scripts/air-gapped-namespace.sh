#!/bin/bash -p
# ADR-135 §4 "CI, conformance and local test runs" (#1422): run PROGRAM [ARGUMENT...] in the
# Air-Gapped test shape, a new network namespace that holds only `lo` (brought up), with empty
# effective, permitted, inheritable, ambient and bounding capability sets, no_new_privs, and the
# test seccomp address-family filter of scripts/air_gapped_seccomp_exec.py.
#
# The preferred shape is an unprivileged user namespace (`unshare --user --map-root-user
# --net`): `lo` is brought up while the mapped root still holds CAP_NET_ADMIN in it, then
# setpriv empties the bounding and inheritable sets, so the final exec leaves CapPrm and CapEff
# empty even for that root. When the host blocks unprivileged user namespaces (AppArmor
# kernel.apparmor_restrict_unprivileged_userns on ubuntu-24.04), the fallback is
# `sudo -n unshare --net` with the same `lo` step and setpriv back to the invoking user and
# group (--reuid/--regid/--init-groups), so the program never runs as real root and file
# permissions and SO_PEERCRED stay unchanged. Neither shape reproduces the deployment unit's
# InaccessiblePaths= or its exact RestrictAddressFamilies= set; #462 verifies those.
#
# This is a test harness and never a production override: the Gateway reads only /proc/self.
#
# bash -p reads no BASH_ENV or ENV file and imports no shell functions; the fixed PATH below
# chooses every program this runner starts. The environment is otherwise passed through
# (sudo -E), so test and coverage variables reach PROGRAM.
set -euo pipefail
readonly RUNNER_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH=$RUNNER_PATH

if [[ $# -lt 1 ]]; then
  echo "usage: $0 PROGRAM [ARGUMENT...]" >&2
  exit 2
fi

readonly HELPER=$(realpath -- "$(dirname -- "$0")/air_gapped_seccomp_exec.py")
readonly DROP=(--no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all)
# Bring `lo` up while CAP_NET_ADMIN is still held, then exec the rest of the arguments.
readonly LOOPBACK_UP='ip link set lo up && exec "$@"'

if unshare --user --map-root-user --net true 2>/dev/null; then
  exec unshare --user --map-root-user --net \
    sh -c "$LOOPBACK_UP" sh setpriv "${DROP[@]}" python3 "$HELPER" "$@"
fi
exec sudo -n -E unshare --net \
  sh -c "$LOOPBACK_UP" sh \
  setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups "${DROP[@]}" \
  python3 "$HELPER" "$@"
