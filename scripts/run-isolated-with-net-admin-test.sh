#!/usr/bin/env bash
# Owner decision 2026-11-09 (#911): run one pos-sandboxd library test of the
# Local attempt namespace adapter in a container that adds NET_ADMIN and
# SYS_ADMIN, so it can create network namespaces, veth pairs and nftables
# state. The container has no network, drops every other capability, keeps
# no-new-privileges and a read-only root, and sees the worktree read-only.
#
# The adapter's own tests (namespace_network::control) pin namespaces with
# bind mounts under /run/netns, which Docker's AppArmor profile refuses, so
# they alone also run unconfined by AppArmor.
#
# Residual risk: SYS_ADMIN lets the test remount filesystems inside its own
# mount namespace, and Docker's AppArmor profile is what normally refuses
# that; the unconfined tests keep only the capability bound. The runner
# therefore accepts only a pos-sandboxd test harness built under target/,
# only the named privileged tests, and verifies inside the container that
# the worktree bind is read-only before the test starts.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 TEST_BINARY TEST_NAME" >&2
  exit 2
fi

readonly ISOLATION_IMAGE='ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254'
readonly SCRIPT_DIRECTORY=$(realpath -- "$(dirname -- "$0")")
readonly REPOSITORY_ROOT=$(realpath -- "$SCRIPT_DIRECTORY/..")
readonly TEST_BINARY=$(realpath -- "$1")
readonly TEST_NAME=$2

case "$TEST_BINARY" in
  "$REPOSITORY_ROOT"/*) ;;
  *)
    echo "test binary must be inside the repository worktree" >&2
    exit 2
    ;;
esac

# Owner decision 2026-11-09 (#911): only the pos-sandboxd library tests of the
# Local attempt namespace adapter may run with NET_ADMIN and SYS_ADMIN, to
# create veth pairs and nftables state in network namespaces they create. The
# container keeps no network and drops every other capability.
readonly TEST_DIRECTORY=$(dirname -- "$TEST_BINARY")
readonly TEST_RELATIVE=${TEST_BINARY#"$REPOSITORY_ROOT"/}
# target/<profile>/deps, or target/<triple or llvm-cov-target>/<profile>/deps.
readonly TEST_TARGET='^target/([A-Za-z0-9_-]+/){1,2}deps/pos_sandboxd-[0-9a-f]{16}$'
if [[ ! $TEST_RELATIVE =~ $TEST_TARGET || ! -f $TEST_BINARY || ! -x $TEST_BINARY ||
  $TEST_BINARY -ef $TEST_DIRECTORY/../pos-sandboxd ]]; then
  echo "only the pos-sandboxd library test harness may use this runner" >&2
  exit 2
fi
readonly TEST_PATTERN='^namespace_network::(netlink|control)::tests::privileged::[a-z0-9_]+$'
if [[ ! $TEST_NAME =~ $TEST_PATTERN ]]; then
  echo "only the #911 namespace adapter tests may use this runner" >&2
  exit 2
fi
# A comma would end the bind mount's source and start another option.
if [[ $REPOSITORY_ROOT == *,* ]]; then
  echo "the repository path must not contain a comma" >&2
  exit 2
fi

docker_arguments=(
  --rm
  --network none
  --read-only
  --cap-drop ALL
  --cap-add NET_ADMIN
  --cap-add SYS_ADMIN
  --security-opt no-new-privileges
  --pids-limit 256
  --memory 2g
  --memory-swap 2g
  --ulimit fsize=268435456:268435456
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=512m
  --tmpfs /var/lib:rw,nosuid,nodev,mode=0755,size=64m
  --tmpfs /run:rw,nosuid,nodev,mode=0755,size=64m
  --mount "type=bind,source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly"
  --workdir "$REPOSITORY_ROOT"
  --env PIGLOROS_PRIVILEGED_COMPOSITION_TEST=1
)
profile_output=

# Owner decision 2026-11-09 (#911): only the tests that pin namespaces run
# without Docker's AppArmor profile.
readonly UNCONFINED_PATTERN='^namespace_network::control::tests::privileged::[a-z0-9_]+$'
if [[ $TEST_NAME =~ $UNCONFINED_PATTERN ]]; then
  docker_arguments+=(--security-opt apparmor=unconfined)
fi

for variable in ASAN_OPTIONS LSAN_OPTIONS; do
  if [[ -n ${!variable:-} ]]; then
    docker_arguments+=(--env "$variable=${!variable}")
  fi
done

if [[ -n ${LLVM_PROFILE_FILE:-} ]]; then
  profile_directory=$(realpath -- "$(dirname -- "$LLVM_PROFILE_FILE")")
  case "$profile_directory" in
    "$REPOSITORY_ROOT"/target/*) ;;
    *)
      echo "LLVM profile output must be inside the worktree target directory" >&2
      exit 2
      ;;
  esac
  if [[ $profile_directory == *,* ]]; then
    echo "the LLVM profile path must not contain a comma" >&2
    exit 2
  fi
  profile_output=$(mktemp "$profile_directory/isolated-profile.XXXXXX.profraw")
  chmod 0666 "$profile_output"
  docker_arguments+=(
    --env LLVM_PROFILE_FILE=/pigloros-profile.profraw
    --mount "type=bind,source=$profile_output,target=/pigloros-profile.profraw"
  )
fi

# access(2) reports a read-only filesystem even to root, so the test starts
# only while the worktree bind refuses writes.
readonly READ_ONLY_PROBE='if [ -w "$1" ]; then echo "the worktree bind is writable" >&2; exit 1; fi; shift; exec "$@"'

set +e
timeout --signal=TERM --kill-after=5s 30s \
  docker run "${docker_arguments[@]}" "$ISOLATION_IMAGE" \
  /bin/sh -c "$READ_ONLY_PROBE" read-only-probe "$REPOSITORY_ROOT" \
  "$TEST_BINARY" --exact "$TEST_NAME" --nocapture
status=$?
set -e

if [[ -n $profile_output ]]; then
  chmod 0600 "$profile_output"
fi
if [[ $status -ne 0 ]]; then
  exit "$status"
fi
if [[ -n $profile_output && ! -s $profile_output ]]; then
  echo "isolated coverage process did not create a profile" >&2
  exit 1
fi
