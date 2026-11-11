#!/bin/bash -p
# bash -p reads no BASH_ENV or ENV file and imports no shell functions, so
# the caller's environment runs nothing here; the fixed PATH below chooses
# every program this runner starts, and Docker runs under exactly the
# environment named where it starts. Its daemon is the system socket, or
# the unix socket PIGLOR_ISOLATED_DOCKER_HOST names (rootless Docker);
# DOCKER_HOST, DOCKER_CONTEXT and DOCKER_CONFIG are ignored on purpose, so
# no Docker context or configuration can send the run to another daemon.
set -euo pipefail
readonly RUNNER_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH=$RUNNER_PATH

if [[ $# -ne 2 ]]; then
  echo "usage: $0 TEST_BINARY TEST_NAME" >&2
  exit 2
fi

readonly DOCKER_SOCKET=${PIGLOR_ISOLATED_DOCKER_HOST:-unix:///var/run/docker.sock}
if [[ ! $DOCKER_SOCKET =~ ^unix:///[A-Za-z0-9._/-]+$ || $DOCKER_SOCKET == *..* ]]; then
  echo "PIGLOR_ISOLATED_DOCKER_HOST must be unix:// and an absolute socket path" >&2
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

docker_arguments=(
  --rm
  --network none
  --read-only
  --cap-drop ALL
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
  profile_output=$(mktemp "$profile_directory/isolated-profile.XXXXXX.profraw")
  chmod 0666 "$profile_output"
  docker_arguments+=(
    --env LLVM_PROFILE_FILE=/pigloros-profile.profraw
    --mount "type=bind,source=$profile_output,target=/pigloros-profile.profraw"
  )
fi

set +e
timeout --signal=TERM --kill-after=5s 30s \
  env -i "PATH=$RUNNER_PATH" HOME=/nonexistent "DOCKER_HOST=$DOCKER_SOCKET" \
  docker run "${docker_arguments[@]}" "$ISOLATION_IMAGE" \
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
