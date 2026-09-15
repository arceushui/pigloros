#!/usr/bin/env bash
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

docker_arguments=(
  --rm
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 256
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777
  --tmpfs /var/lib:rw,nosuid,nodev,mode=0755
  --tmpfs /run:rw,nosuid,nodev,mode=0755
  --mount "type=bind,source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly"
  --workdir "$REPOSITORY_ROOT"
  --env PIGLOROS_PRIVILEGED_COMPOSITION_TEST=1
)

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
  docker_arguments+=(
    --env "LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE"
    --mount "type=bind,source=$profile_directory,target=$profile_directory"
  )
fi

exec timeout --signal=TERM --kill-after=5s 30s \
  docker run "${docker_arguments[@]}" "$ISOLATION_IMAGE" \
  "$TEST_BINARY" --exact "$TEST_NAME" --nocapture
