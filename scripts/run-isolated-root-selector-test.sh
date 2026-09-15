#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 TEST_BINARY TEST_NAME" >&2
  exit 2
fi

sudo -n env \
  "PIGLOROS_TEST_BINARY=$1" \
  "PIGLOROS_TEST_NAME=$2" \
  "LLVM_PROFILE_FILE=${LLVM_PROFILE_FILE:-}" \
  unshare --mount --fork --propagation private \
  bash -ceu '
    mount --make-rprivate /
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/lib
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
    export PIGLOROS_PRIVILEGED_COMPOSITION_TEST=1
    exec "$PIGLOROS_TEST_BINARY" --exact "$PIGLOROS_TEST_NAME" --nocapture
  '
