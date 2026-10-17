#!/bin/sh
# ASan plus build-std test binaries have very large links. Cargo compiles the
# ASan archive in parallel; this linker admits only one link at a time.
exec flock "${RUNNER_TEMP:?}/asan-link.lock" cc "$@"
