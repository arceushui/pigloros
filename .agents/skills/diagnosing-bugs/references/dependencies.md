# Dependency triage

Internal PiglorOS guidance for dependency and lockfile failures.

1. Trace the shared public-type graph and published version constraints across
   producers, containers, adapters, and tests before accepting an isolated bump.
   An upstream immutable API still needs malformed-input coverage at the public
   seam; migrate adversarial fixtures rather than deleting them.
2. Separate locked dependency bytes from live admission metadata such as registry
   withdrawal or trust policy. A lockfile cannot freeze that metadata or prove
   downstream source compatibility. Keep primary-source claims version-specific.
3. Enumerate every workspace resolving a changed manifest, including isolated
   fuzz or tool workspaces. Replay locked metadata independently in each affected
   workspace before editing, subject to the user's local-execution constraints.
4. Preserve the existing lockfile as the resolution seed. Validate or update the
   intended dependency without forcing an unrelated full refresh; parallel
   versions may be required by distinct consumers. Pair manifest changes with
   every affected lockfile and verify library and test targets.
5. For Actions dependency pins, use `ci-verification` to find reviewed producers
   and exact-pin policy consumers before changing a shared reference.

Before delivery, verify compatibility at every affected workspace and consumer,
retain adversarial fixtures, and report any unexecuted hosted validation.
