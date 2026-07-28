# Supply-chain pinning

External GitHub Actions, Docker Actions, and Docker base images are pinned to
immutable revisions. The repository syntactically enforces these reference
forms with:

```bash
bash scripts/check-pinned-dependencies.sh
bash scripts/test-check-pinned-dependencies.sh
```

The `pinned-dependencies` CI job runs the first command on every pull request
and push. The second command is run locally and in CI to verify that the guard
rejects floating, multiline, and malformed Action and image references. The
offline checker validates reference syntax; it cannot prove that a 40-hex
Action revision exists or is a commit in the upstream repository.

## Updating a pin intentionally

Use a reviewed dependency update rather than editing a tag in place.

1. Resolve the desired Action release. Prefer the dereferenced entry for an
   annotated tag, then validate that exactly one 40-hex revision was found:

   ```bash
   action_repository=https://github.com/OWNER/REPOSITORY.git
   action_version=VERSION
   action_refs=$(git ls-remote "$action_repository" \
     "refs/tags/$action_version" "refs/tags/$action_version^{}")
   action_sha=$(printf '%s\n' "$action_refs" | awk '$2 ~ /\^\{\}$/ { print $1 }')
   if [[ -z "$action_sha" ]]; then
     action_sha=$(printf '%s\n' "$action_refs" | awk '$2 !~ /\^\{\}$/ { print $1 }')
   fi
   [[ "$action_sha" =~ ^[0-9a-f]{40}$ ]] || {
     echo 'expected exactly one 40-hex Action revision' >&2
     exit 1
   }
   ```

   Replace the revision in the workflow or composite Action and retain/update
   its trailing release comment. Review the upstream tag and commit before
   accepting the update; the local syntax checker cannot do that remotely.

2. Resolve the desired Docker image to its multi-platform index digest:

   ```bash
   docker buildx imagetools inspect IMAGE:TAG
   ```

   Replace the `sha256:` digest while retaining the human-readable tag before
   `@`.

3. Run both policy commands above, then build and smoke-test the image:

   ```bash
   docker build --tag pigloros-gateway:pin-check .
   docker run --rm -d -p 18080:8080 --name pigloros-pin-check pigloros-gateway:pin-check
   curl -fsS http://localhost:18080/health
   docker stop pigloros-pin-check
   ```

4. Include the upstream release or digest source in the pull request review.

Cargo builds in `Dockerfile` use `--locked`, so the image build fails if
`Cargo.lock` does not resolve the workspace dependencies.
