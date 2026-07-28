# Supply-chain pinning

GitHub Actions and Docker base images are immutable-pinned to make a CI run or
container rebuild reproducible from the repository revision alone. The
repository enforces this with:

```bash
bash scripts/check-pinned-dependencies.sh
bash scripts/test-check-pinned-dependencies.sh
```

The `pinned-dependencies` CI job runs the first command on every pull request
and push. The second command is run locally and in CI to verify that the guard
rejects intentionally floating Action and image references.

## Updating a pin intentionally

Use a reviewed dependency update rather than editing a tag in place.

1. Resolve the desired Action release to its commit:

   ```bash
   git ls-remote https://github.com/OWNER/REPOSITORY.git refs/tags/VERSION
   ```

   Replace the full SHA in the workflow and retain/update its trailing release
   comment.

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
