# Merging through the merge queue

Every change reaches `main` through [Trunk Merge Queue](https://docs.trunk.io/merge-queue).
The queue tests each pull request on top of the latest `main` **plus every
pull request queued ahead of it**, and merges exactly what it tested. Authors
never update branches to "catch up" with `main`, and parallel streams of work
no longer re-run each other's CI. The decision record is ADR-111 on the Redmine
wiki ([#476](https://redmine.piglor.com/issues/476)).

```mermaid
flowchart LR
    A["Open PR"] --> B["PR CI green"]
    B --> C{"Author is the maintainer?"}
    C -- yes --> E["Comment /trunk merge"]
    C -- no --> D["Maintainer reviews, clicks Approve,<br/>adds maintainer-approved"]
    D --> E
    E --> F["Trunk tests main + PRs ahead<br/>on a draft test PR"]
    F -- pass --> G["Trunk merges into main"]
    F -- fail --> H["PR removed with a comment;<br/>others re-tested without it"]
```

## Merging a pull request

1. Open the pull request against `main` and let its CI run.
2. Make sure `maintainer-approval` is green (see [Approval](#approval)).
3. Comment **`/trunk merge`** (or tick the box in Trunk's comment). You may do
   this before CI finishes; Trunk waits until GitHub reports the pull request
   as mergeable.
4. Wait. Trunk posts its status in the same comment and merges when the queue
   test passes.

Do **not**:

- press GitHub's Merge button or call the merge API — the `main -> queue only`
  ruleset rejects it, and any merge outside the queue resets every queued
  test;
- rebase or "Update branch" only because `main` moved — the queue already tests
  on top of the latest `main`. Update a branch only to resolve a **merge
  conflict**, which the queue cannot do for you;
- cancel and re-submit a pull request whose test was reset — Trunk restarts it
  automatically and re-submitting moves it to the back of the queue.

Other commands: `/trunk cancel` removes a pull request from the queue;
`/trunk merge --no-batch` tests a risky change on its own.

## Approval

The required `maintainer-approval` check (`.github/workflows/maintainer-approval.yml`)
replaces GitHub's required-review count, which a sole maintainer cannot
satisfy on their own pull requests.

| Pull request | How it passes |
|---|---|
| Opened by the maintainer (`arceushui`) | Automatically |
| Trunk's queue test pull requests (`trunk-io[bot]`) | Automatically; they contain only already-approved pull requests |
| Anyone else, including Dependabot | An admin or maintainer submits an **Approve** review on the **current head commit**, then adds the `maintainer-approved` label to re-run the check |

- The review is the approval. GitHub binds it to the commit it approved, so
  any new push needs a fresh review; the workflow also removes the label on new
  commits.
- The label only re-runs the check (reviews do not trigger
  `pull_request_target`). Adding it without a matching review grants nothing.
- Only the **admin** and **maintain** roles count. Give collaborators **write**
  or **triage** when they should work on the repository without approving
  merges.
- The workflow runs the copy on `main`, never checks out pull request code,
  and its policy test is `scripts/test_maintainer_approval_policy.py`.

## Stacked pull requests

Trunk supports [GitHub stacked pull requests](https://docs.github.com/en/pull-requests/get-started/about-stacked-prs):
`/trunk merge` on a pull request in a stack tests that pull request and every
pull request below it in one CI run and merges them together.

If Trunk replies that the pull request "is not part of a stack that targets a
branch with a Merge Queue" for a real GitHub stack, merge the bottom pull
request (the one targeting `main`) through the queue first and continue
upwards as GitHub retargets each pull request, and report the stack to Trunk
support.

## When a queued pull request fails or waits

Trunk's comment on the pull request names the failing required check; open the
linked job log before changing anything.

| Symptom | Usual cause | Action |
|---|---|---|
| "Waiting to enter queue" / **Not Ready** | The pull request's own required checks are red or pending, or it has merge conflicts | Fix or re-run the failing check; resolve conflicts by merging `main` into the branch |
| "target branch (`main`) was updated outside of the merge queue" | Something merged without the queue | Nothing; Trunk restarts the affected tests |
| `cargo-crap` fails at "Resolve trusted cargo-crap baseline" right after `main` changed | `main`'s own CI has not yet uploaded the baseline for the new commit; Rust changes fail closed rather than self-baseline | Wait for `main`'s `ci` run to finish; Trunk re-tests or re-submit afterwards |
| "Waiting for tests to start on a bisection of its batch" | A batch failed and Trunk is isolating the culprit | Nothing; pull requests that pass re-enter the queue |
| Every gate fails within seconds after a scope step error | GitHub's changed-file API was unavailable; the scope jobs fall back to the full gate set, so a repeat means a different problem | Read the scope job log |
| `CodeQL (Rust)` reports "analyses from advanced configurations cannot be processed when the default setup is enabled" | CodeQL **default setup** was enabled for the repository | Settings → Advanced Security → CodeQL analysis → **Switch to advanced** |
| Queue test pull request has no CI at all | The `ci` workflow is disabled | Actions → `ci` → **Enable workflow** |
| `github-advanced-security` fails with "requested model is not supported" | The optional Copilot code-scanning AI findings agent | Not a required check; ignore or disable it |

"Flaky" is not a diagnosis: a retry is reasonable only for a confirmed
infrastructure failure, and a second identical failure is real.

## Repository configuration

For maintainers changing settings; everything above works without touching
these.

- **Trunk:** one queue on `main` (`app.trunk.io`, organization `piglor`) in
  Draft PR mode, so the existing `pull_request` CI runs on Trunk's
  `trunk-merge/*` test pull requests without workflow changes.
- **Rulesets on `main`:**
  - `main -> queue only` — restrict updates, deletions and force pushes; the
    Trunk GitHub App is the only bypass actor, as **Exempt**. Adding a person
    to this bypass list lets merges skip the queue and reset it.
  - `Require Rust quality gates` — required checks `ci-gate`,
    `diff mutation testing`, `Trunk Code Quality`, `CodeQL (Rust)` and
    `maintainer-approval`; "require branches to be up to date" stays **off**.
  - `main` — pull request required (0 approvals), resolved conversations,
    linear history, CodeQL alerts block.
- Trunk must not bypass the two mergeability rulesets: they decide when a pull
  request may enter the queue.
- Keep Trunk's merge method compatible with linear history (squash or rebase).
