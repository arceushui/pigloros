# Safe records

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Make append-only logs collision-aware.** Read the live file, assert the next number is unused, append, then verify count, uniqueness, and survival.

- **Anchor appends at the true end.** Verify the new entry follows the previous entry's final field, not just that header counts rose.
