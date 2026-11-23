# ADR-136 acceptance matrix

This document is the complete acceptance matrix of ADR-136 (Redmine #1414).
It maps each bullet of the ADR-136 acceptance tests to the public-seam tests
that cover it. Slice C6a (#1469) covers tests 1 to 7 at the runtime seams.
Slice C6b (#1470) adds tests 8 to 10 and the Gateway parts of test 2. Slice
C6c (#1471) adds test 11: key-less recovery by every consumer, and the served
lifecycle suite in every serve mode. Follow-up F3 (#1408) adds the
operator's closure of `requestErasure`; it is not an ADR-136 test bullet, so
it has its own section and is not counted in the summary.

## Summary

A row is one bullet of a test. "Mapped" rows name at least one test; the other
rows say why no test can exist, and the deviations index lists them.

| Test | Rows | Mapped | Not mapped | Deviations |
|---|---|---|---|---|
| 1. Lifecycle bytes | 3 | 3 | 0 | Q16 |
| 2. The C1′ partition | 13 | 13 | 0 | Deleted after freeze, imported Timelines, service Fork after freeze |
| 3. ARD1 and key binding | 5 | 5 | 0 | none |
| 3a. Snapshot port parity | 3 | 3 | 0 | none |
| 3b. Closure bound | 4 | 4 | 0 | Closure bound |
| 4. Retries and acknowledgements | 5 | 5 | 0 | none |
| 5. Rejections | 4 | 3 | 1 (unreachable) | Rejection provenance |
| 6. Trust and evidence | 15 | 14 | 1 (deferred to #448) | ELTA1 history, recovery legs |
| 7. Crash windows | 5 | 5 | 0 | none |
| 8. The Gateway | 17 | 16 | 1 (compile time) | `q_subject < 1`, plain submission, four runtime-seam mappings |
| 9. `getErasure` and the golden check | 6 | 5 | 1 (no metrics) | none |
| 10. Export and the offline evaluator | 1 | 1 | 0 | Field-level reporting |
| 11. Key-less recovery and serve modes | 9 | 9 | 0 | Adapter N/A (D21), Air-Gapped predicate 6 |
| **Total** | **90** | **86** | **4** | |

### Deviations index

Each entry names its owner decision and the rows it explains.

| Deviation | Tests | Decision | Where |
|---|---|---|---|
| ELTA1 operator-key history is not yet refused | 6 | Deferred to #448 (Q9) | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| Memory and `SQLite` bytes differ only in the replica row | 1 | Q16 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| An affected Timeline cannot be deleted under the host | 2 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| Imported Timelines keep their exported owner (errata) | 2 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| The closure bound counts the store target (errata) | 3b | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| Authorization rejection provenance (errata) | 5 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| Test 6 recovery legs are admission-only (errata) | 6 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| `q_subject < 1` is refused at compile time | 8 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| pos-cli has no plain submission | 8 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| Root-chain advance and revocation, the A/B retry and the signer revocation map to the runtime seam (errata) | 8 | Owner 2026-11-20 | [Test 8](#test-8-the-gateway) |
| Unavailable fields are reported per artifact | 10 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| The service refuses a Fork of an affected parent after the freeze (errata) | 2, 11 | Owner 2026-11-20 | [Deviations](#deviations-owner-decisions-of-2026-11-20) |
| The conformance adapter never acts as a key-less root | 11 | D21 (owner 2026-11-20) | [Test 11](#test-11-key-less-recovery-and-serve-modes) |
| Air-Gapped predicate 6 is vouched for in the served suite | 11 | Harness | [Test 11](#test-11-key-less-recovery-and-serve-modes) |

## Paths

| Short name | Path |
|---|---|
| `LEC` | `crates/pos-runtime/tests/local_erasure_composition_public.rs` |
| `ACC` | `crates/pos-runtime/tests/local_erasure_composition/acceptance.rs`, the module `local_erasure_composition_public::acceptance` |
| `EHP` | `crates/pos-runtime/tests/erasure_host_public.rs` |
| `LEA` | `crates/pos-store/tests/local_erasure_adapter_public.rs` |
| `FAA` | `crates/pos-store/tests/fork_admission_authority.rs` |
| `LER` | `crates/pos-core/tests/local_erasure_records_public.rs` |
| `GW` | `apps/piglor-gateway/src` (in-crate tests) |
| `E` | `apps/piglor-gateway/src/erasure/tests.rs`, the served-router tests of `requestErasure` and `getErasure` |
| `EA` | `apps/piglor-gateway/src/erasure/tests/acceptance.rs`, the module `erasure::tests::acceptance` (C6b) |
| `FS` | `apps/piglor-gateway/src/local_fork_service.rs` (in-crate tests, real Unix socket) |
| `LP` | `apps/piglor-gateway/src/local_principal.rs` (in-crate tests) |
| `KEY` | `apps/piglor-gateway/tests/keyless_erasure_recovery.rs` |
| `CLI` | `apps/pos-cli/src/host_store.rs`, the module `keyless_erasure_tests` |
| `LED` | `apps/piglor-ledger/src/lib.rs`, the module `keyless_erasure_tests` |
| `EXP` | `apps/pos-experiment/src/lib.rs`, the module `keyless_erasure_tests` |
| `ADP` | `apps/pos-gateway-conformance-adapter/src/subject/execute.rs` (in-crate tests) |
| `ADM` | `crates/pos-store/tests/erasure_admissions.rs` |
| `RDG` | `crates/pos-store/tests/erasure_redaction_generation.rs` |
| `HTTP` | `apps/piglor-gateway/src/http.rs` (in-crate tests) |
| `GCC` | `scripts/test_check_gateway_contract.py` |
| `GAP` | `apps/pos-gateway-conformance-adapter/tests/adapter_public.rs` |
| `CMD` | `apps/piglor-gateway/src/erasure_admissions/tests.rs`, the `erasure-admissions` command |

A served test `T` of `E` or `EA` that runs in every serve mode is the module
`T` with the three tests `T::local`, `T::managed_local_fork_admission` and
`T::air_gapped` (test 11). The matrix names it `T`.

## Adapters

Owner decision of 2026-11-20: a runtime acceptance test runs over both
`MemoryStore` and `SQLite` unless its behaviour depends on the adapter. Only
these exceptions stay on one adapter:

- **Q16 replica row:** the ERC1 bytes of Memory and `SQLite` differ only in the
  local-replica row. A Memory store has no file that a purge could prove
  clean.
- **Close and reopen:** only `SQLite` closes and reopens. A Memory store lives
  inside its host, so a test that restarts, or that recomposes under a new
  clock, grant or bundle, runs on `SQLite`. The `ACC` tests over both adapters
  restart only on `SQLite`.
- **Recipient-export catalog:** Memory has none.
- **Held reader:** a held `SQLite` reader makes the replica purge time out. It
  is the only transient negative. On Memory the replica is the permanent
  negative.
- **Write behind the host:** some tests write into the store while a host is
  open over it, or between two hosts: they retain an ELS1, ELO1 or ERCB1
  signed out of band, revoke the root grant, register a key, or rewrite a
  row. A Memory store lives inside its host, and no public seam takes such a
  write, so these tests run on `SQLite`. Moving them to Memory would need a
  production seam, which the owner rules out for C6a.

The column says `both`, `SQLite` or `Memory`. The `LEC` and `ACC` tests over
both adapters use the `Fixture` of `LEC`: it seeds a store on either adapter
before its host opens, and restarts only on `SQLite`. The section
[Single-adapter tests](#single-adapter-tests) lists the reason for every
other `LEC` test.

## Deviations (owner decisions of 2026-11-20)

- **ELTA1 operator-key history:** an ELTA1 that names an operator key outside
  the trust-state store's history is not yet refused. Deferred to #448 (Q9).
- **Memory and `SQLite` bytes:** they differ only in the local-replica row
  (Q16).
- **Affected Timeline deleted after freeze:** the host refuses every deletion,
  so the freeze's partition still verifies.
- **Imported Timelines (errata):** the ADR says an imported Timeline is
  unaffected. Ownership follows the data: an identity-preserving import keeps
  its exported owner, so an import of a Timeline the actor owns is affected,
  and an import of another owner's or an unowned Timeline is not.
- **Closure bound (errata):** the ADR names a 4,096-affected-Timeline
  `timeline-payload` case. The bound is 4,096 targets per category and the
  store target counts toward it, so 4,095 affected Timelines and the store
  target are the admitted edge, and one more is refused.
- **Authorization rejection provenance (errata):** the ADR says `CA(ELREJ1)`.
  The ERS1 provenance is `CA` of the core `ErasureAuthorizationRejectionV1`
  whose `authorization_provenance` is `CA(ELREJ1)`.
- **Test 6 recovery legs (errata):** a forged freeze ELS1, ERAZ1 reuse for
  another actor and an authorize or reject provenance other than `CA(ERAZ1)`
  or `CA(ELREJ1)` are refused at admission only. Such evidence can enter only
  through admission; #1425 added the recovery hooks the ADR names (attempt,
  owner result and receipt evidence).

- **`q_subject < 1` (test 8):** a composition whose `q_subject` would be
  below 1 cannot be built. The compile-time assertion D11 in
  `crates/pos-runtime/src/erasure_local_authority/policy.rs` refuses it, so no
  served test can reach it.
- **pos-cli plain submission past the quota (test 8):** pos-cli exposes no
  plain `submit_erasure_request`. The authority refuses such a submission with
  `ErasureErrorV1::PolicyConflict`, which `erasure_error_host_error` maps to
  `ErasureHostErrorV1::Conflict`, at the runtime seam.
- **Field-level unavailable reporting (test 10):** ADR-060 (wiki v52 :139)
  says the evaluator "reports unavailable fields and the ReplayClaim". The
  public offline evaluator, `ReplayClaimEvaluatorV1`, reports per artifact
  (class, digest, from and to claim, redaction state, authoritative use). It
  has no field-level output, and the Gateway has no subject-export route.
  Test 10 is therefore covered at artifact level through the runtime seam.
- **The service refuses a Fork of an affected parent after the freeze (tests
  2 and 11, ADR errata, owner 2026-11-20):** the ADR says "Forks of
  affected Timelines are always in
  scope through ELLR1, including Forks admitted by the Fork admission
  service". The service admits a Fork only of a parent that every active
  request proves unaffected (ADR-106 r3,
  `ErasureContainmentGateV1::admitted_fork_context`). Once a request has
  frozen the parent, the service answers code 5 and writes nothing, so it
  admits no Fork between the freeze and the first ERSE1. The runtime host's
  `fork_timeline_identified` admits that Fork as the first ERSE1. The owner
  keeps the refusal: the service refuses, and joining the frozen scope holds
  at the runtime seam
  (`ACC::a_fork_admitted_after_freeze_is_the_first_extension_of_the_frozen_scope`).

## Test 1: lifecycle bytes

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A full lifecycle with a `SQLite` close and reopen at every state yields identical ERS1 and ERC1 bytes | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen` | `SQLite` | Close and reopen exception. |
| The same lifecycle over `MemoryStore` and `SQLite` | `LEC::memory_and_sqlite_differ_only_in_the_local_replica_row` | both | Deviation Q16: the bytes differ only in the replica row. |
| One durable transition per driver call | `LEC::advance_commits_one_transition_per_call_until_idle` | both | |

## Test 2: the C1′ partition

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| An actor-created Timeline is affected. Another actor's Timeline, an unowned Timeline and an imported Timeline are not. | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_signed_private_freeze_commits_the_subject_closure`; `EA::the_served_partition_freezes_only_the_actors_lineage` | both; `SQLite`; `SQLite` | Deviation (errata): ADR says imported = unaffected; ownership follows the data (owner 2026-11-20). The ACC test imports with `import_timeline_with_id`: the actor's own Timeline is affected; another owner's and an unowned one are not. The EA test seeds the same imports and an unowned root into a served store: after the actor's erasure the actor's root and own import answer `403 deleted`, and every other one stays readable through the router. |
| A Fork of the actor's Timeline made by another actor inherits the actor as owner and is affected. The actor's Fork of another subject's Timeline is not affected. | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_host_timeline_stays_outside_the_frozen_scope_but_its_owned_fork_does_not`; `LEC::a_service_admitted_fork_of_a_host_timeline_freezes_by_its_inherited_owner`; `FAA::memory_fcc1_child_inherits_the_parent_owner`; `FAA::sqlite_fcc1_child_inherits_the_parent_owner`; `EA::the_fork_admission_service_forks_into_and_beside_an_erasure` | both; `SQLite`; `SQLite`; Memory; `SQLite`; `SQLite` | The runtime host's `fork_timeline` does not take the forking actor, and a child always inherits its parent's owner. So any host Fork stands for a Fork "made by another actor". The Fork admission service's FCC1 child also inherits its parent's owner, read in the commit's transaction (#1477); the FAA tests check an owned and an unowned parent on each adapter. The second LEC test forks, through the service, a listed host Timeline the actor owns: the freeze leaves the host Timeline out, so no `fork_point` lineage reaches the child, and the child freezes by its inherited owner alone. The EA test is the Gateway part, in the managed mode: the Fork admission service forks the actor's root for its own FACR1 principal, the child records the actor as owner, and the actor's erasure freezes that child with the root (two `timeline-payload` targets, both `403 deleted`). |
| A Memory host without an authorizer creates unowned Timelines | `EHP::an_owned_root_records_its_owner_at_creation`; `LP::a_created_root_is_owned_by_its_admitted_actor` | both; Memory | The LP test is the Gateway part: an unprotected Gateway (no authorizer) creates an unowned root through `POST /v1/timelines`. |
| An existing descendant | `LEC::a_signed_private_freeze_commits_the_subject_closure` | `SQLite` | Write behind the host. |
| A future Fork | `LEC::identified_forks_extend_a_frozen_scope_across_restart_and_rotation` | `SQLite` | Restart and bundle rotation. |
| A Fork admitted between the freeze and the first ERSE1 | `ACC::a_fork_admitted_after_freeze_is_the_first_extension_of_the_frozen_scope`; `EA::the_fork_admission_service_forks_into_and_beside_an_erasure` | both; `SQLite` | Covered end to end at the runtime host seam, whose `fork_timeline_identified` admits the Fork as the first ERSE1. The Gateway Fork admission service runs another host command, the FCC1 of `execute_fork_admission_command`. Deviation, ADR errata (owner 2026-11-20): the service refuses; joining holds at the runtime seam (the ACC test). After the freeze the service answers a Fork of the frozen root with code 5 (ADR-106 r3 containment) and writes nothing, and it still admits a Fork of another actor's root, which stays readable (EA test, managed mode). |
| The consent-subject actor's erasure leaves the Consent Timeline and the Erasure Host Timeline unaffected and available | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `EA::a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines` | both; `SQLite` | The EA test is the Gateway part: the consent-subject actor revokes its consent and is erased; the closure holds only its root, the Session still reads the revoked consent from the Consent Timeline, the revocation's exact retry answers its original bytes, and the store holds both host Timelines unfrozen. |
| Every client route answers 404 for the Erasure Host Timeline, and creating it does not consume the root-Timeline ceiling | `LP::host_timelines_are_hidden_from_clients_and_outside_the_ceiling`; `GW/local_fork_coordinator.rs::coordinator_refuses_a_host_timeline_as_fork_parent`; `FS::listener_refuses_the_erasure_host_timeline_as_a_fork_parent`; `EHP::a_client_root_count_leaves_out_recorded_host_roots` | `SQLite`; Memory; `SQLite`; both | Read, signal and action routes answer the 404 of an unknown Timeline (LP). The Fork-parent route is the Unix socket, not HTTP: the FS test sends a FAL1 Fork naming the recorded Erasure Host Timeline through the served listener and gets code 4 (`ParentChanged`), the code of a parent the store does not hold, with no write; the coordinator test shows the bytes equal an unknown parent's. |
| A new owned root created after the freeze, and its Forks, stay unaffected for that request | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | both | |
| An affected Timeline deleted after the freeze: the partition still verifies | `LEC::no_timeline_is_deletable_under_the_host_and_the_partition_survives` | `SQLite` | Deviation: deletion is refused under the host. The test reopens a fail-closed `SQLite` binding. |
| An actor with keys and no owned Timeline gets an ERSC1 that carries the anchor only | `LEC::an_anchor_only_scope_freezes_and_recovers` | `SQLite` | Restart. |
| The positive proof holds after a restart | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `ACC::a_fork_admitted_after_freeze_is_the_first_extension_of_the_frozen_scope`; `LEC::identified_forks_extend_a_frozen_scope_across_restart_and_rotation` | `SQLite` | Close and reopen exception. |
| The actor's Event in another actor's Timeline stays out of scope and is disclosed | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | both | The Event is still there after the receipt. Each `timeline-payload` row of the receipt carries `CA(ELD1)` as its retained disclosure. |

## Test 3: ARD1 and key binding

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Every ARD1 registration of an affected Timeline whose `data_class` matches becomes an obligation | `LEC::bound_ard1_rows_of_the_private_class_and_their_role_7_keys_are_targets`; `LEC::bound_ard1_rows_of_the_consented_class_are_targets` | `SQLite` | Write behind the host. |
| Role-0 keys come from the ADR-091 `subject:<hex>` owner | `LEC::a_signed_private_freeze_commits_the_subject_closure`; `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | `SQLite`; both | |
| Each recipient-export publication of an affected Timeline yields one negative `export-recipient` obligation per grantee | `ACC::each_export_grantee_is_one_negative_export_recipient_obligation`; `LEC::a_consented_freeze_covers_the_store_target_and_each_export_grantee` | `SQLite` | Catalog exception. The ACC test uses two grantees and asserts that each one's acknowledgement is `Negative`. |
| The actor's own role-4 recipient key is not destroyed, and the actor can still decrypt an export another subject granted it | `ACC::the_actors_recipient_key_survives_its_erasure_and_still_decrypts_a_grant` | `SQLite` | Catalog exception. Another subject's role-0 key survives too. |
| A key of another owner, or of the other class, does not become an obligation | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_consented_freeze_covers_the_store_target_and_each_export_grantee`; `LEC::the_key_list_is_bounded_on_its_own` | both; `SQLite`; both | The ACC test compares the exact closure digest, so another subject's role-0 key and the actor's own role-7 key are absent. In the consented class, no role-0 key is a target. |

## Test 3a: snapshot port parity

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Memory and `SQLite` return identical `ErasureAuthoritySnapshotV1`, store identity included | `LEA::authority_snapshot_and_store_identity_have_adapter_parity` | both | |
| A second, different `init_erasure_store_identity` is refused, and an identical one returns the recorded value | `LEA::authority_snapshot_and_store_identity_have_adapter_parity` | both | Also checked after a `SQLite` reopen. |
| A meta row count that does not match the topology fails `ProvenanceMissing` | `LEA::snapshot_rows_must_name_exactly_the_topology`; `LEA::sqlite_snapshot_refuses_a_malformed_owner_row` | Memory; `SQLite` | Cannot arise at the adapter: the rows and the topology are read from one table in one transaction, with a primary key on `timeline_owners`. Covered by the constructor test. |

## Test 3b: closure bound

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A closure of exactly 4,096 targets per category is admitted | `LEC::the_closure_bound_is_exact_at_submit_and_freeze`; `LEC::the_key_and_backup_bound_is_exact_at_submit`; `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | both | At the bound, the freeze needs a signature. |
| The 4,096-affected-Timeline `timeline-payload` case | `LEC::the_closure_bound_is_exact_at_submit_and_freeze` | both | Deviation (errata): ADR says 4,096 affected Timelines; the store target counts (owner 2026-11-20). 4,095 affected Timelines and the store target are admitted; with one more, a new request is refused at submit (`ScopeTooLarge`). |
| 4,097 targets give `400 erasure-scope-too-large` at submit | `LEC::the_closure_bound_is_exact_at_submit_and_freeze`; `LEC::the_key_and_backup_bound_is_exact_at_submit` | both | `ScopeTooLarge` at the runtime seam. The HTTP mapping belongs to C6b. |
| Growth after submit gives `Rejected` (`ScopeInvalid`) at freeze | `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | both | The ERS1 provenance is `CA` of the `ErasureFreezeFailureV1` with `ScopeInvalid` under the request's ERAZ1. |

## Test 4: retries and acknowledgements

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Transient errors auto-retry, then end in `partial-failure` | `LEC::a_transient_negative_is_retried_until_it_succeeds`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure` | `SQLite` | Held-reader exception. The ACC test runs attempt 0 and 3 retries, all timing out. |
| Permanent errors are not retried | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen`; `LEC::memory_and_sqlite_differ_only_in_the_local_replica_row` | `SQLite`; both | The driver is `Idle` after the receipt. |
| Reordered or duplicated acknowledgements produce identical bytes | `ACC::reordered_or_duplicated_acknowledgements_give_identical_receipt_bytes`; `LEC::every_crash_window_resumes_to_identical_bytes` | both; `SQLite` | The ACC test reorders, and duplicates, through the Local executor, signer and authority. The crash-window test also covers a duplicate after a crash. |
| A `partial-failure` receipt issues exactly at the deadline | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure` | `SQLite` | |
| ERRA1 fields equal §5 for attempt 0 and the retries | `LEC::a_transient_negative_is_retried_until_it_succeeds`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure`; `LEC::an_attempt_must_be_the_one_its_request_derives` | `SQLite` | Checked through `assert_attempt` for ordinals 0 to 3. |

## Test 5: rejections

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| An authorization failure commits `Rejected` with `CA(ELREJ1)` | `LEC::the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one` | `SQLite` | Runs on `SQLite` because it recomposes under another grant. Deviation (errata): the ERS1 provenance is `CA(ErasureAuthorizationRejectionV1{authorization_provenance: CA(ELREJ1)})` (owner 2026-11-20). |
| Freeze-time bound failures commit `Rejected` through `persist_freeze_rejection` | `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | both | |
| Freeze-time topology failures (not the bound) | none | | Not reachable through a public seam. Besides the bound, the Local freeze refuses an unclassified cell or an ERSC1 over its 65,536-entry cap. The 48 ELP1 rows classify every cell a closure can hold (7 artifact classes, both data classes, Artifact, Key and Backup, plus the source rows). The ERSC1 cap equals the inventory cap of 65,536 Timelines, and the Erasure Host Timeline is never affected, so no store reaches it. |
| An exact retry reproduces each rejection | `LEC::the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one`; `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | `SQLite`; both | |

## Test 6: trust and evidence

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A forged ELS1, the wrong signer key, purpose confusion and a stale body, refused at admission | `LEC::a_signed_private_freeze_commits_the_subject_closure`; `LEC::only_a_signed_owner_result_that_binds_it_acknowledges`; `LEC::a_complete_receipt_issues_signed_at_its_reached_position` | `SQLite` | Write behind the host. |
| The same evidence, refused at recovery | `LEC::recovery_refuses_owner_evidence_admission_refuses`; `LEC::recovery_refuses_receipt_evidence_admission_refuses`; `LEC::recovery_refuses_an_attempt_its_request_does_not_derive` | `SQLite` | The freeze ELS1 is admission-only (errata, owner 2026-11-20): the Local authority builds ERFAA1 only from an ELS1 it has verified. |
| ERAZ1 reuse for another actor | `LEC::the_authority_recomputes_every_eraz1_rule_of_a_plain_submission` | both | Admission-only (errata, owner 2026-11-20). |
| An ELB1 not signed by a TPS1 root, or signed by a root without the `erasure-bundle/` prefix | `LEC::a_bundle_not_signed_by_its_named_tps1_root_is_invalid`; `LEC::malformed_or_unbound_bundle_records_are_invalid`; `LER::bundle_rules_are_enforced` | Memory | Composition seam. |
| A revoked `issued_by` key | `LEC::a_revoked_bundle_root_or_signer_key_is_refused` | Memory | |
| An ELB1 whose registry digest, store identity, policy or execution binding differs | `LEC::a_bundle_for_another_policy_or_executor_is_a_mismatch`; `LEC::a_bundle_for_another_store_is_a_mismatch`; `LEC::the_executor_binding_is_the_pinned_executor_version_digest` | Memory | |
| A key-registry signer key that differs from ELB1 | `LEC::a_signer_key_the_key_registry_does_not_hold_is_a_mismatch`; `LEC::a_destroyed_signer_key_is_a_mismatch` | Memory | |
| An ELTA1 naming an operator key outside the trust-state history | none | | Deviation: deferred to #448 (Q9). |
| After an operator-key rotation, a store holding an ERQ1 stays closed until the previous anchor is restored | `LEC::an_operator_key_rotation_closes_a_store_with_requests_until_restored` | `SQLite` | |
| An expired TPS1 refuses new submissions and freezes, while recovery, `getErasure` and completion of a frozen request still verify | `LEC::an_expired_tps1_closes_new_admissions`; `ACC::an_expired_tps1_refuses_a_freeze_but_a_frozen_request_still_completes`; `LEC::attempt_0_completes_after_the_bundle_expires` | `SQLite` | The ACC test recomposes under a new clock. The projection stands in for `getErasure` at the runtime seam. |
| Recovery after the installed TPS1 is replaced still verifies an old request | `LEC::a_store_with_requests_opens_only_when_every_retained_tps1_verifies`; `LEC::committed_evidence_still_verifies_after_a_bundle_rotation` | `SQLite` | |
| An authorize or authorize-stage reject with a provenance other than `CA(ERAZ1)` or `CA(ELREJ1)` is refused | `LEC::authorization_names_the_requests_own_evidence` | both | Admission-only (errata, owner 2026-11-20). |
| TPS1 key ids `erasure-bundle/…` and `erasure-signer/<64 hex>` round-trip through the TPS1 codec, and a colon-form id is refused | `ACC::erasure_key_ids_round_trip_through_the_tps1_codec`; `LER::signer_key_ids_are_tps1_key_ids` | none (codec) | The colon form is refused on both encode and decode. |
| The signer refuses a digest it cannot re-derive | `LEC::the_signer_signs_a_freeze_only_of_an_authorized_request_and_its_body`; `LEC::the_signer_signs_an_owner_result_only_over_its_class_committed_effect`; `LEC::the_signer_signs_only_the_committed_receipt_body` | both; `SQLite`; both | The owner-result test retains forged records behind the host. |
| A routine bundle rotation is refused while a request pins the old bundle | `LEC::a_routine_rotation_waits_for_every_pin_and_a_compromise_does_not`; `LEC::a_new_signer_key_waits_for_every_pin_unless_the_tps1_revokes_it` | `SQLite` | |

## Test 7: crash windows

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Before and after the ERQ1 CAS | `LEC::a_crash_left_admission_binds_the_resubmission`; `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | Close and reopen exception. |
| Between ELS1 signing and the CAS | `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | |
| Between the pending key-destruction phase and the tombstone plus ELO1 | `LEC::every_crash_window_resumes_to_identical_bytes`; `LEC::key_destruction_completes_a_pending_phase_left_by_a_crash` | `SQLite` | |
| Between the owner effect plus ELO1 and `acknowledge_erasure` | `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | |
| A key destruction during the erasure's own access freeze succeeds | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen` | `SQLite` | |

## Single-adapter tests

Every other `LEC` test runs on one adapter, for the reason given.

| Reason | Tests |
|---|---|
| Q16 replica row | `memory_and_sqlite_differ_only_in_the_local_replica_row` (both, compared), `a_memory_store_runs_every_owner_class_as_sqlite_does` (both, compared), `a_request_whose_every_owner_succeeds_completes`, `the_projection_follows_a_driven_request` |
| Close and reopen, or a recomposition under a new clock, grant or bundle | `a_driven_lifecycle_has_identical_bytes_across_close_and_reopen`, `every_crash_window_resumes_to_identical_bytes`, `an_exact_retry_is_answered_after_new_admissions_close`, `an_expired_bundle_closes_new_admissions_but_not_a_rejection`, `an_expired_tps1_closes_new_admissions`, `the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one`, `submission_needs_a_local_composition_and_its_principal`, the rotation tests (`a_routine_rotation_waits_for_every_pin_and_a_compromise_does_not`, `a_new_signer_key_waits_for_every_pin_unless_the_tps1_revokes_it`, `committed_evidence_still_verifies_after_a_bundle_rotation`, `a_retry_recovers_on_its_retained_frozen_bundle_after_a_rotation`), the retained-TPS1 tests (`retained_trust_needs_no_check_while_the_store_holds_no_request`, `a_submitted_request_that_pins_no_trust_needs_no_retained_tps1`, `a_store_with_requests_opens_only_when_every_retained_tps1_verifies`, `an_operator_key_rotation_closes_a_store_with_requests_until_restored`) |
| Write behind the host | the root-grant revocation tests (`a_root_grant_revocation_leaves_older_requests_authorized`, `a_fresh_submission_after_a_root_grant_revocation_is_unauthorized`, `an_unauthenticated_submission_learns_nothing_of_a_held_subject`, `a_replay_is_answered_only_to_an_authorized_caller`); every test on the `OwnedStore`, `signed_freeze` or `Attempted` fixtures, which retain ELS1, ELO1 and ERCB1 records signed out of band (tests 2, 3, 4, 6 and 7 rows above); `the_signer_signs_an_owner_result_only_over_its_class_committed_effect`; the store-read and row-rewrite tests (`a_refused_submission_retains_nothing`, the ELADM1 tests from `a_submission_binds_its_bundle_and_mode_and_a_replay_keeps_them` to `a_request_without_its_admission_is_unavailable`, `an_unreadable_pin_or_signer_refuses_every_rotation`, `an_overflowing_sweep_is_skipped`) |
| Recipient-export catalog | `a_consented_freeze_covers_the_store_target_and_each_export_grantee`, `an_export_after_the_erasure_reports_its_unavailable_artifact` |
| Held reader | `a_transient_negative_is_retried_until_it_succeeds`, `the_local_replica_runs_last_and_a_held_store_is_a_transient_negative` |
| Write behind the host, `Attempted` and executor fixtures | `a_partial_failure_retries_only_while_its_subject_is_free`, `a_revoked_pinned_bundle_signs_nothing_and_frees_its_subject`, `an_owner_the_pinned_bundle_does_not_name_acknowledges_nothing`, `a_retry_pins_only_the_frozen_bundle_and_completes_at_its_reached_position`, `a_complete_request_frees_its_subject`, `an_unreadable_complete_request_never_holds_its_subject`, `an_unreadable_rejected_request_never_holds_its_subject`, `attempt_0_is_refused_once_its_bundle_is_revoked_and_rotated`, `every_owner_class_commits_its_effect_and_elo1_at_the_host_seam`, `the_outbox_replays_only_unacknowledged_commands`, `a_replica_check_that_cannot_read_the_store_is_a_host_error`, `an_unreadable_key_registry_commits_no_owner_result`, `a_key_destroyed_under_another_authorization_binds_its_existing_receipt`, `only_a_dispatched_key_command_destroys_and_only_under_an_open_fence`, `a_consistent_command_outside_the_attempt_is_not_dispatched`, `an_artifact_is_redacted_only_once_every_key_it_depends_on_is_tombstoned`, `a_frozen_request_whose_bundle_is_revoked_no_longer_holds_its_subject`, `an_undecodable_admission_fails_the_submission_closed`, `a_submission_without_a_binding_epoch_retains_nothing`, `the_root_grant_must_match_the_composition_and_name_the_operation` |
| Close and reopen with the operator's admissions record written behind the host (#1408) | `a_closed_record_answers_the_exact_replay_and_retains_nothing`, `an_admitted_request_freezes_and_completes_while_admissions_are_closed`, `an_unreadable_record_fails_closed_for_a_fresh_submission_only` |
| No store, or composition only (Memory) | `composition_errors_have_stable_payload_free_messages`, `the_compiled_policy_carries_the_owner_constants`, `the_classification_is_exactly_the_owner_table`, `a_bundle_owner_of_another_class_is_unencodable`, `a_host_without_an_authority_has_no_outbox`, `a_key_less_root_skips_only_the_execution_binding`, `a_bundle_without_its_erasure_host_timeline_is_a_mismatch` |

Moved onto the two-adapter `Fixture` in C6a: `a_local_submission_is_derived_idempotent_and_bound_to_its_body`, `a_subject_has_one_pre_terminal_request`, `the_subject_quota_admits_exactly_its_share`, `the_quota_is_shared_by_the_principals_actors`, `authorization_names_the_requests_own_evidence`, `a_root_grant_admits_the_last_position_of_its_window`, `the_closure_bound_is_exact_at_submit_and_freeze`, `the_key_and_backup_bound_is_exact_at_submit`, `the_key_list_is_bounded_on_its_own`, `the_signer_signs_a_freeze_only_of_an_authorized_request_and_its_body`, `the_signer_signs_only_the_committed_receipt_body`, `a_refused_signature_defers_the_step`, `advance_commits_one_transition_per_call_until_idle`, `advance_passes_over_a_request_it_cannot_step`, `the_projection_never_tells_an_unknown_id_from_another_subjects`, the plain-submission tests (`the_authority_recomputes_every_eraz1_rule_of_a_plain_submission`, `the_authority_recomputes_every_erq1_field_of_a_plain_submission`, `a_plain_submission_cannot_bypass_the_subject_checks`), and the `local_authority` fixture tests (`the_local_authority_refuses_an_unbound_freeze`, `the_local_authority_recomputes_every_fork_scope_extension`, `the_local_authority_refuses_an_unknown_attempt_or_unpinned_acknowledgement`, `a_receipt_needs_an_active_attempt_and_correction_and_resolution_are_refused`, `destruction_goes_only_to_an_owner_the_bundle_names`, `committed_freeze_evidence_pins_one_policy_and_trust`, `recovery_needs_a_resolvable_bundle_and_the_issue_position`).

The composition tests of test 6 (`a_root_signed_bundle_that_matches_the_binary_and_store_composes` to `a_signer_owner_id_that_is_no_key_registry_owner_is_a_mismatch`) compose over a `MemoryStore`; composition does not open a host.

## Test 8: the Gateway

Every Gateway test serves a `SQLite` store: the Local erasure authority is
served only over `SQLite`.

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A missing Idempotency-Key gives 400; an exact retry returns the same 202 and `erasure_id`; the same key with another `scope` gives `409 idempotency-conflict` | `E::an_exact_retry_answers_the_same_receipt_bytes` | `SQLite` | Also after a restart. |
| The exact retry after an ELP1 change (new release) | `LEC::a_submission_binds_its_bundle_and_mode_and_a_replay_keeps_them`; `E::an_exact_retry_answers_the_same_receipt_bytes`; `E::a_crash_left_admission_binds_the_resubmission` | `SQLite` | The 202 is a function of the retained ERQ1 and ELADM1 alone (D5), so a retry answers the pinned policy, bundle and mode profile, never the current ones. The ELP1 is compiled into the binary, so no test can serve one store under two ELP1s; the LEC test replays under another mode binding, and the E crash-left test answers a binding the Gateway does not compile. |
| The exact retry after a root-chain advance | `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_replay_is_answered_only_to_an_authorized_caller`; `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_root_grant_revocation_leaves_older_requests_authorized` | `SQLite` | ADR errata (owner 2026-11-20): mapped to the runtime host seam. The Gateway cannot drive it: no Gateway route writes the root chain; only offline provisioning does. |
| An `erasure.read`-only grant is refused on `requestErasure` (403), and an `erasure.request`-only grant gets 404 on `getErasure` | `E::each_erasure_operation_needs_its_own_grant` | `SQLite` | |
| Two parallel submissions with different keys and classes give one 202 and one `429 resource-limit-exceeded` | `E::parallel_requests_of_one_subject_admit_one` | `SQLite` | No `Retry-After`. |
| Resubmission after `partial-failure` gives 202 | `E::each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next` | `SQLite` | |
| With `A` actors, the `q_subject`th request gives 202 and the next `409 erasure-quota-exhausted` | `E::a_subject_past_its_quota_is_refused_for_good`; `LEC::the_subject_quota_admits_exactly_its_share`; `LEC::the_quota_is_shared_by_the_principals_actors` | `SQLite`; both; both | Lowered, test-only limits (D11): 514 request heads, two actors, `q_subject = 1`. |
| Every actor's quota used up, then a restart: recovery succeeds and the total stays at most `maximum_requests - reserve` | `EA::every_actors_used_quota_holds_across_a_restart` | `SQLite` | Both actors use their one request; after the restart each projection reads, each exact retry answers its original bytes, and each next request is `409`, so the store holds exactly `514 - 512 = 2` requests. |
| Composition with `q_subject < 1` refuses to serve `erasure.*` | none | | Deviation: refused at compile time by the D11 assertion in `policy.rs`; no composition can reach it. |
| pos-cli's plain `submit_erasure_request` past the quota is refused (`PolicyConflict`); a corrected submission is refused | `LEC::a_plain_submission_cannot_bypass_the_subject_checks`; `LEC::a_receipt_needs_an_active_attempt_and_correction_and_resolution_are_refused` | both | Deviation: pos-cli has no plain submit. The authority's `PolicyConflict` is mapped to `ErasureHostErrorV1::Conflict` by `erasure_error_host_error`. |
| A reaches `partial-failure`, B runs its own attempt 0, and A's retry is refused until B is no longer pre-terminal and has no active attempt | `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_partial_failure_retries_only_while_its_subject_is_free` | `SQLite` | ADR errata (owner 2026-11-20): mapped to the runtime host seam. The Gateway cannot drive it: a retry is driver-internal and needs a transient negative, which only the held-reader fixture behind the host gives. |
| After a TPS1 revocation of the signer, a request pinned to the old bundle does not block resubmission, and a `partial-failure` request retries under the new bundle without a new submission | `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_revoked_pinned_bundle_signs_nothing_and_frees_its_subject`; `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_frozen_request_whose_bundle_is_revoked_no_longer_holds_its_subject`; `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_retry_recovers_on_its_retained_frozen_bundle_after_a_rotation` | `SQLite` | ADR errata (owner 2026-11-20): mapped to the runtime host seam. The Gateway cannot drive it: a served Gateway has one deployment trust state and bundle, and revoking the signer needs a new TPS1 and a compromise re-provisioning between serves. |
| A root-chain revocation after submission does not break recovery or retries | `crates/pos-runtime/tests/local_erasure_composition_public.rs::a_root_grant_revocation_leaves_older_requests_authorized` | `SQLite` | ADR errata (owner 2026-11-20): mapped to the runtime host seam. The Gateway cannot drive it: no Gateway route revokes the root grant. |
| No grant gives 403 | `E::each_erasure_operation_needs_its_own_grant`; `E::a_retained_only_scope_is_refused_after_the_decision` | `SQLite` | |
| Revoked consent still gives 202 | `EA::a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines`; `E::both_erasure_operations_are_consent_exempt` | `SQLite`; none | The EA test revokes the actor's consent through `POST /v1/me/consent-revocations`, sees the governed Timeline creation refused `403 revoked`, and then gets `202`. |
| A retained-only scope gives `400 erasure-scope-retained` | `E::a_retained_only_scope_is_refused_after_the_decision` | `SQLite` | After the decision. |
| `400 erasure-scope-too-large` at submit (test 3b) | `LEC::the_closure_bound_is_exact_at_submit_and_freeze`; `E::every_submit_refusal_has_its_answer` | both; none | The runtime gives `ScopeTooLarge`; the Gateway maps it to `400 erasure-scope-too-large`. A served test would need 4,095 seeded Timelines. |

## Test 9: `getErasure` and the golden check

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Byte-identical 404s for an unknown id, another subject's id and a missing grant | `E::get_erasure_answers_one_not_found`; `E::each_erasure_operation_needs_its_own_grant` | `SQLite` | Also past the denial-record bound. |
| No topology, digest or owner value appears in responses | `EA::the_served_partition_freezes_only_the_actors_lineage`; `E::get_erasure_answers_one_not_found` | `SQLite` | The EA golden check scans every erasure answer of a lifecycle (the 202, its retry, every projection, the `409`, the subject's read and both 404s), headers included. Every 64-hex token must be a declared digest (key digest, policy, bundle, mode profile) or the body's own `provenance.digest`; every ULID token must be an `erasure_id` the request named; no signer owner or `subject:` owner appears. So no Timeline, actor, owner, store identity or other state digest does. |
| ... nor in logs | `apps/piglor-gateway/src/local_erasure_composition/tests.rs::a_wake_reports_only_a_changed_deferred_count` | none | The Gateway has no in-test log capture seam: it writes straight to process stderr (`announce!`). The erasure paths write three payload-free lines (`local_erasure_composition.rs`): the startup sweep (`LocalErasureSweepV1`, which is `Swept(count)` or `Skipped`), the driver stop (`panicked: bool`), and the deferred request count, tested as a string. None carries an id or digest. |
| ... nor in metrics | none | | piglor-gateway exports no metrics; there is nothing to check. |
| `generation` never decreases | `E::each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next`; `EA::the_served_partition_freezes_only_the_actors_lineage`; `LEC::the_projection_follows_a_driven_request` | `SQLite` | |
| Claim strength never increases | `EA::the_served_partition_freezes_only_the_actors_lineage`; `EA::a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines` | `SQLite` | `assert_monotonic` checks each observed projection against the previous one with `ErasureReplayClaimV1::weakened_to`. |

## Test 10: export, erasure and the offline evaluator

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A subject-scoped export, then erasure, then the post-erasure export through the public offline evaluator, which reports the unavailable artifact and the weakened claim | `LEC::an_export_after_the_erasure_reports_its_unavailable_artifact` | `SQLite` | Recipient-export catalog exception. Deviation: artifact level, not field level, and through the runtime seam, not the Gateway (see the deviations). |

## Conformance cases

Owner 2026-11-20: mapped, no new adapter compositions or fixture
regeneration. The Gateway client conformance layer keeps its erasure cases
`pos.10`, `den.10`, `den.11`, `den.12`, `res.2` and `mal.6`.

Owner 2026-11-23, for #1407 only: the gateway-client-conformance fixtures
and oracles are regenerated, overriding the no-regeneration rule above. The
observation gains its optional `headers` member (`cache-control` only), so
every expected exchange now carries `Cache-Control: no-store`, and the
`pos.10` erasure read carries `redaction_generation: 0`. No composition is
added: there is still no driven-erasure composition. See *Follow-up F2*.

The two refusals without a conformance case are covered by these tests:

| Refusal | Tests |
|---|---|
| `409 erasure-quota-exhausted` | `E::a_subject_past_its_quota_is_refused_for_good`; `EA::every_actors_used_quota_holds_across_a_restart`; `LEC::the_subject_quota_admits_exactly_its_share`; `LEC::the_quota_is_shared_by_the_principals_actors` |
| `400 erasure-scope-too-large` | `E::every_submit_refusal_has_its_answer` (the HTTP mapping); `LEC::the_closure_bound_is_exact_at_submit_and_freeze`; `LEC::the_key_and_backup_bound_is_exact_at_submit` (`ScopeTooLarge` at submit) |

## Test 11: key-less recovery and serve modes

### Key-less recovery

Slice C5d (#1450) added these tests. Each consumer opens a Gateway store that
holds a Local erasure request with the shared loader's key-less composition
(`LocalErasureRecoveryV1`: ELB1, ELB1S and the release anchor from
`$CREDENTIALS_DIRECTORY`, the TPS1 from the deployment trust state, no signer
key). A store without a recorded erasure identity opens with the closed
composition. Missing or invalid trust inputs over a store with an identity
are a typed refusal, never a fall back to the closed composition.

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| The shared loader recovers a Gateway store that holds ERQ1 records without a private key | `KEY::valid_credentials_recover_the_store_and_its_request`; `KEY::the_closed_composition_cannot_recover_a_store_that_holds_a_request`; `KEY::missing_or_invalid_credentials_are_typed_refusals` | `SQLite` | The store is one the Gateway provisioned. The closed composition refuses it, which is why every consumer needs the key-less one. |
| pos-cli recovers it | `CLI::valid_credentials_recover_a_store_that_holds_a_request`; `CLI::a_store_without_an_identity_opens_and_works`; `CLI::missing_credentials_are_a_typed_refusal`; `CLI::an_invalid_bundle_or_signature_is_a_typed_refusal` | `SQLite` | Through `HostedCliStore::open_with_trust`. |
| piglor-ledger recovers it | `LED::valid_credentials_recover_a_store_that_holds_a_request`; `LED::a_store_without_an_identity_opens_and_works`; `LED::missing_credentials_are_a_typed_refusal`; `LED::an_invalid_bundle_or_signature_is_a_typed_refusal` | `SQLite` | The read-only ledger path composes on its read-only handle. |
| pos-experiment recovers it | `EXP::valid_credentials_recover_a_store_that_holds_a_request`; `EXP::a_store_without_an_identity_opens_and_works`; `EXP::missing_credentials_are_a_typed_refusal`; `EXP::an_invalid_bundle_or_signature_is_a_typed_refusal` | `SQLite` | |
| The conformance adapter recovers it | `ADP::only_the_erasure_bundle_compositions_record_an_erasure_identity` | `SQLite`; Memory (`open`) | N/A: the adapter never acts as a key-less root; its erasure compositions hold the signer (D21, owner 2026-11-20). Each sub-case serves a fresh store. The test composes every adapter composition: each one without a fixture erasure bundle serves a store with no recorded erasure identity under the closed composition, so it has no ERQ1 to recover. It holds in any environment: on a networked host `authorized-air-gapped` does not compose (predicate 6, `air-gapped-no-route`, refuses it), and where it composes it records no identity; the adapter's existing namespace tests cover that case. The `authorized-erasure` compositions record one, and compose through the `serve` loader, which refuses to start without the signer credential. |

### The served lifecycle suite in every serve mode

The served lifecycle suite runs as one test per serve mode (owner decision of
2026-11-20). Each suite function takes the mode, and `in_every_serve_mode!`
in `apps/piglor-gateway/src/erasure/tests.rs` gives it the tests `local`,
`managed_local_fork_admission` and `air_gapped`. Each mode is composed on the
production entry points of its `serve`:

- **Local:** `LocalErasureServeV1::for_serve` reads the four erasure
  credentials, the host opens with that composition, `LocalErasureServeV1::start`
  runs the startup sweep, and `local_gateway` composes the Gateway, as
  `serve_http` does. The host does not run `bind_gateway_mode_v1`: the
  fixture bound the store to the Local mode when it was created, and the host
  attaches to that binding under a binding whose predicates the test vouches
  for (`test_attach_host` with `test_binding`).
- **Managed Local Fork admission:** `serve_managed_local_fork_admission` with
  `--require-local-erasure`. The test seam
  `local_fork_service::tests::start_managed_for_test` runs its steps in order:
  `managed_credentials_and_erasure` reads the three Fork admission and the
  four erasure credentials from one unit directory, the host opens, the
  production `bind_gateway_mode_v1` binds it over the Fork-admission socket,
  the startup sweep runs, and `open_with_credentials` and `start_listener`
  start the Gateway with its Fork-admission slot and the listener. It is the
  only mode that runs the production `bind_gateway_mode_v1`. The loaded
  FACR1 registers no peer of the test process, whose uid is its service uid,
  so the listener runs the current-peer credentials of the same seeds, whose
  FAH1 the world provisioned.
- **Air-Gapped:** the Local composition's steps over a store the fixture
  bound to the Air-Gapped mode, attached under a vouched Air-Gapped binding
  (`test_attach_host` with `test_binding`), not through
  `bind_gateway_mode_v1`: predicate 6, `air-gapped-no-route`, cannot hold on
  a networked test host (`main.rs` runs it in a network namespace). The
  deployment seeds the trust state store with its bundled TPS1 (D17), and the
  world's trust state stands for it.

Every mode opens its host with the test's recovery limits, so the quota tests
can lower them (D11). The suite covers the served bullets of tests 1, 2, 4, 8
and 9. Tests 3 to 7 and 10 have no served bullet; the serve mode selects only
the composition, the binding and the listener over the same host, so their
runtime-seam rows hold in every mode.

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| The managed Local Fork admission mode runs the Gateway lifecycle suite: the served bullets of tests 1, 2, 4, 8 and 9 (tests 3 to 7 and 10 have no served bullet) | `E::an_exact_retry_answers_the_same_receipt_bytes`; `E::each_erasure_operation_needs_its_own_grant`; `E::get_erasure_answers_one_not_found`; `E::parallel_requests_of_one_subject_admit_one`; `E::a_retained_only_scope_is_refused_after_the_decision`; `E::each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next`; `E::a_subject_past_its_quota_is_refused_for_good`; `EA::the_served_partition_freezes_only_the_actors_lineage`; `EA::every_actors_used_quota_holds_across_a_restart`; `EA::a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines`, each `::managed_local_fork_admission` | `SQLite` | Submission, the drive to the first receipt, the `getErasure` projection, the exact retry (also after a restart), the quota, consent revocation, the 404s and the disclosure golden check. A restart stops the listener and serves the store again. |
| The managed mode's Fork admission service | `EA::the_fork_admission_service_forks_into_and_beside_an_erasure` | `SQLite` | Test 2 through the service: the child inherits its parent's owner (the actor's root's child is the actor's, the other actor's root's child is the other actor's), and the post-freeze refusal is an ADR errata (see the deviations). |
| Air-Gapped passes the same suite with the bundled TPS1 | The same ten suite functions, each `::air_gapped` | `SQLite` | The projection discloses `gateway-mode-air-gapped-v1`. The consent test asserts the same `403 revoked` and exact-retry `200` as Local: an Air-Gapped binding only fixes the authorizer's revocation-freshness claim to current (D10), which every serve composition already holds. |
| The Local serve mode (the baseline of both) | The same ten suite functions, each `::local` | `SQLite` | |

## Follow-up F3: closing `requestErasure` (#1408)

The operator closes new erasure admissions durably with
`piglor-gateway erasure-admissions close <sqlite-path>` and reopens them
with `open`; `status` prints the record. `close` and `open` hold the
store's exclusive mode lock, so they refuse to run beside a live `serve`
(owner decision of 2026-11-23: a foreign commit would make the serving host
fail closed, `getErasure` and the driver included, until it restarts); the
operator stops `serve`, changes the record and starts `serve` again.
`status` takes the shared lock and only reads the record. Every verb runs in every execution
mode. The record is
one singleton row (`erasure_admissions`), absent meaning open. The Local
erasure host reads it on every submission and applies it after the
exact-replay check, so only a fresh request is refused: `LocalErasureSubmitErrorV1::OperatorClosed`,
which the Gateway answers `503 erasure-admissions-closed`, not retryable.
`getErasure`, the driver and its startup sweep never read it.

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A store without the record is open; each change returns the state it replaced | `ADM::a_store_without_the_record_is_open`; `ADM::each_change_returns_the_state_it_replaced` | both | |
| A closed record survives a reopen of the store file, and `open` restores | `ADM::a_closed_record_survives_a_reopen_and_open_restores` | `SQLite` | |
| An unreadable record fails and is left unchanged | `ADM::an_unreadable_record_fails_and_is_left_unchanged` | `SQLite` | A row the `CHECK` refuses, written with the checks off. |
| A closed record refuses a fresh submission with the new variant | `LEC::a_closed_record_refuses_a_fresh_submission` | both | The Memory store is closed before its host owns it. |
| An exact replay of an installed request is still answered while closed, and a refused fresh submission retains nothing | `LEC::a_closed_record_answers_the_exact_replay_and_retains_nothing` | `SQLite` | The refusal comes before the subject checks; reopening lets the next request reach them again. |
| An admitted request still freezes and completes while closed, after the startup sweep | `LEC::an_admitted_request_freezes_and_completes_while_admissions_are_closed` | `SQLite` | |
| A record the host cannot read fails closed | `LEC::an_unreadable_record_fails_closed_for_a_fresh_submission_only` | `SQLite` | `ErasureHostErrorV1::AdapterFailure` for a fresh request (a retryable `503 temporarily-unavailable` at the Gateway); the exact replay is still answered. |
| Closed admissions refuse `POST` with `503 erasure-admissions-closed`; `GET` answers and the admitted request reaches its first receipt; both hold after a restart; reopened, `POST` gives `202` | `E::closed_admissions_refuse_new_erasures_and_finish_admitted_ones`; `E::every_submit_refusal_has_its_answer` | `SQLite`; none | Local serve mode. The command runs between serves. |
| `close`, `open` and `status` output; Air-Gapped stores accepted; a served store refuses `close`/`open` but answers `status`; unbound, locked and unreadable stores and other arguments refused | `CMD::close_open_and_status_report_the_record`; `CMD::an_air_gapped_store_closes_and_reopens`; `CMD::unbound_locked_and_unreadable_stores_are_refused`; `CMD::a_serving_store_refuses_changes_but_answers_status`; `CMD::other_arguments_are_a_usage_error`; `apps/piglor-gateway/src/main.rs::erasure_admissions_subcommand_is_dispatched_by_the_binary_entrypoint` | `SQLite` | |

## Follow-up F2: the supported client-cache contract (#1407)

The Gateway v1 contract states the client-cache rule (README, *Client
cache*): every response carries `Cache-Control: no-store`, a supported
client never persists a managed representation, and it re-reads and drops
its copies once `getErasure` shows `client-cache-signal` positive. RFC 9111
§5.2.2.5 makes `no-store` alone insufficient for privacy, so the client rule
carries the guarantee; `Clear-Site-Data` is a precedent only and never sent.
One router layer (`http::finish`) adds the header to every answer of every
router, problems, unrouted paths and the non-v1 routes `/`, `/ledger` and
`/health` included. `openapi.json` declares it `required` on every operation
response through the shared `components/headers/CacheControl` (`const:
"no-store"`), and the baseline freezes it.

The store's redaction generation is a new store-wide counter: the number of
ELCG1 cache generations the store has committed. `commit_local_owner_effect`
raises it by one in the same adapter transaction that newly retains an
ELCG1 (`PreparedLocalOwnerEffectV1::raises_redaction_generation`); a repeated
ELCG1 retains nothing new and raises nothing, and a generation that cannot
be raised fails the commit, so neither changes. `SQLite` keeps it in the
singleton table `erasure_redaction_generation` (absent until the first
commit, validated like the other erasure tables); `MemoryStore` keeps it for
the instance's life, like its other erasure records. The per-request ELCG1
`generation` is unchanged (the attempt's admitted position, 2 for attempt 0).
`getErasure` always carries it as `redaction_generation` when a Local
erasure composition serves it, 0 before any commit; the schema keeps the
member optional for append-only compatibility.

Wholly erased resources keep their refusals: a frozen Timeline is
`403 deleted` and an erased revision `410 deleted`. The contract states that
`availability.withheld[{member, reason: "deleted"}]` with state `partial` or
`unavailable` applies to a representation that mixes erased and kept
members; no served representation does today.

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Every response carries `Cache-Control: no-store`: a `200`, a `202`, problems, the unprovisioned `401`, `404`s, a `405`, a redirect and the non-v1 routes | `HTTP::every_router_marks_every_answer_no_store`; `HTTP::every_protected_route_refuses_an_unprovisioned_host_before_its_body`; every `E` and `EA` test through `Served::send` and `status_of` | Memory; `SQLite` | `Served::send` fails any answer without exactly `no-store`, so every served erasure test checks it on each answer. |
| The golden disclosure check scans the new header and passes | `EA::the_served_partition_freezes_only_the_actors_lineage` (`Disclosure::check`) | `SQLite` | `no-store` carries neither a digest nor a ULID token. |
| After the first receipt `redaction_generation` has risen, it never decreases across successive reads and a restart, the claim is weakened and the frozen Timeline's Events are `403 deleted` | `E::each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next` | `SQLite` | Every serve mode. It counts one ELCG1 per request at each first receipt (1, then 2). |
| A served projection carries `redaction_generation: 0` before any commit | `E::get_erasure_answers_one_not_found` | `SQLite` | Every serve mode. |
| The counter starts at 0, rises exactly once per new ELCG1 commit and for no other effect, a repeated ELCG1 raises nothing, and a refused commit changes nothing | `RDG::each_new_cache_generation_raises_it_once_on_both_adapters` | both | |
| A `SQLite` counter persists across a reopen | `RDG::a_sqlite_generation_survives_a_reopen` | `SQLite` | |
| A counter that cannot be raised rolls the ELCG1 commit back; an unreadable one fails closed | `RDG::a_sqlite_generation_that_cannot_be_raised_rolls_the_commit_back`; `RDG::an_unreadable_sqlite_generation_fails_closed`; `crates/pos-store/src/memory/local_erasure.rs::a_generation_that_cannot_be_raised_refuses_the_commit` | both | `SQLite` refuses past `i64::MAX`, Memory past `u64::MAX`. |
| Only an ELCG1 raises it | `LER::each_owner_effect_retains_only_its_own_record` | none | |
| The counter rises across two requests; each ELCG1 keeps `generation` 2 for attempt 0 | `LEC::the_redaction_generation_rises_across_requests` | `SQLite` | |
| The contract declares the header on every response and the optional member; an example that states `headers` states them exactly | `GCC::test_every_response_is_declared_no_store`; `GCC::test_the_redaction_generation_is_an_optional_erasure_member`; `GCC::test_an_example_states_its_response_headers_exactly` | none | New examples `client-cache-erasure-redacted`, `client-cache-frozen-timeline-deleted` and `client-cache-unrouted-path`, frozen by `--freeze`; no frozen example was edited. |
| The conformance observation carries `cache-control` only | `GAP::an_observation_carries_the_cache_control_header_only`; `GAP::every_family_meets_its_oracle_identically_in_local_and_air_gapped`; `apps/pos-gateway-conformance-adapter/tests/provider_dispatch_public.rs` | Memory; `SQLite` | The regenerated fixtures expect `no-store` on every sent exchange. |
