# ADR-136 acceptance matrix

This table maps each bullet of the ADR-136 acceptance tests (Redmine #1414) to
the public-seam tests that cover it. Slice C6a (#1469) covers tests 1 to 7 at
the runtime seams. Slices C6b and C6c add tests 8 to 11 in the section at the
end.

## Paths

| Short name | Path |
|---|---|
| `LEC` | `crates/pos-runtime/tests/local_erasure_composition_public.rs` |
| `ACC` | `crates/pos-runtime/tests/local_erasure_composition/acceptance.rs`, the module `local_erasure_composition_public::acceptance` |
| `EHP` | `crates/pos-runtime/tests/erasure_host_public.rs` |
| `LEA` | `crates/pos-store/tests/local_erasure_adapter_public.rs` |
| `LER` | `crates/pos-core/tests/local_erasure_records_public.rs` |
| `GW` | `apps/piglor-gateway/src` (in-crate tests) |

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

The column says `both`, `SQLite` or `Memory`. **Not yet parameterized** marks
an existing `LEC` test whose behaviour does not depend on the adapter but that
still runs on `SQLite` only. Its `LocalStore` fixture reopens the store by path
between the signing step and the retaining step, and Memory cannot do that.
Moving such a test onto the driver fixture that `ACC` uses is test-only work
that C6a has not done.

## Deviations (owner decisions of 2026-11-20)

- **ELTA1 operator-key history:** an ELTA1 that names an operator key outside
  the trust-state store's history is not yet refused. Deferred to #448 (Q9).
- **Memory and `SQLite` bytes:** they differ only in the local-replica row
  (Q16).
- **Affected Timeline deleted after freeze:** the host refuses every deletion,
  so the freeze's partition still verifies.

## Test 1: lifecycle bytes

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A full lifecycle with a `SQLite` close and reopen at every state yields identical ERS1 and ERC1 bytes | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen` | `SQLite` | Close and reopen exception. |
| The same lifecycle over `MemoryStore` and `SQLite` | `LEC::memory_and_sqlite_differ_only_in_the_local_replica_row` | both | Deviation Q16: the bytes differ only in the replica row. |
| One durable transition per driver call | `LEC::advance_commits_one_transition_per_call_until_idle` | `SQLite` | Not yet parameterized. |

## Test 2: the C1′ partition

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| An actor-created Timeline is affected. Another actor's Timeline, an unowned Timeline and an imported Timeline are not. | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_signed_private_freeze_commits_the_subject_closure` | both; `SQLite` | The imported Timeline comes through the generic `import_timeline`, which creates a fresh unowned root. **Open question for the owner:** the ID-preserving `import_timeline_with_id` and `import_timeline_verified_v1` keep the exported `owner`. So an imported copy of a Timeline the actor owns would be affected. |
| A Fork of the actor's Timeline made by another actor inherits the actor as owner and is affected. The actor's Fork of another subject's Timeline is not affected. | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_host_timeline_stays_outside_the_frozen_scope_but_its_owned_fork_does_not` | both; `SQLite` | The runtime host's `fork_timeline` does not take the forking actor, and a child always inherits its parent's owner. So any host Fork stands for a Fork "made by another actor". The Gateway attribution belongs to C6b. |
| A Memory host without an authorizer creates unowned Timelines | `EHP::an_owned_root_records_its_owner_at_creation` | both | Runtime part only: `create_timeline` records no owner. The Gateway composition without an authorizer belongs to C6b. |
| An existing descendant | `LEC::a_signed_private_freeze_commits_the_subject_closure` | `SQLite` | Not yet parameterized. |
| A future Fork | `LEC::identified_forks_extend_a_frozen_scope_across_restart_and_rotation` | `SQLite` | Restart and bundle rotation. |
| A Fork admitted between the freeze and the first ERSE1 | `ACC::a_fork_admitted_before_the_first_extension_joins_the_frozen_scope` | both | Covered end to end at the runtime host seam. The Gateway Fork admission service belongs to C6b. |
| The consent-subject actor's erasure leaves the Consent Timeline and the Erasure Host Timeline unaffected and available | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | both | Runtime part: a root opened with `open_root_timeline`, as the Gateway opens its Consent Timeline, and the Erasure Host Timeline both stay readable. The Gateway Consent Timeline with its consent Events belongs to C6b. |
| Every client route answers 404 for the Erasure Host Timeline, and creating it does not consume the root-Timeline ceiling | `GW/local_principal.rs::host_timelines_are_hidden_from_clients_and_outside_the_ceiling`; `GW/local_fork_coordinator.rs::coordinator_refuses_a_host_timeline_as_fork_parent`; `EHP::a_client_root_count_leaves_out_recorded_host_roots` | `SQLite`; both | The Gateway routes are C6b's to extend. |
| A new owned root created after the freeze, and its Forks, stay unaffected for that request | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | both | |
| An affected Timeline deleted after the freeze: the partition still verifies | `LEC::no_timeline_is_deletable_under_the_host_and_the_partition_survives` | `SQLite` | Deviation: deletion is refused under the host. The test reopens a fail-closed `SQLite` binding. |
| An actor with keys and no owned Timeline gets an ERSC1 that carries the anchor only | `LEC::an_anchor_only_scope_freezes_and_recovers` | `SQLite` | Restart. |
| The positive proof holds after a restart | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `ACC::a_fork_admitted_before_the_first_extension_joins_the_frozen_scope`; `LEC::identified_forks_extend_a_frozen_scope_across_restart_and_rotation` | `SQLite` | Close and reopen exception. |
| The actor's Event in another actor's Timeline stays out of scope and is disclosed | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | both | The Event is still there after the receipt. Each `timeline-payload` row of the receipt carries `CA(ELD1)` as its retained disclosure. |

## Test 3: ARD1 and key binding

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Every ARD1 registration of an affected Timeline whose `data_class` matches becomes an obligation | `LEC::bound_ard1_rows_of_the_private_class_and_their_role_7_keys_are_targets`; `LEC::bound_ard1_rows_of_the_consented_class_are_targets` | `SQLite` | Not yet parameterized. |
| Role-0 keys come from the ADR-091 `subject:<hex>` owner | `LEC::a_signed_private_freeze_commits_the_subject_closure`; `ACC::the_c1_partition_freezes_exactly_the_actors_lineage` | `SQLite`; both | |
| Each recipient-export publication of an affected Timeline yields one negative `export-recipient` obligation per grantee | `ACC::each_export_grantee_is_one_negative_export_recipient_obligation`; `LEC::a_consented_freeze_covers_the_store_target_and_each_export_grantee` | `SQLite` | Catalog exception. The ACC test uses two grantees and asserts that each one's acknowledgement is `Negative`. |
| The actor's own role-4 recipient key is not destroyed, and the actor can still decrypt an export another subject granted it | `ACC::the_actors_recipient_key_survives_its_erasure_and_still_decrypts_a_grant` | `SQLite` | Catalog exception. |
| A key of another owner, or of the other class, does not become an obligation | `ACC::the_c1_partition_freezes_exactly_the_actors_lineage`; `LEC::a_consented_freeze_covers_the_store_target_and_each_export_grantee`; `LEC::the_key_list_is_bounded_on_its_own` | both; `SQLite` | The ACC test compares the exact closure digest, so another subject's role-0 key and the actor's own role-7 key are absent. In the consented class, no role-0 key is a target. |

## Test 3a: snapshot port parity

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Memory and `SQLite` return identical `ErasureAuthoritySnapshotV1`, store identity included | `LEA::authority_snapshot_and_store_identity_have_adapter_parity` | both | |
| A second, different `init_erasure_store_identity` is refused, and an identical one returns the recorded value | `LEA::authority_snapshot_and_store_identity_have_adapter_parity` | both | Also checked after a `SQLite` reopen. |
| A meta row count that does not match the topology fails `ProvenanceMissing` | `LEA::snapshot_rows_must_name_exactly_the_topology`; `LEA::sqlite_snapshot_refuses_a_malformed_owner_row` | Memory; `SQLite` | **Open at the adapter level.** The constructor test and the malformed-row test cover the check. No adapter can produce a count mismatch: both read the rows and the topology from one table in one transaction, and `timeline_owners` is keyed by `timeline_id`. |

## Test 3b: closure bound

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A closure of exactly 4,096 targets per category is admitted | `LEC::the_closure_bound_is_exact_at_submit_and_freeze`; `LEC::the_key_and_backup_bound_is_exact_at_submit`; `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | `SQLite`; both | At the bound, the ACC test's freeze needs a signature. |
| The 4,096-affected-Timeline `timeline-payload` case | none | | **Open: needs an owner decision.** Every closure holds the store target, whose Artifact cell is `client-cache-signal`. So 4,096 affected Timelines make 4,097 Artifact targets, and the bound (`extend_bounded` in `erasure_local_authority/freeze.rs`, over all targets) refuses them. |
| 4,097 targets give `400 erasure-scope-too-large` at submit | `LEC::the_closure_bound_is_exact_at_submit_and_freeze` | `SQLite` | `ScopeTooLarge` at the runtime seam. The HTTP mapping belongs to C6b. |
| Growth after submit gives `Rejected` (`ScopeInvalid`) at freeze | `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | both | The ERS1 provenance is `CA` of the `ErasureFreezeFailureV1` with `ScopeInvalid` under the request's ERAZ1. |

## Test 4: retries and acknowledgements

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Transient errors auto-retry, then end in `partial-failure` | `LEC::a_transient_negative_is_retried_until_it_succeeds`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure` | `SQLite` | Held-reader exception. The ACC test runs attempt 0 and 3 retries, all timing out. |
| Permanent errors are not retried | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen`; `LEC::memory_and_sqlite_differ_only_in_the_local_replica_row` | `SQLite`; both | The driver is `Idle` after the receipt. |
| Reordered or duplicated acknowledgements produce identical bytes | `ACC::reordered_acknowledgements_give_identical_receipt_bytes`; `LEC::every_crash_window_resumes_to_identical_bytes` | both; `SQLite` | The ACC test reorders through the Local executor, signer and authority. The crash-window test covers the duplicate. |
| A `partial-failure` receipt issues exactly at the deadline | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure` | `SQLite` | |
| ERRA1 fields equal §5 for attempt 0 and the retries | `LEC::a_transient_negative_is_retried_until_it_succeeds`; `ACC::the_retry_cap_ends_a_transient_failure_in_partial_failure`; `LEC::an_attempt_must_be_the_one_its_request_derives` | `SQLite` | Checked through `assert_attempt` for ordinals 0 to 3. |

## Test 5: rejections

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| An authorization failure commits `Rejected` with `CA(ELREJ1)` | `LEC::the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one` | `SQLite` | Runs on `SQLite` because it recomposes under another grant. **Note:** the ERS1 provenance is `CA` of core `ErasureAuthorizationRejectionV1`, whose `authorization_provenance` is `CA(ELREJ1)`. It is not `CA(ELREJ1)` itself. |
| Freeze-time bound failures commit `Rejected` through `persist_freeze_rejection` | `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | both | |
| Freeze-time topology failures (not the bound) | none | | **Open.** The only freeze refusals other than the bound are an unclassified ARD1 cell and the 65,536-entry ERSC1 cap. C6a has no fixture for either yet. |
| An exact retry reproduces each rejection | `LEC::the_driver_rejects_an_unverifiable_authorization_and_defers_an_expired_one`; `ACC::a_closure_that_outgrows_its_bound_commits_scope_invalid_at_freeze` | `SQLite`; both | |

## Test 6: trust and evidence

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| A forged ELS1, the wrong signer key, purpose confusion and a stale body, refused at admission | `LEC::a_signed_private_freeze_commits_the_subject_closure`; `LEC::only_a_signed_owner_result_that_binds_it_acknowledges`; `LEC::a_complete_receipt_issues_signed_at_its_reached_position` | `SQLite` | Not yet parameterized. |
| The same evidence, refused at recovery | `LEC::recovery_refuses_owner_evidence_admission_refuses`; `LEC::recovery_refuses_receipt_evidence_admission_refuses`; `LEC::recovery_refuses_an_attempt_its_request_does_not_derive` | `SQLite` | **Open for the freeze ELS1.** The Local authority builds ERFAA1 only from an ELS1 it has verified, and no public seam commits a freeze under a refused ELS1. A recovery leg would need a hand-built forged chain. |
| ERAZ1 reuse for another actor | `LEC::the_authority_recomputes_every_eraz1_rule_of_a_plain_submission` | `SQLite` | Admission. **Open at recovery:** the recovery verifier has no hook that re-verifies authorization provenance. |
| An ELB1 not signed by a TPS1 root, or signed by a root without the `erasure-bundle/` prefix | `LEC::a_bundle_not_signed_by_its_named_tps1_root_is_invalid`; `LEC::malformed_or_unbound_bundle_records_are_invalid`; `LER::bundle_rules_are_enforced` | Memory | Composition seam. |
| A revoked `issued_by` key | `LEC::a_revoked_bundle_root_or_signer_key_is_refused` | Memory | |
| An ELB1 whose registry digest, store identity, policy or execution binding differs | `LEC::a_bundle_for_another_policy_or_executor_is_a_mismatch`; `LEC::a_bundle_for_another_store_is_a_mismatch`; `LEC::the_executor_binding_is_the_pinned_executor_version_digest` | Memory | |
| A key-registry signer key that differs from ELB1 | `LEC::a_signer_key_the_key_registry_does_not_hold_is_a_mismatch`; `LEC::a_destroyed_signer_key_is_a_mismatch` | Memory | |
| An ELTA1 naming an operator key outside the trust-state history | none | | Deviation: deferred to #448 (Q9). |
| After an operator-key rotation, a store holding an ERQ1 stays closed until the previous anchor is restored | `LEC::an_operator_key_rotation_closes_a_store_with_requests_until_restored` | `SQLite` | |
| An expired TPS1 refuses new submissions and freezes, while recovery, `getErasure` and completion of a frozen request still verify | `LEC::an_expired_tps1_closes_new_admissions`; `ACC::an_expired_tps1_refuses_a_freeze_but_a_frozen_request_still_completes`; `LEC::attempt_0_completes_after_the_bundle_expires` | `SQLite` | The ACC test recomposes under a new clock. The projection stands in for `getErasure` at the runtime seam. |
| Recovery after the installed TPS1 is replaced still verifies an old request | `LEC::a_store_with_requests_opens_only_when_every_retained_tps1_verifies`; `LEC::committed_evidence_still_verifies_after_a_bundle_rotation` | `SQLite` | |
| An authorize or authorize-stage reject with a provenance other than `CA(ERAZ1)` or `CA(ELREJ1)` is refused | `LEC::authorization_names_the_requests_own_evidence` | `SQLite` | Admission. **Open at recovery,** for the same reason as ERAZ1 reuse. |
| TPS1 key ids `erasure-bundle/…` and `erasure-signer/<64 hex>` round-trip through the TPS1 codec, and a colon-form id is refused | `ACC::erasure_key_ids_round_trip_through_the_tps1_codec`; `LER::signer_key_ids_are_tps1_key_ids` | none (codec) | The colon form is refused on both encode and decode. |
| The signer refuses a digest it cannot re-derive | `LEC::the_signer_signs_a_freeze_only_of_an_authorized_request_and_its_body`; `LEC::the_signer_signs_an_owner_result_only_over_its_class_committed_effect`; `LEC::the_signer_signs_only_the_committed_receipt_body` | `SQLite` | Not yet parameterized. |
| A routine bundle rotation is refused while a request pins the old bundle | `LEC::a_routine_rotation_waits_for_every_pin_and_a_compromise_does_not`; `LEC::a_new_signer_key_waits_for_every_pin_unless_the_tps1_revokes_it` | `SQLite` | |

## Test 7: crash windows

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| Before and after the ERQ1 CAS | `LEC::a_crash_left_admission_binds_the_resubmission`; `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | Close and reopen exception. |
| Between ELS1 signing and the CAS | `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | |
| Between the pending key-destruction phase and the tombstone plus ELO1 | `LEC::every_crash_window_resumes_to_identical_bytes`; `LEC::key_destruction_completes_a_pending_phase_left_by_a_crash` | `SQLite` | |
| Between the owner effect plus ELO1 and `acknowledge_erasure` | `LEC::every_crash_window_resumes_to_identical_bytes` | `SQLite` | |
| A key destruction during the erasure's own access freeze succeeds | `LEC::a_driven_lifecycle_has_identical_bytes_across_close_and_reopen` | `SQLite` | |

## Tests 8 to 11 (placeholder for C6b and C6c)

<!-- C6b and C6c add rows here for tests 8 (Gateway), 9 (getErasure
and golden checks), 10 (export, erasure, offline evaluator) and 11
(recovery by every consumer, managed Local Fork admission, Air-Gapped). -->

| Bullet | Test | Adapters | Note |
|---|---|---|---|
| *Test 8: to be filled by C6b* | | | |
| *Test 9: to be filled by C6b* | | | |
| *Test 10: to be filled by C6c* | `LEC::an_export_after_the_erasure_reports_its_unavailable_artifact` exists | | |
| *Test 11: to be filled by C6c* | | | |
