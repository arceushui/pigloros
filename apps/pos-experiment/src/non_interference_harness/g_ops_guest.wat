;; The G-OPS non-interference guest (ADR-062 Revision 8 slice N3, #1231; owner
;; note ADR-062_R8_NonInterference_Operations, decision 1).
;;
;; A tiny community Plugin Component of `pigloros:plugin/community-plugin@0.1.0`
;; with the exact contract and host-v1 types of the engine's probe Component.
;; `drive` and `reduce` first record one operational log whose message is the
;; invocation's observation bytes (at most 256), under category Simulation
;; Time + 1. The Simulation Time then selects the behaviour:
;;
;;  0  return the constant output below;
;;  1  return `guest-declared-failure(7)` whose canonical coordinate is the
;;     observation bytes (at most 128);
;;  2  trap with `unreachable`.
;;
;; The constant output echoes the invocation ID, which the host fixes to sixteen
;; 0x47 bytes, and carries one draft (schema 1, entity sixteen 0x4f bytes, type
;; `ni-g-ops.observed`, payload the CBOR `["g-ops", 1]`), the next state schema
;; thirty-two 0x53 bytes, the next state `g-ops-state`, one trace annotation
;; (schema 1, the CBOR text `span`) and no dependency digest. Its output digest
;; is the V1 output digest of exactly those fields; a test of
;; `non_interference_harness::g_ops` recomputes it. `describe` traps: the host
;; never calls it.
(component
  (type $contract-v1
    (instance
      (type (list u8))
      (export "bytes" (type (eq 0)))
      (type (record (field "value" 1)))
      (export "digest32" (type (eq 2)))
      (type (record (field "schema-id" u32) (field "field-ordinal" u16)))
      (export "field-ref" (type (eq 4)))
      (type (record (field "utf8" 1)))
      (export "bounded-text" (type (eq 6)))
      (type (variant (case "invalid-invocation" 5) (case "unsupported-schema" u32) (case "capability-required" 7) (case "dependency-missing" 3) (case "deterministic-budget-exhausted") (case "invalid-state" 5) (case "migration-rejected" 5) (case "guest-declared-failure" u16)))
      (export "plugin-error-code" (type (eq 8)))
      (type (option 1))
      (type (option 3))
      (type (record (field "code" 9) (field "canonical-coordinate" 10) (field "related-digest" 11)))
      (export "plugin-error" (type (eq 12)))
      (type (list 3))
      (type (record (field "migration-id" 7) (field "to-state-schema" 3) (field "migrated-state-bytes" 1) (field "consumed-dependencies" 14) (field "output-digest" 3)))
      (export "migration-output" (type (eq 15)))
      (type (record (field "migration-id" 7) (field "from-state-schema" 3) (field "to-state-schema" 3) (field "prior-state-bytes" 1) (field "deterministic-budget-id" 7) (field "provenance-root" 3)))
      (export "migration-request" (type (eq 17)))
      (type (record (field "capability-id" 7) (field "operation" 7) (field "resource-pattern" 7) (field "purpose" 7) (field "audience" 7) (field "required" bool) (field "max-calls" u32) (field "max-request-bytes" u32) (field "max-response-bytes" u32)))
      (export "capability-declaration" (type (eq 19)))
      (type (record (field "schema-id" u32) (field "byte-length" u64) (field "digest" 3)))
      (export "artifact-ref" (type (eq 21)))
      (type (option 7))
      (type (record (field "from-state-schema" 3) (field "to-state-schema" 3) (field "migration-id" 7) (field "migration-component" 22) (field "deterministic-budget-id" 7) (field "reverse-migration-id" 23)))
      (export "migration-descriptor" (type (eq 24)))
      (type (enum "exogenous-frozen" "intervention-assigned" "endogenous-recomputed" "fixed-policy" "presentation-only"))
      (export "dependency-class" (type (eq 26)))
      (type (list 7))
      (type (record (field "dependency-id" 7) (field "release-digest" 3) (field "world" 7) (field "abi-major" u16) (field "min-abi-minor" u16) (field "max-abi-minor" u16) (field "required-features" 28) (field "required-capabilities" 28) (field "dependency-class" 27)))
      (export "dependency-descriptor" (type (eq 29)))
      (type (list 20))
      (type (list 25))
      (type (list 30))
      (type (record (field "plugin-id" 7) (field "release-semver" 7) (field "world" 7) (field "abi-major" u16) (field "min-abi-minor" u16) (field "max-abi-minor" u16) (field "required-features" 28) (field "event-schema-digests" 14) (field "state-schema-digest" 3) (field "capabilities" 31) (field "migrations" 32) (field "dependencies" 33) (field "manifest-digest" 3) (field "release-digest" 3)))
      (export "plugin-descriptor" (type (eq 34)))
      (type (enum "reduce" "drive"))
      (export "invocation-kind" (type (eq 36)))
      (type (record (field "timeline-id" 1) (field "seq" u64) (field "tick" u64) (field "scheduler-position" u32)))
      (export "timeline-position" (type (eq 38)))
      (type (record (field "invocation-id" 1) (field "kind" 37) (field "timeline-position" 39) (field "output-base-ordinal" u32) (field "principal-ref" 22) (field "authorization-decision" 22) (field "observation-snapshot" 22) (field "observation-bytes" 1) (field "prior-state-schema" 3) (field "prior-state-bytes" 1) (field "execution-profile-digest" 3) (field "trust-policy-snapshot-digest" 3) (field "deterministic-budget-id" 7) (field "deterministic-random-domain" 3) (field "provenance-root" 3)))
      (export "plugin-invocation" (type (eq 40)))
      (type (record (field "event-schema-id" u32) (field "entity-id" 1) (field "event-type" 7) (field "canonical-payload" 1) (field "dependency-digests" 14)))
      (export "event-draft" (type (eq 42)))
      (type (record (field "annotation-schema-id" u32) (field "canonical-bytes" 1) (field "dependency-digests" 14)))
      (export "trace-annotation" (type (eq 44)))
      (type (list 43))
      (type (list 45))
      (type (record (field "invocation-id" 1) (field "event-drafts" 46) (field "next-state-schema" 3) (field "next-state-bytes" 1) (field "trace-annotations" 47) (field "consumed-dependencies" 14) (field "output-digest" 3)))
      (export "plugin-output" (type (eq 48)))
    )
  )
  (import "pigloros:plugin/contract-v1@0.1.0" (instance $contract (type $contract-v1)))
  (alias export $contract "digest32" (type $digest32))
  (alias export $contract "bytes" (type $bytes))
  (alias export $contract "plugin-error" (type $plugin-error))
  (alias export $contract "bounded-text" (type $bounded-text))
  (alias export $contract "plugin-descriptor" (type $plugin-descriptor))
  (alias export $contract "plugin-invocation" (type $plugin-invocation))
  (alias export $contract "plugin-output" (type $plugin-output))
  (type $host-v1
    (instance
      (alias outer 1 $digest32 (type))
      (export "digest32" (type (eq 0)))
      (alias outer 1 $bytes (type))
      (export "bytes" (type (eq 2)))
      (alias outer 1 $plugin-error (type))
      (export "plugin-error" (type (eq 4)))
      (alias outer 1 $bounded-text (type))
      (export "bounded-text" (type (eq 6)))
      (type (func (result u64)))
      (export "simulation-time" (func (type 8)))
      (type (result 3 (error 5)))
      (type (func (param "domain" 1) (param "offset" u64) (param "length" u32) (result 9)))
      (export "deterministic-random" (func (type 10)))
      (type (result (error 5)))
      (type (func (param "category" u16) (param "message" 7) (result 11)))
      (export "record-operational-log" (func (type 12)))
    )
  )
  (import "pigloros:plugin/host-v1@0.1.0" (instance $host (type $host-v1)))


;; Linear memory and a bump allocator for the lowered invocation.
  (core module $libc
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 8192))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $at i32)
      (local.set $at
        (i32.and
          (i32.add (global.get $next) (i32.sub (local.get 2) (i32.const 1)))
          (i32.sub (i32.const 0) (local.get 2))))
      (global.set $next (i32.add (local.get $at) (local.get 3)))
      (local.get $at)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $memory))
  (alias core export $libc "realloc" (core func $realloc))

  (core func $time (canon lower (func $host "simulation-time")))
  (core func $log
    (canon lower (func $host "record-operational-log") (memory $memory) (realloc $realloc)))

  (core module $main
    (import "host" "time" (func $time (result i64)))
    (import "host" "log" (func $log (param i32 i32 i32 i32)))
    (import "libc" "memory" (memory 1))
    (func (export "describe") (result i32) unreachable)
    ;; The lowered `plugin-invocation` record: `invocation-id` at 0 and
    ;; `observation-bytes` at 128 (pointer, then length).
    (func (export "invoke") (param $input i32) (result i32)
      (local $selector i64)
      (local $observation i32)
      (local $length i32)
      (local.set $selector (call $time))
      (local.set $observation (i32.load offset=128 (local.get $input)))
      (local.set $length (i32.load offset=132 (local.get $input)))
      (call $log
        (i32.add (i32.wrap_i64 (local.get $selector)) (i32.const 1))
        (local.get $observation)
        (select (local.get $length) (i32.const 256)
          (i32.le_u (local.get $length) (i32.const 256)))
        (i32.const 2048))
      (if (i64.eq (local.get $selector) (i64.const 2)) (then unreachable))
      (if (i64.eq (local.get $selector) (i64.const 1))
        (then
          (i32.store (i32.const 3120) (local.get $observation))
          (i32.store (i32.const 3124)
            (select (local.get $length) (i32.const 128)
              (i32.le_u (local.get $length) (i32.const 128))))
          (return (i32.const 3100))))
      (i32.store (i32.const 3004) (i32.load (local.get $input)))
      (i32.store (i32.const 3008) (i32.load offset=4 (local.get $input)))
      (i32.const 3000))
    ;; The constant output's members.
    (data (i32.const 1024) "\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f\4f")
    (data (i32.const 1040) "ni-g-ops.observed")
    (data (i32.const 1064) "\82\65g-ops\01")
    (data (i32.const 1072) "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")
    (data (i32.const 1104) "g-ops-state")
    (data (i32.const 1120) "\64span")
    (data (i32.const 1128) "\4a\d4\14\72\c3\a9\4f\a2\bc\9f\df\f2\d2\1e\27\6b\6a\d4\86\94\7b\a1\37\28\06\11\08\3a\24\b7\57\03")
    ;; The one `event-draft` and the one `trace-annotation`.
    (data (i32.const 1200) "\01\00\00\00\00\04\00\00\10\00\00\00\10\04\00\00\11\00\00\00\28\04\00\00\08\00\00\00\00\00\00\00\00\00\00\00")
    (data (i32.const 1240) "\01\00\00\00\60\04\00\00\05\00\00\00\00\00\00\00\00\00\00\00")
    ;; At 3000 the `ok` return area (its invocation ID is written per call); at
    ;; 3100 the `guest-declared-failure(7)` return area (its coordinate is
    ;; written per call).
    (data (i32.const 3000) "\00\00\00\00\00\00\00\00\00\00\00\00\b0\04\00\00\01\00\00\00\30\04\00\00\20\00\00\00\50\04\00\00\0b\00\00\00\d8\04\00\00\01\00\00\00\00\00\00\00\00\00\00\00\68\04\00\00\20\00\00\00")
    (data (i32.const 3100) "\01\00\00\00\07\00\00\00\07\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))
  (core instance $main (instantiate $main
    (with "host" (instance
      (export "time" (func $time))
      (export "log" (func $log))))
    (with "libc" (instance (export "memory" (memory $memory))))))

  (func $describe (result (result $plugin-descriptor (error $plugin-error)))
    (canon lift (core func $main "describe") (memory $memory)))
  (func $invoke (param "input" $plugin-invocation)
    (result (result $plugin-output (error $plugin-error)))
    (canon lift (core func $main "invoke") (memory $memory) (realloc $realloc)))
  (instance $guest
    (export "describe" (func $describe))
    (export "reduce" (func $invoke))
    (export "drive" (func $invoke)))
  (export "pigloros:plugin/guest-v1@0.1.0" (instance $guest))
)
