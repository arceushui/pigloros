;; Probe Component for the engine tests (#541).
;;
;; It imports every host-v1 function and exports every guest-v1 function the
;; host invokes with its exact type, so it loads. `describe` then selects one
;; behaviour by the Simulation Time the test passes in:
;;
;;  1 `unreachable`                  9 call `simulation-time` forever
;;  2 integer division by zero      10 log "ok" forever
;;  3 out-of-bounds memory load     11 log a 257-byte message
;;  4 indirect call to null         12 log invalid UTF-8
;;  5 unbounded recursion           13 request 4,097 random bytes
;;  6 out-of-bounds `table.get`     14 request random bytes with a 31-byte domain
;;  7 loop forever                  15 return a `plugin-id` pointer past memory
;;  8 grow memory by 2,000 pages    16 log one 256-byte message
;; 17 grow the table past 65,536     18 request random bytes while `realloc`
;;    elements                          returns a pointer past memory
;; 19 request random bytes while `realloc` executes `unreachable`
;;
;; Every other selector returns an all-zero descriptor, whose empty
;; `plugin-id` is not an ADR-061 ID. `reduce` and `drive` trap if called.
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


  ;; Linear memory and a bump allocator for the lowered host results.
  (core module $libc
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 8192))
    (global $bad (export "bad") (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $at i32)
      (if (i32.eq (global.get $bad) (i32.const 2)) (then unreachable))
      (if (global.get $bad) (then (return (i32.const -16))))
      (local.set $at
        (i32.and
          (i32.add (global.get $next) (i32.sub (local.get 2) (i32.const 1)))
          (i32.sub (i32.const 0) (local.get 2))))
      (global.set $next (i32.add (local.get $at) (local.get 3)))
      (local.get $at)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $memory))
  (alias core export $libc "realloc" (core func $realloc))
  (alias core export $libc "bad" (core global $bad))

  (core func $time (canon lower (func $host "simulation-time")))
  (core func $random
    (canon lower (func $host "deterministic-random") (memory $memory) (realloc $realloc)))
  (core func $log
    (canon lower (func $host "record-operational-log") (memory $memory) (realloc $realloc)))

  (core module $main
    (import "host" "time" (func $time (result i64)))
    (import "host" "random" (func $random (param i32 i32 i64 i32 i32)))
    (import "host" "log" (func $log (param i32 i32 i32 i32)))
    (import "libc" "memory" (memory 1))
    (import "libc" "bad" (global $bad (mut i32)))
    (type $void (func))
    (table $table 1 funcref)
    (func $recurse (call $recurse))
    (func (export "invoke") (param i32) (result i32) unreachable)
    (func (export "describe") (result i32)
      (local $selector i64)
      (local.set $selector (call $time))
      (if (i64.eq (local.get $selector) (i64.const 1)) (then unreachable))
      (if (i64.eq (local.get $selector) (i64.const 2))
        (then (drop (i32.div_u (i32.const 1)
          (i32.wrap_i64 (i64.sub (local.get $selector) (i64.const 2)))))))
      (if (i64.eq (local.get $selector) (i64.const 3))
        (then (drop (i32.load (i32.const 0x7ffffff0)))))
      (if (i64.eq (local.get $selector) (i64.const 4))
        (then (call_indirect $table (type $void) (i32.const 0))))
      (if (i64.eq (local.get $selector) (i64.const 5)) (then (call $recurse)))
      (if (i64.eq (local.get $selector) (i64.const 6))
        (then (drop (table.get $table (i32.const 5)))))
      (if (i64.eq (local.get $selector) (i64.const 7)) (then (loop $spin (br $spin))))
      (if (i64.eq (local.get $selector) (i64.const 8))
        (then (drop (memory.grow (i32.const 2000)))))
      (if (i64.eq (local.get $selector) (i64.const 9))
        (then (loop $calls (drop (call $time)) (br $calls))))
      (if (i64.eq (local.get $selector) (i64.const 10))
        (then (loop $logs
          (call $log (i32.const 1) (i32.const 0) (i32.const 2) (i32.const 2048))
          (br $logs))))
      (if (i64.eq (local.get $selector) (i64.const 11))
        (then (call $log (i32.const 1) (i32.const 16) (i32.const 257) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 12))
        (then (call $log (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 13))
        (then (call $random
          (i32.const 512) (i32.const 32) (i64.const 0) (i32.const 4097) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 14))
        (then (call $random
          (i32.const 512) (i32.const 31) (i64.const 0) (i32.const 16) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 15)) (then (return (i32.const 4000))))
      (if (i64.eq (local.get $selector) (i64.const 17))
        (then (drop (table.grow $table (ref.null func) (i32.const 70000)))))
      (if (i64.eq (local.get $selector) (i64.const 18))
        (then
          (global.set $bad (i32.const 1))
          (call $random
            (i32.const 512) (i32.const 32) (i64.const 0) (i32.const 16) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 19))
        (then
          (global.set $bad (i32.const 2))
          (call $random
            (i32.const 512) (i32.const 32) (i64.const 0) (i32.const 16) (i32.const 2048))))
      (if (i64.eq (local.get $selector) (i64.const 16))
        (then (call $log (i32.const 1) (i32.const 16) (i32.const 256) (i32.const 2048))))
      (i32.const 3000))
    (data (i32.const 0) "ok")
    (data (i32.const 16) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    (data (i32.const 400) "\ff")
    ;; At 3000 an all-zero `ok` descriptor; at 4000 an `ok` descriptor whose
    ;; `plugin-id` points 64 bytes past the end of memory.
    (data (i32.const 4000) "\00\00\00\00\00\ff\ff\ff\40\00\00\00"))
  (core instance $main (instantiate $main
    (with "host" (instance
      (export "time" (func $time))
      (export "random" (func $random))
      (export "log" (func $log))))
    (with "libc" (instance (export "memory" (memory $memory)) (export "bad" (global $bad))))))

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
