;; Probe Component for the engine tests (#541).
;;
;; It imports every host-v1 function with its exact type and exports guest-v1
;; with simplified signatures: `describe` returns `list<u8>`, never a
;; `result`, and `reduce` and `drive` take nothing. The engine loads it,
;; because only imports are checked exactly, and `describe` then selects one
;; behaviour by the Simulation Time the test passes in:
;;
;;  1 `unreachable`                  9 call `simulation-time` forever
;;  2 integer division by zero      10 log "ok" forever
;;  3 out-of-bounds memory load     11 log a 257-byte message
;;  4 indirect call to null         12 log invalid UTF-8
;;  5 unbounded recursion           13 request 4,097 random bytes
;;  6 out-of-bounds `table.get`     14 request random bytes with a 31-byte domain
;;  7 loop forever                  15 return a list pointer past memory
;;  8 grow memory by 2,000 pages    16 log one 256-byte message
;;
;; Every other selector returns the valid list "ok", which is still not a
;; `result<plugin-descriptor, plugin-error>`.
(component
  (type $host-v1 (instance
    (type (;0;) (list u8))
    (export (;1;) "bytes" (type (eq 0)))
    (type (;2;) (record (field "value" 1)))
    (export (;3;) "digest32" (type (eq 2)))
    (type (;4;) (record (field "schema-id" u32) (field "field-ordinal" u16)))
    (export (;5;) "field-ref" (type (eq 4)))
    (type (;6;) (record (field "utf8" 1)))
    (export (;7;) "bounded-text" (type (eq 6)))
    (type (;8;) (variant
      (case "invalid-invocation" 5)
      (case "unsupported-schema" u32)
      (case "capability-required" 7)
      (case "dependency-missing" 3)
      (case "deterministic-budget-exhausted")
      (case "invalid-state" 5)
      (case "migration-rejected" 5)
      (case "guest-declared-failure" u16)))
    (export (;9;) "plugin-error-code" (type (eq 8)))
    (type (;10;) (option 1))
    (type (;11;) (option 3))
    (type (;12;) (record
      (field "code" 9)
      (field "canonical-coordinate" 10)
      (field "related-digest" 11)))
    (export (;13;) "plugin-error" (type (eq 12)))
    (type (;14;) (func (result u64)))
    (export "simulation-time" (func (type 14)))
    (type (;15;) (result 1 (error 13)))
    (type (;16;) (func (param "domain" 3) (param "offset" u64) (param "length" u32) (result 15)))
    (export "deterministic-random" (func (type 16)))
    (type (;17;) (result (error 13)))
    (type (;18;) (func (param "category" u16) (param "message" 7) (result 17)))
    (export "record-operational-log" (func (type 18)))
  ))
  (import "pigloros:plugin/host-v1@0.1.0" (instance $host (type $host-v1)))

  ;; Linear memory and a bump allocator for the lowered host results.
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
  (core func $random
    (canon lower (func $host "deterministic-random") (memory $memory) (realloc $realloc)))
  (core func $log
    (canon lower (func $host "record-operational-log") (memory $memory) (realloc $realloc)))

  (core module $main
    (import "host" "time" (func $time (result i64)))
    (import "host" "random" (func $random (param i32 i32 i64 i32 i32)))
    (import "host" "log" (func $log (param i32 i32 i32 i32)))
    (import "libc" "memory" (memory 1))
    (type $void (func))
    (table $table 1 funcref)
    (func $recurse (call $recurse))
    (func (export "noop"))
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
      (if (i64.eq (local.get $selector) (i64.const 15)) (then (return (i32.const 3008))))
      (if (i64.eq (local.get $selector) (i64.const 16))
        (then (call $log (i32.const 1) (i32.const 16) (i32.const 256) (i32.const 2048))))
      (i32.const 3000))
    (data (i32.const 0) "ok")
    (data (i32.const 16) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    (data (i32.const 400) "\ff")
    ;; (pointer, length) pairs: "ok", and 64 bytes past the end of memory.
    (data (i32.const 3000) "\00\00\00\00\02\00\00\00")
    (data (i32.const 3008) "\00\ff\ff\ff\40\00\00\00"))
  (core instance $main (instantiate $main
    (with "host" (instance
      (export "time" (func $time))
      (export "random" (func $random))
      (export "log" (func $log))))
    (with "libc" (instance (export "memory" (memory $memory))))))

  (func $describe (result (list u8)) (canon lift (core func $main "describe") (memory $memory)))
  (func $noop (canon lift (core func $main "noop")))
  (instance $guest
    (export "describe" (func $describe))
    (export "reduce" (func $noop))
    (export "drive" (func $noop)))
  (export "pigloros:plugin/guest-v1@0.1.0" (instance $guest))
)
