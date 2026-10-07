;; Asks for ambient randomness through WASI. The host-v1-only linker must refuse
;; it at load time, before any guest code runs.
(component
  (import "wasi:random/random@0.2.0" (instance
    (export "get-random-u64" (func (result u64)))
  ))
)
