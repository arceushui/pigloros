;; Asks to spawn threads through WASI threads. The host-v1-only linker defines no
;; WASI instance, so loading must fail before any guest code runs. Only the import name
;; matters; the exported function is a placeholder.
(component
  (import "wasi:threads/thread-spawn@0.1.0" (instance
    (export "spawn" (func (result u64)))
  ))
)
