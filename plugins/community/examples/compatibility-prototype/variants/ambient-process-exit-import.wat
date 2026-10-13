;; Asks to control the process through WASI exit. The host-v1-only linker defines no
;; WASI instance, so loading must fail before any guest code runs. Only the import name
;; matters; the exported function is a placeholder.
(component
  (import "wasi:cli/exit@0.2.0" (instance
    (export "exit" (func (result u64)))
  ))
)
