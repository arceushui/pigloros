;; Asks for the process environment through WASI. The host-v1-only linker defines no
;; WASI instance, so loading must fail before any guest code runs. Only the import name
;; matters; the exported function is a placeholder.
(component
  (import "wasi:cli/environment@0.2.0" (instance
    (export "get-arguments" (func (result u64)))
  ))
)
