;; Asks for the filesystem through WASI. The host-v1-only linker defines no
;; WASI instance, so loading must fail before any guest code runs. Only the import name
;; matters; the exported function is a placeholder.
(component
  (import "wasi:filesystem/types@0.2.0" (instance
    (export "get-directories" (func (result u64)))
  ))
)
