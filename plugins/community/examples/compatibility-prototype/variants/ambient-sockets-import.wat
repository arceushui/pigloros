;; Asks for the network through WASI sockets (a TCP socket). The host-v1-only linker defines no
;; WASI instance, so loading must fail before any guest code runs. Only the import name
;; matters; the exported function is a placeholder.
(component
  (import "wasi:sockets/tcp@0.2.0" (instance
    (export "create-tcp-socket" (func (result u64)))
  ))
)
