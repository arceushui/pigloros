;; Imports host-v1 `simulation-time` with the wrong result type. The typed
;; linker definition must refuse it at load time.
(component
  (import "pigloros:plugin/host-v1@0.1.0" (instance
    (export "simulation-time" (func (result u32)))
  ))
)
