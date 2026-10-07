;; Imports host-v1 with a function the world does not declare. The linker
;; provides only the three host-v1 functions, so loading must fail.
(component
  (import "pigloros:plugin/host-v1@0.1.0" (instance
    (export "simulation-time" (func (result u64)))
    (export "wall-clock-now" (func (result u64)))
  ))
)
