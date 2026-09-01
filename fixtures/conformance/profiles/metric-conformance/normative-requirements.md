# Metric computation profile requirements

The evaluator must compute metrics from the public canonical input and compare
the exact metric identity, value, unit, ordering, and failure result. It must
reject undeclared inputs, non-deterministic aggregation, and resource-limit
effects. Operational watchdog expiry is not an executed conformance result.
