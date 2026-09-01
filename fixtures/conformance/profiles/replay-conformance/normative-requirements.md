# Replay profile requirements

The evaluator must replay the public Event sequence under the selected
ExecutionProfile and reproduce the exact ordered output, state transition,
failure coordinate, and deterministic-budget outcome. Replay must not consult
wall-clock time, undeclared network input, hidden state, or implementation-
private helpers.
