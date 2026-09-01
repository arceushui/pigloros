# Gateway client seam profile requirements

The evaluator must exercise the public gateway-client seam with declared
capabilities and deterministic inputs. It must verify canonical requests,
responses, denial without state change, bounded resource failure, and explicit
network policy. No fixture may rely on a live service or private gateway
implementation as its oracle.
