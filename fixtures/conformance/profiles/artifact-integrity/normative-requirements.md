# Artifact integrity profile requirements

The evaluator must verify every declared member path, byte length, media type,
role, and BLAKE3 digest before accepting the archive. It must reject duplicate,
missing, undeclared, non-canonical, or path-unsafe members and must authenticate
the complete signed release identity. Draft evidence may remain unexecuted, but
it may not claim a successful result.
