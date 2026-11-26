# Documentation boundaries

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Keep Git docs contributor-facing and canonical.** Put current usage, contribution, policy, and durable contract guidance in Git; search for an existing source before creating another guide. Put dated execution logs, plans, and decision history in Redmine or Notion; link to the canonical external record rather than copying it into a dated Markdown file.

- **Treat external documentation as structured data.** Mermaid code is literal: do not apply rich-text escaping inside code fences, use `<br>` for label breaks, and quote labels containing special characters. In Notion tables, use native Markdown links or plain text, not raw HTML anchors or block-level markup in cells. Treat diagrams, rich text, table cells, and page tags as separate serialization layers.

- **Verify external writes by reading back canonical content.** A child-page creation can append a structural `<page>` block to its parent; fetch the live parent, place the block at the intended index, and fetch parent and child after the write. Verify schemas, links, hierarchy, authority markers, vocabulary, maturity claims, and migrated record counts rather than trusting a success summary.

- **Make documentation claims reviewable before making them attractive.** Lead product pages with user value and a concrete first action; give architecture pages a current system map and next seam; give validation pages a claim contract before technical detail. Use examples that clarify without narrowing the product, and mark current state, maturity, and source of truth structurally.

- **Keep hierarchy and current truth explicit.** A parent page must explain why its child is the next useful drill-down. Living overviews and technical hubs state the current product or domain contract; dated plans, review transcripts, competitor investigations, and execution logs belong in linked history or dedicated pages.

- **Tie strategy and research to release evidence.** Preserve dated first-party evidence and historical investigation separately from the current landscape, then map each objective, differentiator, and scenario to a named milestone and user-visible acceptance gate. Traceability should clarify the product journey rather than make the reader reconstruct it from tickets.

- **Make external records durable and auditable.** When comments or delegated edits are part of the handoff, consolidate them into ordered page content with session/job ownership, verify the migrated count and canonical text, and state any API limitation that prevents source cleanup. Never trust a mutation success summary without a read-back.
