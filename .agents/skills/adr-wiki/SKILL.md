---
name: adr-wiki
description: Rules for ADR wiki pages on Redmine — parent hierarchy, Markdown formatting, and Redmine API usage. Use when creating, editing, or reorganising ADR wiki pages.
---

# ADR Wiki

Rules for managing ADR pages on the Redmine wiki at `redmine.piglor.com/projects/pigloros/wiki`.

## Parent hierarchy

1. **Every ADR page MUST have `ADR` set as its parent.** No ADR page should be a root-level wiki page. This ensures `{{child_pages}}` on the ADR index page auto-lists all ADRs.

2. **When creating a new ADR via the Redmine API**, set the parent in the PUT body:
   ```
   wiki_page[parent_title]=ADR
   ```
   The `parent_title` parameter (not `parent` or `parent_id`) is the correct API field. Include the page text to avoid overwriting:
   ```
   wiki_page[text]=...&wiki_page[parent_title]=ADR
   ```

3. **When fixing an orphaned ADR**, fetch the page's current text first (`GET /projects/pigloros/wiki/<title>.json`), then PUT with `parent_title=ADR` and the original text.

## Markdown formatting

4. **ADR wiki pages use Markdown, not Textile.** Formatting rules:
   - Headings: `## Heading` not `h2. Heading`
   - Inline code: `` `code` `` not `@code@`
   - Code blocks: triple backticks, not `<pre>` tags
   - Lists: `- item` not `# item`
   - Bold: `**text**` (same in both)

5. **Header template at the top of every ADR:**
   ```
   **Status:** Accepted | **Wave:** <n> | **Deciders:** core team | **Date:** <YYYY-MM-DD>
   ```

6. **Page skeleton:**
   ```
   **Status:** ... | **Wave:** ... | **Deciders:** ...
   
   Related: [[ADR-NNN_...]] · #ticket
   
   ---
   
   ## Context
   
   ...
   
   ## Decisions
   
   ### 1. ...
   
   ## Consequences
   
   ...
   ```

7. **Approval is revision-specific.** Record the exact revision reviewed and
   distinguish section-level feedback from approval of the complete page. An
   earlier or partial approval does not approve a later amendment.

8. **Pending amendments control page status.** If an accepted ADR gains an
   unapproved amendment, mark the page `Under Review` and identify which base
   decisions remain accepted. Restore `Accepted` only after the amended
   revision is explicitly approved.

9. **Markdown table rows must be contiguous.** Do not place blank lines between
   the header, separator, or data rows. Parser-sensitive layout is part of the
   canonical format, not a cosmetic detail.

## Redmine API reference

10. **Wiki page URLs** use the title with underscores, URL-encoded:
   - `GET /projects/pigloros/wiki/<title>.json` — read
   - `PUT /projects/pigloros/wiki/<title>.json` — update
   - Auth: header `X-Redmine-API-Key`

11. **Auth:** Include API key in all requests:
   ```
   X-Redmine-API-Key: <key>
   ```

12. **Synchronize and verify external writes.** Fetch the current canonical
    page and any source design before editing. After every write, fetch the page
    again and verify its parent, status, revision/version marker, links, table
    structure, and complete text. A successful response alone is not evidence
    that Redmine stored the intended ADR.

## Pre-flight

- [ ] The page is parented under `ADR` and uses Markdown.
- [ ] Status reflects the least-approved active decision on the page.
- [ ] The exact reviewed revision and approval scope are explicit.
- [ ] Tables have contiguous structural rows.
- [ ] The canonical page was read back after the final write.
