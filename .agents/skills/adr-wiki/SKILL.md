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

## Redmine API reference

7. **Wiki page URLs** use the title with underscores, URL-encoded:
   - `GET /projects/pigloros/wiki/<title>.json` — read
   - `PUT /projects/pigloros/wiki/<title>.json` — update
   - Auth: header `X-Redmine-API-Key`

8. **Auth:** Include API key in all requests:
   ```
   X-Redmine-API-Key: <key>
   ```
