# Client documentation and the password vault

Design and build plan. Replaces the plain-text pages on a client's **Docs** tab with Markdown
documents built from category templates and custom blocks, and adds the password vault that
[psa.md](psa.md#documentation-and-credentials) deferred, with credentials and TOTP codes that
documents can link to.

## What exists today

- `client_docs` / `client_doc_revisions` (migration 0017), handlers at the end of
  `crates/rmm-server/src/api/pm.rs`, routes in `api/mod.rs`, UI in
  `web/src/lib/components/work/ClientDocs.svelte` (the `docs` tab of `/clients/[id]`).
- A page is a title, a free-text category and a plain-text body shown with `whitespace-pre-wrap`.
  Editing happens in a modal textarea. Every save keeps the previous version.
- Gaps: no formatting, no structure, nothing to start a page from, categories are whatever
  someone typed, no way to hold a secret (people will paste passwords into the text), no deep
  links to a page, no protection against two people saving over each other.

## Decisions

| Question | Decision |
|---|---|
| What is a document? | One Markdown source, stored in `client_docs.body`. It exports as a `.md` file with YAML front matter and a `.md` file can be imported. Nothing about a document lives outside its Markdown except title and category. |
| Custom blocks | Fenced code blocks with a known language (` ```fields `, ` ```credential `, ` ```callout `, ` ```device `). They stay valid Markdown anywhere else (they show as code), and need no parser extension. |
| Categories | First-class and MSP-wide (`doc_categories`), managed by admins. A document has zero or one. |
| Templates | MSP-wide (`doc_templates`), each in a category. A template is a Markdown body with blocks and `{{placeholders}}`. Starting a page copies the body; later template edits don't touch existing pages. |
| Markdown renderer | `markdown-it` with `html: false`, `linkify: true`, `breaks: true`. Raw HTML is never rendered, so the CSP and `{@html}` stay safe; `breaks` keeps today's plain-text pages reading the same. |
| Vault scope | Per client. Items hold a name, username, URL, password, TOTP secret and notes. |
| Vault encryption | Envelope: a random 32-byte key per client, wrapped with `RMM_DATA_KEY`, seals every secret field with ChaCha20-Poly1305 and an AAD that binds the ciphertext to its item and field. No `RMM_DATA_KEY`, no vault: it never falls back to plaintext. |
| Vault access | Two new permissions, `vault.read` and `vault.manage`, both default to technician and above. The user must also have two-factor authentication turned on. |
| Secrets on the wire | Lists and documents never carry secrets. A password or note is fetched one at a time by an audited `reveal` call. TOTP secrets never leave the server: the server computes the code. |
| Document ↔ credential link | A `vault:<uuid>` reference in the Markdown. The server derives a link table from the body on every save. |

## Documents

### Markdown and blocks

Standard Markdown (CommonMark plus tables, strikethrough, autolinks and read-only task lists).
A fenced block whose language is in the block registry renders as a component instead of code.
Block bodies are `key: value` lines unless stated.

````markdown
```fields
Gateway: 10.0.0.1
DNS: 10.0.0.2, 1.1.1.1
DHCP range: 10.0.0.100 - 10.0.0.200
```

```credential
item: vault:6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111
```

```credential
label: Firewall admin
```

```callout warning
Never reboot this host during business hours. **Call Dana first.**
```

```device
agent: 0b7e6d58-3c53-4b56-9d0b-2f2f7d1c9e10
```
````

| Block | Renders as | Notes |
|---|---|---|
| `fields` | A two-column definition grid, each value with a copy button. | Lines without `: ` are shown as a full-width row. |
| `credential` | A card: name, username (copy), password (masked; reveal and copy), TOTP (show code with a countdown), URL (open). | With `item:` it shows that vault item. With only `label:` it is an **empty slot**: this is how a template says "a credential goes here". Slots show "No credential linked" when reading and a *Choose credential* button in the editor preview, which picks or creates an item and rewrites the block to `item: vault:<id>`. |
| `callout` | A tinted box. The word after `callout` is `info` (default), `warning` or `danger`. | The body is rendered as Markdown. |
| `device` | A card with the agent's name, online state, OS and a link to its page. | Agents of another client, or deleted ones, show "Device not found". |

Inline references work anywhere in the text:

- `[Firewall admin](vault:<uuid>)` renders as a credential chip; clicking it opens the same card in a popover.
- `[Network overview](doc:<uuid>)` links to another page of the same client.

Unknown languages are ordinary code blocks. A block that can't be parsed shows its source with a
one-line error rather than failing the page.

**Rendering.** `web/src/lib/docs/markdown.ts` parses with `md.parse()`, splits the source at
top-level `fence` tokens whose language is registered (using `token.map` line ranges), and
returns segments: `{ kind: 'md', html }` or `{ kind: 'block', name, arg, body, from, to }`.
`DocView.svelte` renders `md` segments with `{@html}` and block segments with the component from
`web/src/lib/docs/blocks.ts` (the registry: name, label, icon, component, `insert()` snippet,
optional insert form). Adding a block type is one component and one registry entry. `validateLink`
is extended to allow the `vault:` and `doc:` schemes and nothing else new.

### Categories and templates

- `doc_categories`: name (unique, case-insensitive), position. Seeded: Network, Infrastructure,
  Accounts & access, Applications, Backup & recovery, Vendors, Procedures, Onboarding. The
  migration also turns every distinct existing free-text category into a row and points the
  documents at it.
- `doc_templates`: name (unique), category, description, body. Seeded with a starter set, all
  editable and deletable: *Network overview*, *Wi-Fi*, *Server*, *Microsoft 365 tenant*,
  *Line-of-business application*, *Backup and recovery*, *Vendor*, *New user procedure*,
  *Client onboarding checklist*. Each uses the blocks that suit it (the network one has `fields`
  and credential slots for firewall and switch; the onboarding one is task lists).
- Placeholders, filled once when a page is started: `{{client.name}}`, `{{date}}` (ISO date),
  `{{user.name}}`. Unknown placeholders are left as written.
- Managed by admins under **Company settings → Documentation** (categories: add, rename,
  reorder, delete; templates: list by category, create, edit with the same editor as documents,
  duplicate, delete). On a document, technicians get **Save as template** only if they're admin.
- Deleting a category leaves its documents and templates uncategorised (`ON DELETE SET NULL`).

### The Docs tab

- **Left:** a filter box, then pages grouped by category in category order, uncategorised last.
- **New page:** a dialog with title, category, and the templates of that category as cards
  (*Blank* first; choosing a template first sets the category). *Import .md* reads a file in the
  browser, takes `title` and `category` from front matter when present, and opens the editor.
  Nothing is saved until the user presses Save.
- **Reading:** the rendered document; header with category, who saved it and when; History,
  Export (.md), Edit, Delete. A **Linked credentials** list sits under the header when the page
  references any.
- **Editing** happens in the page, not a modal: title and category fields, a toolbar (bold,
  italic, heading, list, link, table, **Insert block ▾**), CodeMirror with Markdown highlighting
  (`@codemirror/lang-markdown`, loaded lazily like `CodeEditor.svelte`) beside a live preview.
  Under `lg` the two become a Write / Preview switch. Leaving with unsaved changes asks first.
- **Insert block** opens the block's form where it has one (credential: pick an item or create
  one; device: pick one of the client's agents; callout: pick a type) and inserts the fence at
  the cursor.
- The selected page is in the URL (`?tab=docs&doc=<id>`), so pages can be linked and `doc:` links work.
- History and restore stay as they are; a version renders as Markdown too.

### API changes (documents)

Existing routes stay. Changes:

- `GET /clients/{id}/docs`, `GET /docs/{id}`: rows gain `category_id`; `category` is now the
  category's name (empty when none). `GET /docs/{id}` gains `credentials`: the linked vault
  items' metadata (see below), an empty list when the caller lacks `vault.read`, plus
  `credentials_hidden: true` in that case if the page has links.
- `POST /clients/{id}/docs`, `PUT /docs/{id}`: take `category_id` (nullable) instead of
  `category`. `PUT` takes an optional `expected_updated_at`; if the page changed since, 409
  "someone else saved this page since you opened it".
- `GET /docs/{id}/export`: `text/markdown` attachment, `<title>.md`, front matter
  `title`, `category`, `client`, `updated`.
- `GET /doc-categories`; admin: `POST /doc-categories`, `PUT /doc-categories/{id}`,
  `DELETE /doc-categories/{id}`, `PUT /doc-categories/order` (`{ ids: [...] }`).
- `GET /doc-templates` (no bodies), `GET /doc-templates/{id}`; admin: `POST`, `PUT`, `DELETE`.
- Audit: `doc_category.*`, `doc_template.*` alongside the existing `client_doc.*`.

Move the documentation handlers out of `pm.rs` into `api/docs.rs`.

## Password vault

### Model

```sql
vault_keys      (client_id PK → clients ON DELETE CASCADE, wrapped_key bytea, created_at)
vault_items     (id, client_id → clients CASCADE, name, username, url,
                 password bytea, notes bytea, totp_secret bytea,
                 totp_algorithm text DEFAULT 'SHA1', totp_digits smallint DEFAULT 6, totp_period smallint DEFAULT 30,
                 password_changed_at, created_by, updated_by, created_at, updated_at)
vault_item_history (id bigserial, item_id → vault_items CASCADE, password bytea, replaced_by, replaced_at)
client_doc_vault_links (doc_id → client_docs CASCADE, item_id → vault_items CASCADE, PRIMARY KEY (doc_id, item_id))
```

Name, username and URL are stored in the clear: lists and search need them and they aren't the
secret. Password, notes and TOTP secret are sealed. Changing a password moves the old one to
`vault_item_history` (the last 10 are kept).

### Encryption

- `crypto.rs` gains `seal_aad` / `open_aad` (ChaCha20-Poly1305 with associated data).
- A client's vault key is 32 random bytes made on first use, stored as
  `DataKey.seal_aad(key, "vault-key:<client_id>")`.
- A field is `client_key.seal_aad(plain, "<item_id>:<field>")`, so a ciphertext copied to another
  row or column won't open.
- Deleting a client deletes its key row, which makes any leftover ciphertext (backups aside) unreadable.
- Without `RMM_DATA_KEY` every vault endpoint answers 409 "the vault needs RMM_DATA_KEY to be set
  on the server" and the UI says so. At startup, wrapped keys with no `RMM_DATA_KEY` log a warning.
- Rotating `RMM_DATA_KEY` only needs the wrapped keys rewrapped. Not built here.

### Access

Every vault endpoint requires all of:

1. the client is one the user can see (`access::client`; otherwise 404);
2. `vault.read` (reading, reveal, codes) or `vault.manage` (create, edit, delete);
3. two-factor authentication turned on for the user, else 403 "turn on two-factor authentication
   to use the vault".

`Perm::VaultRead` and `Perm::VaultManage` default to technician and admin. Read-only users and
portal users have no vault access. Add both to `Permission` in `session.svelte.ts` and the
permission picker under Settings → Users.

Reveal and code requests are rate-limited per user (a new `vault_reveal` limiter: 60 per 5
minutes), and every one writes an audit entry naming the item and field: `vault.reveal`,
`vault.totp`. Also audited: `vault.create`, `vault.update` (which fields changed, never values),
`vault.delete`. Responses carrying a secret set `Cache-Control: no-store`. Secrets are never logged.

### API

| Route | Permission | |
|---|---|---|
| `GET /clients/{id}/vault` | read | Items: `id, name, username, url, has_password, has_totp, has_notes, docs` (count), `password_changed_at, updated_at, updated_by_name`. |
| `POST /clients/{id}/vault` | manage | `name` (required), `username`, `url`, `password`, `notes`, `totp`. |
| `GET /vault/{id}` | read | The same metadata, plus `linked_docs: [{id, title}]` and `history: [{id, replaced_at, replaced_by_name}]`. |
| `PUT /vault/{id}` | manage | For `password`, `notes`, `totp`: absent = unchanged, `null` = cleared, string = set. |
| `DELETE /vault/{id}` | manage | Documents that reference it show "Credential not found". |
| `POST /vault/{id}/reveal` | read | `{ field: "password" \| "notes" }` or `{ history: <id> }` → `{ value }`. |
| `POST /vault/{id}/totp` | read | `{ code, digits, period, remaining }`, computed on the server. |

`totp` accepts a base32 secret or an `otpauth://totp/...` URI (secret, algorithm, digits and
period are read from it). `totp.rs` gains a general `code(secret, algorithm, digits, period, unix)`
covering SHA-1, SHA-256 and SHA-512, tested against the RFC 6238 vectors; sign-in keeps using
`verify`.

### Linking

On every document create and update, the server finds `vault:<uuid>` in the body and replaces
the document's rows in `client_doc_vault_links` with the references that resolve to items of the
same client. Unresolved references are ignored and render as "Credential not found", so imports
and restored versions never fail to save. The link table gives the document its `credentials`
list and the vault item its `linked_docs`.

### UI

A **Passwords** tab on the client page, next to Docs, shown to users with `vault.read`.

- A table: name, username, URL, a TOTP mark, linked pages, last changed. Filter box. *New password*.
- A row opens a drawer with the credential card (the same component the `credential` block
  uses), linked pages, password history (reveal per entry) and Edit / Delete.
- The form has a password generator (`crypto.getRandomValues`; length and character classes) and
  a TOTP field taking a secret or an `otpauth://` URI.
- A revealed password hides itself after 30 seconds. A TOTP code shows a countdown and offers
  *New code* when it runs out; it isn't polled, so every code shown is one audit entry.
- States: no `RMM_DATA_KEY` (explains what to set), no 2FA (links to Account → Two-factor),
  no permission (tab hidden; blocks in documents say "You don't have access to credentials").

## Documents on tickets

A ticket can have documentation pages linked to it, the same way it has agents
(`ticket_agents`, `POST /tickets/{id}/agents`, the Agents card on the ticket page). The rules
mirror that feature one for one.

**Model** (migration `0024_ticket_docs.sql`):

```sql
ticket_docs (ticket_id → tickets CASCADE, doc_id → client_docs CASCADE,
             added_by → users SET NULL, added_at, PRIMARY KEY (ticket_id, doc_id))
-- plus an index on doc_id
```

**API**

- `POST /tickets/{id}/docs` `{ doc_id }` and `DELETE /tickets/{id}/docs/{doc_id}`: technician,
  ticket visible to the user. The page must belong to the ticket's client, else 400 "the page
  must belong to the ticket's client"; a page of a client the user can't see is 404. Linking
  twice is a no-op. Unlinking something not linked is 404 "linked page".
- Each link and unlink adds an internal timeline event of kind `doc` with
  `{ doc_id, title, linked }` (never shown in the portal or sent by email) and announces the ticket.
- `GET /tickets/{id}` gains `docs: [{ id, title, category, updated_at, updated_by_name }]`,
  ordered by title.
- `GET /docs/{id}` gains `tickets: [{ id, number, subject, status, status_category, updated_at }]`:
  the tickets that link the page, newest first, at most 50, limited to tickets the caller may see.
- Changing a ticket's client drops links to the old client's pages. Merging moves the links to
  the surviving ticket. Both exactly as for agents.

**UI**

- Ticket page: a **Documentation** card under Agents. Each row is the page title with its
  category and when it was saved, and an unlink button for technicians. A combobox of the
  client's pages not yet linked adds one. Without a client: "Choose a client first".
- Clicking a title opens the page in a drawer, rendered by `DocView` (blocks, credentials and
  TOTP included, under the usual vault rules), with *Open page* going to
  `/clients/<client>?tab=docs&doc=<id>`. The technician reads the runbook without leaving the ticket.
- The timeline shows "linked Network overview" / "unlinked Network overview" like the agent events.
- Docs tab: a page linked from tickets shows a **Linked tickets** row under its header (number,
  subject, status), each going to the ticket.

**Tests:** e2e (link, duplicate link, wrong client's page, unlink, timeline events, the ticket
and document responses, client change drops links, merge moves them, a read-only user is
refused, the portal's ticket view shows no `doc` events); mocks and visual baselines for the
ticket page and the docs tab.

## Out of scope

- Ticking task-list boxes while reading (they're read-only; edit the page).
- Sharing credentials with portal users, browser extensions, autofill, importing from other vaults.
- An MSP-wide (not per-client) vault.
- A `RMM_DATA_KEY` rotation command.
- Full-text search across documents and adding documents or credentials to the command palette.
- Bulk export of a client's documents.

## Build plan

Each step ends green: `cargo clippy -p rmm-server --all-targets -- -D warnings`,
`cargo test -p rmm-server`, and for the web `npm run check` and `npm run build` in `web/`.

**Server**

1. Migration `0023_docs_vault.sql`: `doc_categories` (seeded, plus existing free-text
   categories), `doc_templates` (seeded starter set), `client_docs.category_id` (backfilled;
   drop `category`), the four vault tables.
2. `crypto.rs`: `seal_aad` / `open_aad` with tests. `totp.rs`: general `code()` and otpauth
   parsing with tests.
3. `auth.rs`: `Perm::VaultRead`, `Perm::VaultManage`. `ratelimit.rs`: `vault_reveal`.
4. `api/docs.rs`: documents moved from `pm.rs`, `category_id`, `expected_updated_at`, export,
   link derivation, `credentials` on the detail; categories and templates.
5. `api/vault.rs`: everything in the vault table above, with the access checks in one helper.
6. `tests/e2e.rs`: extend the documentation section and add a vault section. Cover: a template
   and category round trip; link derivation (resolved, unresolved, other client's item);
   the 409 on a stale save; export front matter; create / reveal / update / history / TOTP
   code; reveal writes an audit row; a user without 2FA, a read-only user and a user scoped to
   another client are each refused; no secret appears in any list or document response.

**Web**

7. Dependencies: `markdown-it`, `@types/markdown-it`, `@codemirror/lang-markdown`.
8. `lib/docs/`: `markdown.ts` (parser config, segmenting, placeholders, front matter),
   `blocks.ts` (registry), `types.ts`; block components under `components/docs/blocks/`.
9. `components/docs/`: `DocView`, `DocEditor`, `NewDocDialog`, and `ClientDocs.svelte`
   rewritten around them (moved from `components/work/`).
10. `components/vault/`: `CredentialCard`, `VaultForm`, `VaultPicker`, `PasswordGenerator`,
    `ClientVault.svelte`; the **Passwords** tab on `/clients/[id]`.
11. `routes/settings/documentation/`: categories and templates; the tab in the settings layout.
12. Visual tests: mock the new endpoints in `tests/visual/mock.ts`, add `client-docs`,
    `client-docs-edit`, `client-passwords` and `settings-documentation` to `pages.spec.ts`, and
    make their baselines in Docker (`npm run test:visual:docker -- --update-snapshots`), leaving
    other baselines untouched.

**Docs**

13. README (a *Documentation and passwords* section, the two permissions, the `RMM_DATA_KEY`
    requirement), `docs/ROADMAP.md` and the vault paragraph in `psa.md`.
