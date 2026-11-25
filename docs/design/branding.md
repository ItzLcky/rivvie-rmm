# White-labelling

Design record, 2026-11-24. Built from section D1 of the [parity plan](parity-plan.md). Migration `0044_branding.sql`.

## Model

The server is self-hosted per MSP, so "the MSP's branding" is one instance row. A client may have its own row, which overrides what that client's people see: the portal after they sign in, mail to its contacts, invoice and QBR PDFs for it, packages made with its enrollment tokens, and the remote-desktop consent prompt on its devices. Staff always see the instance's branding.

`branding (client_id UNIQUE NULLS NOT DISTINCT)`: `product_name`, `logo_light`, `logo_dark`, `icon` (storage keys), `accent` (`#rrggbb`), `support_email`, `support_phone`, `support_url`, `support_hours`, `email_from_name`, `email_footer`, `updated_by`, `updated_at`. The instance row is seeded. Every value is optional; a client row's NULL falls back to the instance's, then to the built-in look (field by field).

`email_messages.from_name` (also in `0044`) records the sender name chosen when a message is queued, since the client is known then and not at send time. Rows queued before the migration send with the instance's name.

## Server (`src/branding.rs`)

- `Cache`: every row, in `AppState::branding`, reloaded after each write. `resolve(st, client_id) -> Branding` reads only the cache (no query), so other modules call it freely: the PWA manifest, scheduled reports and the tray should use `resolve` and `branding::image(st, client, Variant)` (bytes, content type, ETag) rather than the table.
- `Branding`: `product_name` (configured or none), `name` (product name, else "<company> RMM", else "RMM"), image URLs, `accent` and the derived `theme`, `support`, `source_url`; server-only `email_from_name` (configured, else the company name, else "Support"), `email_footer`, `agent_name()` ("<product> Agent" or "RMM Agent"), `slug()`.
- **Accent.** The accent itself fills buttons (`--cta`) with white or ink text, whichever has more contrast. If that is under 4.5:1 the colour is refused (mid-tones about 0.2 luminance). Links and other accent text use a shade moved toward ink (light theme) or white (dark theme) until it reaches 4.5:1 on that theme's surfaces; the soft tint, its ink, the hover shades and the rail indicator are derived the same way. A unit test sweeps the colour cube and checks every pair in both themes.
- **Images.** PNG or JPEG only (no SVG: sanitising risk), 512 KiB at most, checked by content, not name. Logos 16–2048 px; the icon a square PNG of 64–1024 px. PNGs are decoded with the `png` crate (dimensions, and the PDF form); JPEG dimensions come from the SOF marker. Stored under `branding/<instance|client id>/<variant>-<random>.<ext>`; a replaced image's object is deleted. ETag = a hash of the key.
- **PDF.** `pdf::Image` is an image XObject: JPEG as DCTDecode, PNG as Flate RGB with the alpha channel as an SMask. `pdf::report_with_logo` puts the light logo top right of every page (the QBR); `Invoice.logo` puts it above the company name. `pdf::report` is unchanged.
- **ICO.** `branding::ico` wraps the icon PNG in a one-image `.ico` (Vista+ reads PNG icons) for the MSI's `ARPPRODUCTICON`.

## Surfaces

| Where | What changes |
|---|---|
| Console | `GET /settings/public` has `branding`. Product name in the title, rail and sign-in page; the dark logo in the rail and sign-in panel; the icon as favicon; the accent through `--brand-light-*` / `--brand-dark-*` custom properties that `layout.css` falls back from. `static/theme.js` applies the cached palette (`localStorage['rmm.brand']`) before first paint |
| Portal | `/portal/info` (instance) and `/portal/me` (the contact's client over the instance) have `branding`: logo and name in the header, accent, favicon, the support contact card in the footer |
| Email | Sender name per message (client for mail to its contacts: replies, acknowledgements, portal links, surveys, invoices; instance for staff mail); the footer after `-- ` on every message |
| PDF | QBR and invoice header logo (the client's override applies) |
| MSI | `ProductName`, summary subject and feature title "<product> Agent"; `ARPPRODUCTICON` from the icon; `--product-name` on the enroll custom action |
| deb/rpm | Download file name `<slug>-agent_<ver>_<arch>.deb` / `<slug>-agent-<ver>-1.<arch>.rpm` (`<slug>-agent-<ver>-x64.msi`); deb `Description` and rpm `Summary`; `product_name` in `enroll.toml` |
| Agent | `enroll --product-name` (or `product_name` in `enroll.toml`) is kept in `agent.toml`; `install` names the service "<product> Agent" (systemd `Description`, Windows display name). The consent prompt title is "<product>: remote support request" (`Consent.product`, `serde(default)`, omitted when empty) |

Not renamed, on purpose: the binary, service id (`RmmAgent`, `rmm-agent.service`), install paths, package name and MSI UpgradeCode (self-update, upgrades and scripts depend on them).

## API

Admin only, not in the public API (`/api/v1`). Audit `branding.update` with the scope and changed fields or the image.

- `GET|PUT /api/settings/branding`; `GET|POST|DELETE /api/settings/branding/{logo_light|logo_dark|icon}` (multipart field `file`)
- `GET|PUT|DELETE /api/clients/{id}/branding`; `GET|POST|DELETE /api/clients/{id}/branding/{variant}`
- `GET /api/branding/{variant}`: public, the instance's image, `ETag`, `Cache-Control: public, max-age=300`, `304` on `If-None-Match`
- `GET /api/portal/branding/{variant}`: the signed-in contact's (their client's, else the instance's)

**Deviation from the plan:** the plan had `GET /api/branding/{variant}?client=` "only for a signed-in contact". The portal session cookie is scoped to `Path=/api/portal`, so a browser never sends it to `/api/branding`; the contact's route lives under `/api/portal/branding` instead, and `/api/branding` serves the instance only.

## Licence

AGPL-3.0-or-later §13: users interacting with the server over a network must be offered its source. A "Licence and source" link to `RMM_SOURCE_URL` (default: the upstream repository) is on the console sign-in page, the Account page's About card, the portal sign-in page and the portal footer, and no branding setting removes it. An MSP running modified code must point `RMM_SOURCE_URL` at its own copy. Don't promise "no trace of the product" without the owner's agreement.

## Choices made here

- Client overrides can set every field, images included (the plan's API listed uploads for the instance only).
- A package's branding is that of its enrollment token's client.
- The MSI passes `--product-name` only when a product name is configured, so an unbranded MSI still works with an older agent binary in `RMM_AGENT_DIR`. A branded MSI needs an agent of this version or later (older ones reject the flag and the enrollment action fails).
- The email *body* still signs off with the company name (as before); only the sender name and the footer are branded. Alert notification mail (`notify.rs`) is unchanged.
- The theme derivation is server-side only; the settings preview shows the saved palette and the unsaved text.
- Deleting a client deletes its row (cascade) but not its stored images.

## Tests

- Unit (`branding.rs`, `pdf.rs`, `api/msi.rs`, `api/packages.rs`, agent `config.rs`): hex parsing, contrast, the colour-cube sweep, slugs, image checks (PNG, JPEG, CMYK, SVG, truncated, oversize, square icon), the PDF and ICO forms, the resolution order, the XObject on every page with a valid xref, the branded MSI (ProductName, ARPPRODUCTICON, Icon stream, `--product-name` sanitised), `enroll.toml`, service display names.
- e2e `branding`: validation; uploads; public settings, image ETag and 304; portal info; a client override reaches that client's contact only (mail From and `/portal/me`, the client's own image route); the footer in mail; the MSI's `ProductName`, icon and custom action read back with the `msi` crate; the package file names; the QBR PDF contains `/XObject`; then it puts everything back.
- Visual: Settings → Branding, the client's Settings tab, and branded sign-in, dashboard (rail), portal sign-in and portal, both themes, with axe.

## Unproven here

How real mail clients show the sender name and footer, and how Windows "Apps & features" and `services.msc` show the branded names and icon: listed in [windows-testing.md](windows-testing.md) and roadmap blocks 1 and 2.
