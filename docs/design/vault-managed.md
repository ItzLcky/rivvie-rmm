# Vault: the system write path

Design record, 2026-11-24 (parity plan A2). Migration `0037_vault_managed.sql`; code in `crates/rmm-server/src/vault.rs` (shared sealing and `put_managed`), `api/vault.rs` (HTTP); web `ClientVault.svelte`, `CredentialCard.svelte`, `VaultForm.svelte`.

Disk encryption escrow, LAPS and identity resets need to store secrets the server itself produces. They all go through one function:

```rust
vault::put_managed(&st, client_id, Managed { kind, agent_id, reference, name, username, url, notes, state }, &password, Source::system("diskenc")) -> ApiResult<Uuid>
```

## Model

`vault_items` gains `managed_kind` (`disk_recovery`, `local_admin`, `identity`; constraint `vault_items_managed_kind_check`), `agent_id` (`ON DELETE SET NULL`: deleting a device keeps its recovery key; the hostname stays in the name), `managed_ref` (the caller's key, 1-200 characters, set exactly when the kind is) and `managed_state` (caller-defined, 1-40 characters, e.g. LAPS `pending`). A partial unique index covers `(client_id, managed_kind, managed_ref)`.

## `put_managed`

- Upserts on `(client, kind, reference)`; writers of one item are serialized by an advisory lock, so two first writes make one item.
- A changed password moves the old one (still sealed for `<item>:password`) into `vault_item_history`, last 10 kept; the same password again changes nothing and isn't audited.
- `agent_id`, `notes` and `state` as `None` leave the stored value alone on an update. `Some("")` notes clear them.
- Audits `vault.system_write` with client, kind, reference, name, agent, feature, `created` and the names of the changed fields, never a value. `Source::user(feature, id)` records the person who caused it (and `updated_by`/`replaced_by`).
- Without `RMM_DATA_KEY`: `ApiError::Conflict(vault::NEEDS_KEY)`. Callers report "needs RMM_DATA_KEY" and do nothing else: LAPS must not rotate a password it can't store.
- Other errors: unknown client or agent (404), a field out of bounds (400, no value echoed).

Also in `vault.rs`: `client_key`, `seal`, `open` (moved from `api/vault.rs`), `read_password(db, key, client, item)` for features that must hand a stored password to an agent (script parameters use it; the caller audits why), `set_managed_state`, and the field cleaners.

## Rules for people

- Lists (`GET /clients/{id}/vault`) and details carry `managed_kind`, `agent_id`, `agent_hostname`, `managed_state`; `?kind=managed|manual|disk_recovery|local_admin|identity` filters.
- `PUT /vault/{id}` on a managed item answers 409 when it would change the password or username. Name, URL, notes and TOTP stay editable. Delete needs `vault.manage` (as for any item). Reveal is unchanged (2FA, rate limit, `vault.reveal`).
- The UI shows a "Managed" badge and a filter in the Passwords tab; the card names the kind and device; the edit form hides the password and locks the username.

## CLI

`rmm-server vault-put-managed --client <id> --kind <kind> --reference <ref> --name <name> [--username] [--agent] [--state]`, password in `RMM_VAULT_PASSWORD`, prints the item id. Hidden from `--help`: it exists for the e2e suite and break-glass imports.

## Tests

Unit: kinds match the migration's CHECK, sealing is bound to item and column, URL rules. e2e in `docs_and_vault`: two writes make one item with one history row (an unchanged third write adds neither a row nor an audit entry), both keys reveal, a user edit of password or username is 409 while a rename works, the device is deleted and the item remains with `agent_id` NULL, an unknown client fails without echoing the password; `key_rotation` reveals a managed item after `rotate-data-key`.
