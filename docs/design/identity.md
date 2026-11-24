# Identity management

A client's directories (on-premises Active Directory, Entra ID) in the console: their users and groups as last synced, the everyday actions on an account (unlock, reset the password, disable and enable, remove from groups, revoke sessions), and onboarding and offboarding as ticket templates whose checklist items run those actions. Parity plan section F1. Intune devices read through the same Entra connection are [mdm.md](mdm.md).

## Sources

A client has any number of directories (`identity_sources`, migration `0049`), each `ad` or `entra`. Admins add, change, test and remove them (Users tab → Directories); technicians with `identity.manage` can sync one now. Each syncs on its own schedule (`sync_minutes`, 5-1440, default 60) from a server loop (`identity::run`, every 30 s it picks the due ones); `last_sync_at` is set on failure too, so a broken source is retried at its interval, with the reason in `last_error`.

### Active Directory: through the agent on a domain controller

The agent advertises the capability `identity_ad` only where Windows says it is a domain controller (`ProductType` is `LanmanNT`). The source names that agent; it must be one of the client's.

Directory operations are **dedicated messages, not script jobs**: a job's body and output are stored, and a password must not be. `ServerMsg::Identity { request_id, op }` → `AgentMsg::IdentityReply { request_id, reply }` (agent message kind 42), awaited with the `hub.tool` pattern (a oneshot with a timeout: 90 s for an action, 5 minutes per sync page). Ops (`rmm-proto/src/identity.rs`): `Sync { since_usn, page }`, `Unlock`, `ResetPassword { password, must_change }`, `SetEnabled`, `RemoveFromGroups`.

On the agent (`src/identity/`), each op is **one fixed PowerShell script** using the ActiveDirectory module, passed with `-EncodedCommand`. The arguments go to it as JSON on stdin (`[Console]::In.ReadToEnd() | ConvertFrom-Json`), never into the script or a command line; the password goes from that JSON straight into a `SecureString`. SIDs are checked against `S-1-5-21-a-b-c-rid` (each part a 32-bit number) before anything runs, on the agent and on the server, and **RID 500 (Administrator) and 502 (krbtgt) are always refused**, whatever the server asks.

Sync: users with `uSNChanged` above the last high-water mark, in USN order, 500 a page (`Get-ADUser -LDAPFilter`), with `SamAccountName`, UPN, display name, mail, enabled, `LockedOut`, `adminCount`, `lastLogonTimestamp`, `pwdLastSet`, `msDS-UserPasswordExpiryTimeComputed`, department, title and `MemberOf` (mapped to group SIDs); every group on the first page; and on the last page of a full sync every user SID, so users gone from the directory are marked deleted (kept, so tickets and the audit log still name them). The domain's `highestCommittedUSN` at the start is the next delta's mark. Group membership lives on the group object, so a delta only refreshes it for the users it lists; **a full sync runs at least once a day** (`last_full_sync_at`) and whenever the source's agent changes. FILETIMEs of 0 and `0x7FFFFFFFFFFFFFFF` ("never") are none. PowerShell 5.1's one-element arrays (a bare value) and empty ones (null) are both read.

Debug builds: `RMM_IDENTITY_FAKE=<file>` answers from a directory kept in that JSON file (and advertises the capability on any OS when the file exists at start); every action is appended to `<file>.ops.jsonl`, the password included, which is how the e2e checks what the "directory" was given.

### Entra ID: through Graph

An app registration **in the customer's tenant** (tenant id or `.onmicrosoft.com` domain, application id, client secret), signed in with the client-credentials flow; `graph::app_token` is the token call extracted from the mailbox code and shared by both. The secret is sealed with `RMM_DATA_KEY` (`identity_sources.secret`, `secret_sealed`, in `rotate::TABLES`) and never returned (`has_secret`).

Permissions (application):

| For | Needs |
|---|---|
| Reading users and groups | `User.Read.All`, `Group.Read.All` |
| Privileged accounts (directory role members) | `RoleManagement.Read.Directory` (optional: without it nobody is marked, and the sync says why) |
| MFA registration | `AuditLog.Read.All` and Entra ID P1/P2 (optional: without it the column is empty) |
| Disable, enable, revoke sessions, reset | `User.ReadWrite.All`, plus the **User Administrator** directory role on the app's service principal: Graph doesn't reset passwords on application permissions alone |
| Remove from groups | `GroupMember.ReadWrite.All` |
| Intune devices | `DeviceManagementManagedDevices.Read.All` ([mdm.md](mdm.md)) |

A sync reads every user (`$select`ed, 999 a page, following `@odata.nextLink`, but only to the Graph host the first request went to, so the token never goes elsewhere), every group and its members, the activated directory roles with their members, and MFA registration when it can. Entra has no `uSNChanged`: it's a full list every time. `lastSignInDateTime` needs `AuditLog.Read.All` too and a premium licence, and asking for it fails the whole list without them, so the last sign-in isn't read for Entra users (the UI says so).

**A user synced from on-premises AD** (`onPremisesSyncEnabled`) is changed in AD: the Entra actions are refused with that explanation (409), as Graph would refuse most of them anyway.

## Users

`identity_users`: the external id (SID or object id), user name, UPN, display name, email, enabled, locked (AD), privileged, synced from AD, last logon (AD), password set and expiry, MFA registered (Entra), department, title, the matched contact, deleted, synced. Users are **matched to the client's contacts by email** (or UPN), ignoring case, after every sync. `identity_groups` (with a `privileged` flag: AD `adminCount`) and `identity_group_members`.

**Privileged**: AD `adminCount = 1` or membership of a group with it (Domain Admins and the other protected groups); Entra membership of any activated directory role.

## Actions

`POST /identity/users/{id}/{unlock|reset-password|disable|enable|revoke-sessions|remove-groups}`. The same rules wherever an action starts (the Users tab, a ticket's checklist), in `identity::check` and `identity::act`:

1. The client is one the user sees (else 404), `identity.manage`, a second factor (else 403), and a token from the `identity_action` limiter (30, then one per 10 s, per user).
2. Not deleted from the directory; **privileged accounts need an admin**; AD: a valid SID, never RID 500/502, no "revoke sessions"; Entra: not synced from AD, no "unlock" (Entra's smart lockout clears itself and has no API to clear it).
3. The directory changes first; the stored user is updated at once (locked, enabled, password set, memberships) rather than at the next sync.
4. Audited as `identity.unlock`, `identity.reset_password`, `identity.disable`, `identity.enable`, `identity.revoke_sessions`, `identity.remove_groups`, with the client, directory, account and where it was started (`via`); never a password.

`remove-groups` takes `group_ids`, or removes the account from every group it's in (AD: the primary group isn't in `memberOf` and stays).

### Password resets: exactly one delivery

The server generates the password (16 characters from an alphabet without `0O1lI`, with upper and lower case, a digit and a symbol, uniform by rejection sampling) or takes the technician's (8-256 characters; the directory's own rules apply on top). `must_change` defaults to true. `delivery` is required and is **exactly one** of:

- `show`: the password is in the response (`Cache-Control: no-store`) and **stored nowhere**: not in a table, not in the audit log (the e2e searches every table for it). The dialog shows it once with a copy button.
- `vault`: saved with `vault::put_managed` as a managed item of kind `identity`, reference `<source id>:<external id>`, named after the account and its directory, username the UPN (or user name), state `ok`, written as the user who asked (`Source::user("identity", ...)`). A second reset of the same account replaces the password and moves the old one to the item's history. Without `RMM_DATA_KEY` the reset is refused **before** the directory is touched. If the vault write fails after the reset (a database error), the answer says the password was reset but not stored and to reset again.

The type (`Delivered::Shown { password } | Delivered::Vault { item_id }`) makes "both" and "neither" unrepresentable; the audit entry records which (`shown`, `vault`).

## Ticket templates and checklists

There were no ticket templates (canned responses, macros and ticket types only). Migration `0050`:

- `ticket_templates (id, name, client_id, board_id, type_id, priority, subject, body, checklist jsonb)`; `client_id` set means "only for this client". Two seeded: **New starter** and **Leaver**. Admins manage them under Settings → Service desk → Ticket templates; `{name}` in the subject and body becomes the directory user's (or the contact's) name.
- `ticket_checklist_items (id, ticket_id, position, text, action, action_state, done_by, done_at)`, `action` one of `identity.disable`, `identity.reset_password`, `identity.remove_groups`, `identity.revoke_sessions`.
- `tickets.identity_user_id`: the directory user the ticket is about.

`POST /tickets/from-template {template_id, client_id, contact_id?, identity_user_id?, subject?}` opens the ticket (source `dashboard`; the template's body as an internal first entry) with the template's checklist. In the console it's started from a directory account's drawer ("Open a ticket about …").

`GET|PUT /tickets/{id}/checklist` reads it (with the directory user) and replaces the items (keeping the state of those that stay, by id) and, when given, the directory user. Two routes beyond the plan: `POST /tickets/{id}/checklist/{item}` ticks an item off by hand (`{done}`), and `POST /tickets/{id}/checklist/{item}/run` runs its action on the ticket's directory user through `identity::act` (so the same permission, 2FA, privileged and rate-limit rules); a reset from a checklist goes to the vault unless `{delivery: "show"}`. Success marks the item done (`action_state` `done`); a refusal or failure records `failed: <why>` and leaves it open. **Every tick and every run writes an internal note** to the timeline (`tickets::add_event`, kind `note`, not public), naming the action and the account, never a password.

The automations module was the wrong shape for this (a device event triggering a script).

## UI

- Client page → **Users** (`identity.read`): the directories (sync now, test, edit, remove), and the accounts with filters (locked, disabled, not used in 90 days, no MFA, privileged), search and paging. An account opens a drawer (`components/identity/UserDrawer.svelte`) with its state, groups and the actions; disabled buttons say why. **Reset** is a dialog (`ResetDialog.svelte`): generate or type, "ask for a new password", then "save it in the vault" or "show it to me once".
- A ticket's **Checklist** panel (`components/ticket/TicketChecklist.svelte`): the directory user, items with tick boxes and Run buttons, editing; and the ticket contact's directory accounts, which open the same drawer, so the actions are there too.
- Settings → Service desk → **Ticket templates**.

## Permissions

`identity.read` (see users, groups and Intune devices) and `identity.manage` (the actions), both technicians and up by default. Directories are admin-only to add and change. **Not in the public API**, like the vault (only `listMdmDevices` is, see [mdm.md](mdm.md)). Other audit actions: `identity.source.create`, `.update`, `.delete`, `.test`, `.sync`; `ticket_template.create`, `.update`, `.delete`.

## Tests

- Unit: the recorded `Get-ADUser`/`Get-ADGroup` sync JSON (fixture `crates/rmm-agent/src/identity/fixtures/ad-sync.json`, FILETIMEs, single-element arrays), Graph pages of users, directory roles and managed devices (`crates/rmm-server/tests/fixtures/graph-*.json`), SID validation and RID 500/502, the agent's refusals, `-EncodedCommand`, the fake's deltas, the action rules (privileged, synced, per-kind), generated passwords, exactly one delivery, checklist validation and that the seeded templates use known actions.
- e2e `identity` (`RMM_E2E_ONLY=identity`, `tests/e2e_parts/identity.rs`): a second agent with the fake directory; source admin-only and the agent must be the client's; test and sync; contact matching; unlock; reset to the vault (the revealed password equals what the directory got; audit says `vault`, no password); reset shown once (`no-store`, and in no table, the audit log included); disable; RID 500 refused, a privileged account needs an admin, nothing reached the directory; another client's technician gets 404 everywhere; no second factor, no actions; a delta sync. Entra through the extended `graph_mock()` (two pages, roles, MFA): list, disable, reset shown, revoke, remove from groups (what the mock received), synced-from-AD refused, a role member needs an admin; the secret is sealed at rest. The Leaver template: a ticket whose `identity.disable` item disables the user and notes it on the timeline, remove from groups, an AD revoke recorded as failed, a manual tick, editing that keeps state; template admin rules.
- Visual: Users tab, account drawer, reset dialog (and the shown-once state), the checklist on a ticket, Settings → Service desk.

## Unproven here

Nothing here ran against a real domain controller or tenant. Before release ([roadmap](../ROADMAP.md) blocks 1 and 2, [windows-testing.md](windows-testing.md) section 7c): the PowerShell scripts on a real DC (Server 2016-2025, Windows PowerShell 5.1), the `LanmanNT` detection, `LockedOut` and `uSNChanged` behaviour across replication (an unlock on one DC reaches the others at the customer's replication interval), fine-grained password policies refusing a reset, and on a real tenant the permission and User Administrator role requirements for resets, `revokeSignInSessions`, group removal for mail-enabled and dynamic groups (Graph refuses both), and throttling on large tenants.
