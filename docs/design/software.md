# Software deployment

Design record, 2026-11-22. Status: built (migration `0032_software.sql`). Roadmap block 4, first
bullet: winget and Chocolatey on Windows, apt and dnf on Linux and uploaded MSI/EXE installers,
as a catalog, ad hoc deploys, desired state in policy sets and a third-party updates view.

## Model

**Catalog** (`software_packages`): MSP-wide (`client_id` NULL) or one client's. A package says how
to handle it on each platform, and any combination may be set:

| Field | Used by |
|---|---|
| `winget_id` | winget (`Mozilla.Firefox`) |
| `choco_id` | Chocolatey (`firefox`) |
| `apt_name`, `dnf_name` | apt-get, dnf/dnf5/yum |
| uploaded installer | an `.msi` or `.exe` in object storage (`attachments/<uuid>`, hashed with SHA-256), `silent_args`, and for removal `product_code` (MSI) or `uninstall_cmd` (EXE); `detect_name` finds it under Uninstall when there is no product code |

`version` pins an exact version; empty means latest. For an uploaded installer it is required: it is
the version the file installs, and the only thing that says what "newer" means. A package without
any source yet stays in the catalog (the installer is uploaded after creating it) but can't be
deployed. MSP-wide packages need an admin; a client's own, a technician with access to the client.

The agent uses the first way that is available on the machine: **winget, Chocolatey, then the
uploaded installer** on Windows; **apt, then dnf/yum** on Linux. A Windows package with only a
Chocolatey id on a machine without Chocolatey fails, unless the run allows installing it (below).

**Runs** (`software_runs`): one install, upgrade or uninstall of one package on one agent, shaped
like `patch_runs` (`queued` until the agent is online, `sent`, then `succeeded`, `failed`, `lost`,
`expired` or `cancelled`), with the agent's log, the provider used, and the versions before and
after. Runs from a technician are `manual`; runs started by enforcement are `policy` and name the
policy item.

**State** (`software_state`): what the last scan found per agent and catalog package: installed
version, a newer version on offer, which provider answered. `provider` NULL means nothing on the
device could look, so "not installed" would be a guess and nothing is enforced. The agent scans
every package of its OS the catalog offers (MSP-wide and its client's) with the same
`RMM_PATCH_SCAN_HOURS` interval as patches, on connect when stale, after every run (for the
package it just touched), when a policy needing a package it hasn't scanned arrives, and on
demand.

## Desired state: the `software` policy module

A multi-instance module like alerts and schedules: define it in any set, with the usual limit
(client, site, excluded agents), and it applies to that set and everything below it.

```
software: {package_id, state: present | latest | absent, bootstrap_choco: false, window: null | {days, start, minutes, tz}}
```

- `present`: installed (at the pinned version, if pinned: an older install is brought up to the pin,
  a newer one is left alone). Upgrades are never done for it.
- `latest`: `present`, and upgraded whenever the provider offers a newer version, inside `window`
  (`null`: the site's maintenance window, like patching; installs and removals don't wait for it).
  A pinned package is not kept current.
- `absent`: uninstalled.
- A version a person chose to ignore in the updates view is not installed automatically; a newer one is.
- `state`, `bootstrap_choco` and `window` can be overridden in descendant sets; `package_id` can't.
- When several items name one package on one device, the strictest wins: absent over latest over
  present.
- A client's own package can only be required by that client's sets or items limited to it.

**Enforcement** runs when a scan arrives, when a run finishes (which starts the next requirement),
when policies change (devices that joined a set, edited items: missing scan data is requested
first), when a device connects, and from the scheduler every minute (back-offs ending, windows
opening). It starts at most one run per device at a time. `software::decide` is the pure function
deciding what to do; the e2e covers the whole path. After a failure the device backs off 15 minutes,
doubling to a day (`software_state.fail_count`); changing the package resets it. Only runs started
by enforcement count toward backing off.

Deleting a package is refused (409) while a policy requires it.

## Updates to third-party software

`GET /software/updates` lists, per device and catalog package, installed versions with a newer one
on offer: winget's `Available` column, `choco outdated`, `apt-get -s dist-upgrade`, dnf
`check-update`, and for uploaded installers the catalog's version when newer than the installed
one. A technician can upgrade selected rows now (an upgrade run), or ignore the version on offer.
`latest` policy items do the same automatically.

This is **not** the OS patch approval pipeline. Patches carry severities, categories, deferrals and
standing approvals because Windows Update and distributions publish them; winget, Chocolatey and
the other providers give a version number and nothing else, so there is nothing to approve by.
The approval here is the decision to put a package in a `latest` policy (or to upgrade a device by
hand), plus the ignore list.

## Agent side (`crates/rmm-agent/src/deploy/`)

`Manager` is the patch manager's twin: one operation at a time (it shares the patch manager's
lock, since package managers lock anyway; the self-updater waits for it), results kept until
`SoftwareAck` and resent after reconnects (the run ids go in `Auth.software_runs`), and a rescan of
the package after every run: the rescan decides whether the run worked (a provider that reports
success while the package isn't there is a failure). Linux commands run through the patch
manager's `cmd::run` with `detach`, so on systemd hosts they're in their own transient scope and
survive an agent restart.

- **winget** runs as SYSTEM, which has no `winget` on its PATH: the agent finds the newest
  `Microsoft.DesktopAppInstaller_<version>_x64__8wekyb3d8bbwe` under `Program Files\WindowsApps`
  itself and puts its directory first on PATH. `--source winget` (the Store's agreements and
  certificate requirements don't apply), `--accept-source-agreements --accept-package-agreements
  --disable-interactivity --silent`, `--scope machine` first and winget's own choice when the
  package has no machine installer. Exit codes "no applicable upgrade" and "already installed"
  count as success.
- **Chocolatey** from PATH, `ChocolateyInstall` or `ProgramData\chocolatey`; `list` is local-only
  from 2.0 and needs `--local-only` before. Exit 3010 and 1641 mean success with a reboot needed.
  When it is missing and the run allows it (`bootstrap_choco` in the policy item, or the box in
  the deploy dialog; off by default) the agent runs Chocolatey's official install script, which
  downloads and executes code from chocolatey.org.
- **Uploaded installers** are fetched from `/api/agent/software/{id}/installer` with the agent's
  credentials (the same route shape as signature databases, resumable), verified against the
  catalog's SHA-256 and run silently: `msiexec /i … /qn /norestart` plus the package's arguments,
  or the EXE with its arguments. Installed state comes from the Uninstall registry keys
  (product code, else DisplayName).
- Ids and versions are checked on both ends (`software::valid_token`: letters, digits and
  `. _ + - : ~`, never a leading `-`) because they end up on command lines; installer arguments
  are split into separate arguments (double quotes group) and never go through a shell.
- Debug builds only: `RMM_SOFTWARE_FAKE=<file>` replaces the providers with a JSON file, for the
  e2e (the same trick as `RMM_PATCH_FAKE`).

## API

All under `/api` (and `/api/v1` for keys with the `software` scope; see the OpenAPI document).

```
GET    /software/packages               ?client_id ?q ?platform      catalog with installed/update/policy counts
POST   /software/packages               create (client_id optional)
GET|PUT|DELETE /software/packages/{id}
POST   /software/packages/{id}/installer      multipart `file` (limited by RMM_ATTACHMENT_MAX_MB)
DELETE /software/packages/{id}/installer
GET    /software/packages/{id}/devices  ?show=installed|missing|noncompliant|all
POST   /software/deploy                 {package_id, op, agent_ids, bootstrap_choco}
POST   /software/scan                   {agent_ids}
GET    /software/runs  ·  GET /software/runs/{id}  ·  POST /software/runs/{id}/cancel
GET    /software/updates                POST /software/updates/install | /ignore
GET    /agents/{id}/software            what the device has, what its policies ask, its runs
GET    /agent/software/{id}/installer   for agents (X-Rmm-Agent + bearer secret)
```

Reading is open to everyone, filtered to their clients; deploying, scanning and updating need a
technician; changing the catalog follows the package's owner (admin for MSP-wide). Every
mutation is audited, including what a run did on a device (`agent.software_result`).

## Left out

- Dependencies, per-package licences/keys and detection scripts: use a script, or a package that
  does it.
- Downgrades: a pin is a floor.
- Alerts and health for failed deployments: failures show on the device, the package and the runs
  list; they don't open alerts yet.
- macOS (brew, pkg), Flatpak/snap, MSIX/Store apps, and Arch/pacman.
- The Windows paths have been compile-checked (mingw clippy) and their parsers tested against
  recorded output; they haven't run on a real Windows host (roadmap block 1).
