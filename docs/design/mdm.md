# MDM, scoped down: Intune devices, read-only

A read-only view of a client's **Intune managed devices**, through the client's Entra ID connection from [identity management](identity.md). Parity plan section F2. Nothing is ever sent to Intune.

## Setup

On an Entra ID directory (Users tab → Directories), "Also read Intune devices" (`identity_sources.sync_devices`) with the extra application permission `DeviceManagementManagedDevices.Read.All`. The directory's sync then also lists `GET /deviceManagement/managedDevices` (paged; `id`, `deviceName`, `userPrincipalName`, `operatingSystem`, `osVersion`, `complianceState`, `isEncrypted`, `managedDeviceOwnerType`, `serialNumber`, `model`, `manufacturer`, `enrolledDateTime`, `lastSyncDateTime`; Intune's `0001-01-01` "never" is none). If devices can't be read, the users are still synced and the source's `last_error` says why (`Intune devices: ...`). "Test" checks the device list too when it is switched on. Switching it off deletes the stored devices.

## Data

Migration `0051_mdm.sql`: `mdm_devices` (`source_id`, `external_id`, `name`, `user_upn`, `os`, `os_version`, `compliance`, `encrypted`, `ownership` company/personal/unknown, `serial`, `model`, `manufacturer`, `enrolled_at`, `last_sync_at`, `agent_id`, `synced_at`). Each sync replaces the source's devices: new ones added, changed ones updated, those gone from Intune deleted. `encrypted` is declared `bool` rather than `boolean`: it isn't a sealed-value flag, and `rotate`'s schema check looks for `*encrypted boolean` columns.

**Matching to agents**: the plan says by serial number, else host name. Agents don't report a serial number yet, so the match is **by host name**: the device name and the agent's hostname up to the first dot, ignoring case, within the client (the most recently seen agent when several match). Adding the BIOS serial to the agent's inventory would let the serial match go first; it's left for a later change, since it touches the inventory message other features use.

## API

- `GET /clients/{id}/mdm/devices`: paged (sort `name`, `last_sync`, `compliance`, `user`), filters `compliance` (comma-separated), `os`, `unmatched`, `q` (name, user, serial). Public API `listMdmDevices`, group `agents`; the key needs `identity.read`.
- `GET /mdm/devices/{id}`.
- `GET /clients/{id}/mdm/summary` (an addition, for the tab): how many sources read devices, the count per compliance state, how many devices have no agent, and the client's Windows and macOS workstations with an agent but no Intune device (up to 500; servers and Linux aren't expected in Intune).

Reading needs `identity.read`; another client's devices are 404.

## UI

Client page → **Mobile and Intune**: counts (in Intune, compliant, not compliant, in Intune without an agent), the device list with a compliance badge, "not encrypted", last check-in, user and ownership, and a link to the matched agent; and the two gap lists: "in Intune, no agent" (the `unmatched` filter) and "agent, not in Intune".

## Cut, deliberately

Remote actions (wipe, retire, lock, sync: destructive, need `DeviceManagementManagedDevices.PrivilegedOperations.All`, and untested against a real tenant); compliance and configuration policy authoring; app deployment; Apple MDM and Android Enterprise; our own MDM server; alerts on non-compliance (possible after step C1b).

## Tests

Unit: a recorded `managedDevices` page (`crates/rmm-server/tests/fixtures/graph-managed-devices.json`). e2e `identity`: the Graph mock's devices are synced; the one named after the test agent is matched to it (case-insensitively); `unmatched` and `compliance` filters; the summary; another client's technician gets 404; a device removed from Intune is gone after the next sync. Visual: the tab.

## Unproven here

A real tenant: the permission, `isEncrypted` and `complianceState` values for each platform, paging on a large tenant, and how device names compare with agent host names in practice (Autopilot naming templates, macOS names with spaces). See [ROADMAP.md](../ROADMAP.md) block 2.
