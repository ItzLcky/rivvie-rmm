# Disk encryption status and recovery-key escrow

Design record, 2026-11-24 (parity plan B1). Migration `0038_disk_encryption.sql`; agent `crates/rmm-agent/src/diskenc/`; protocol `crates/rmm-proto/src/diskenc.rs`; server `src/diskenc.rs`, `api/diskenc.rs`; web `AgentDiskEncryption.svelte`, `DiskEncryptionFleet.svelte`, `DiskEncryptionForm.svelte`.

Every agent reports the encryption state of its fixed volumes. BitLocker recovery passwords are escrowed into the device's client vault as managed items. Encryption is never turned on from here: that needs TPM readiness, a restart and the user.

## What the agent reads

| OS | Source | Escrow |
|---|---|---|
| Windows | One embedded PowerShell script over CIM `Win32_EncryptableVolume` (`root/CIMV2/Security/MicrosoftVolumeEncryption`): `GetConversionStatus`, `GetEncryptionMethod`, `GetLockStatus`, `GetKeyProtectors`, `GetKeyProtectorType`. Fixed drives come from `Win32_LogicalDisk` (`DriveType=3`), so USB disks are left out. TPM from `Win32_Tpm`. A Windows without the BitLocker classes reports its fixed drives as unencrypted, not as an error. Any other CIM failure falls back to parsing `manage-bde -status` (English only, and without protector ids, so no escrow). | Yes |
| macOS | `fdesetup status` (and `haspersonalrecoverykey`, `hasinstitutionalrecoverykey`), the device from `diskutil info -plist /`. One volume, `/`. | No: the key can't be read after the fact |
| Linux | `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS,UUID,PKNAME,RM` (`MOUNTPOINT` on util-linux before 2.37). A filesystem is encrypted when it, or a device below it (LVM on LUKS), is `crypt` or `crypto_LUKS`. One volume per filesystem (`/`, then `/home`, else its shortest mount); `/boot`, the EFI partition, swap, loop devices and removable media are left out. TPM from `/sys/class/tpm`. | No: a key slot needs an existing passphrase |

**Status:** `encrypted`, `encrypting` (including paused), `decrypting`, `unencrypted`, `suspended` (fully encrypted with protection off: BitLocker suspended), `unknown`. **Protectors** are kinds (`tpm`, `recovery_password`, `tpm_pin`, `passphrase`...); the BitLocker numerical password's id is `recovery_protector_id`.

The agent reports after connecting, when the state changes (re-read every 15 minutes), at least every 6 hours, and on `DiskEncryptionRefresh`. Debug builds: `RMM_DISKENC_FAKE=<file>` reports the JSON in that file while it exists (with `keys` and `fail` knobs for the e2e).

## Escrow: pulled, never pushed

Reports carry protector ids only. After storing a report the server compares each BitLocker volume's `recovery_protector_id` with the one it escrowed; where they differ and the device's `disk_encryption` policy says `escrow_recovery_keys`, it sends `DiskRecoveryRequest {request_id, volume_id, protector_id}`. The agent answers `DiskRecoveryKey` with the password (it travels as `rmm_proto::localadmin::Secret`, which never shows in `Debug` output). The server accepts it only from the agent it asked, for a request still pending (two minutes), with matching volume and protector, then calls

```
vault::put_managed(kind = disk_recovery, agent_id, reference = "<agent>:<volume>",
                   name = "BitLocker recovery: HOST C:", username = <protector id>, state = "escrowed")
```

A rotated key updates the same item and moves the old one into its history. Audited: `diskenc.escrow` (volume, protector id, item) plus `vault.system_write`; never the key. Without `RMM_DATA_KEY` nothing is requested. Keys are reachable only through the vault (2FA, `vault.read`, reveal rate limit).

`add_recovery_protector` (off by default) adds a numerical password to an encrypted volume that has none (`ProtectKeyWithNumericalPassword`; Windows makes the password); a refusal (Group Policy often forbids them) is shown on the volume and not retried for a day. `POST /agents/{id}/disk-encryption/{volume}/rotate-key` (`security.respond`) adds a new recovery password and deletes the old ones, waits for the agent (90 s), and audits `diskenc.rotate`; the next report escrows the new one.

## Data

`disk_volumes` (primary key `(agent_id, volume_id)`) as the plan has it, plus `escrow_error` (why the last attempt failed) and `suspended_since` (the alert's grace period counts from it: an addition to the plan). `agents.diskenc_at`, `diskenc_error`, `tpm`, and `diskenc_status` (`encrypted`, `partial`, `none`; also an addition: the device list's Encryption column and `?encryption=` filter read it). Volumes that disappear from a report are deleted; their keys stay in the vault, and deleting the device keeps them too.

Policy module `disk_encryption`, single-instance, item `00000000-0000-4000-8000-000000000005` in All devices: `{escrow_recovery_keys: true, add_recovery_protector: false}`. Editing it needs `security.manage`.

## Alerts

Kind `disk_encryption`, params `{volumes: "os" | "all_fixed", require_escrow: true, grace_hours: 24}`. One alert per volume, key `vol:<id>`, with the first finding: `unencrypted`; `suspended` for longer than the grace period; `not_escrowed` (BitLocker only: no recovery password, or not the one in the vault, and no request in flight). Encrypting is not a finding. Checked on every report and key, on `recheck_item`/`recheck_agent`, and every minute for suspended volumes (the grace period ends without a report).

## API and UI

`GET /agents/{id}/disk-encryption`, `POST /agents/{id}/disk-encryption/refresh` (technician), `POST /agents/{id}/disk-encryption/{volume}/rotate-key`, `GET /disk-encryption?client_id&status&escrowed&os_only&alerting&q` (keyset-paged). The two GETs are public (`getAgentDiskEncryption`, `listDiskEncryption`, group `security`); `vault_item_id` is only returned to people who may open the vault. Live updates reuse the `security` event.

UI: a Disk encryption card on the device's Inventory tab (with "Recovery key" opening the credential, and Rotate); Security → Disk encryption (fleet list); the policy set's Disk encryption section; the alert kind; an Encryption column and filter on Devices; a "Disk encryption coverage" block in the QBR.

## Not proven here

The CIM and `manage-bde` parsers are tested against output written from Microsoft's documentation, and the Windows CI runner has no BitLocker: there the report lists an unencrypted `C:`. A real BitLocker volume, escrow and rotation, TPM states and Group Policy refusing recovery passwords are in [windows-testing.md](windows-testing.md). FileVault parsing is unit-tested; macOS only builds in CI.
