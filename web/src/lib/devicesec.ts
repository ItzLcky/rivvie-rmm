/** Disk encryption and local admin rotation (docs/design/disk-encryption.md, docs/design/local-admin.md). */
import type { Tone } from '#lib/ui/Badge.svelte';

export type VolumeStatus = 'encrypted' | 'encrypting' | 'decrypting' | 'unencrypted' | 'suspended' | 'unknown';
export type EncryptionSummary = 'encrypted' | 'partial' | 'none';

export interface DiskVolume {
	agent_id: string; hostname: string; online: boolean; client_id: string; client_name: string; site_name: string;
	volume_id: string; mount: string; device: string; kind: 'bitlocker' | 'filevault' | 'luks' | 'none'; role: 'os' | 'data';
	status: VolumeStatus; percent: number | null; method: string | null; protectors: string[]; protection_on: boolean; locked: boolean;
	recovery_protector_id: string | null; escrowed: boolean; escrowed_at: string | null; escrow_error: string | null;
	vault_item_id: string | null; suspended_since: string | null; updated_at: string; alerting: boolean;
}
export interface Tpm { present: boolean; ready?: boolean | null; enabled?: boolean | null; activated?: boolean | null; version?: string | null; manufacturer?: string | null }
export interface AgentDiskEncryption {
	reported_at: string | null; error: string | null; tpm: Tpm | null; summary: EncryptionSummary | null;
	escrow_recovery_keys: boolean; add_recovery_protector: boolean; volumes: DiskVolume[];
}

export const volumeStatusLabel: Record<VolumeStatus, string> = {
	encrypted: 'Encrypted', encrypting: 'Encrypting', decrypting: 'Decrypting', unencrypted: 'Not encrypted', suspended: 'Suspended', unknown: 'Unknown'
};
export const volumeStatusTone: Record<VolumeStatus, Tone> = {
	encrypted: 'success', encrypting: 'info', decrypting: 'warning', unencrypted: 'danger', suspended: 'warning', unknown: 'neutral'
};
export const kindLabel: Record<DiskVolume['kind'], string> = { bitlocker: 'BitLocker', filevault: 'FileVault', luks: 'LUKS', none: 'None' };
export const summaryLabel: Record<EncryptionSummary | 'unknown', string> = { encrypted: 'Encrypted', partial: 'Partly', none: 'Not encrypted', unknown: 'Not reported' };
export const summaryTone: Record<EncryptionSummary | 'unknown', Tone> = { encrypted: 'success', partial: 'warning', none: 'danger', unknown: 'neutral' };
export const protectorLabel: Record<string, string> = {
	tpm: 'TPM', recovery_password: 'Recovery password', tpm_pin: 'TPM + PIN', tpm_startup_key: 'TPM + startup key', tpm_pin_startup_key: 'TPM + PIN + key',
	external_key: 'Startup key', passphrase: 'Passphrase', password: 'Password', public_key: 'Certificate', tpm_certificate: 'TPM certificate', sid: 'AD account',
	personal_recovery_key: 'Personal recovery key', institutional_recovery_key: 'Institutional recovery key'
};

export type LocalAdminStatus = 'ok' | 'pending' | 'failed' | 'unsupported' | 'conflict';
export interface LocalAdminView {
	policy: { enabled: boolean; account: string; create: boolean; rotate_days: number; length: number; rotate_after_reveal_hours: number };
	state: {
		agent_id: string; account: string; vault_item_id: string | null; status: LocalAdminStatus; rotated_at: string | null; next_rotate_at: string | null;
		rotate_reason: 'first' | 'schedule' | 'reveal' | 'manual' | null; attempts: number; sent_at: string | null; last_error: string | null; updated_at: string;
	} | null;
	managed_state: string | null;
	needs_data_key: boolean;
}
export const localAdminLabel: Record<LocalAdminStatus, string> = { ok: 'Rotated', pending: 'Rotating', failed: 'Failed', unsupported: 'Unsupported', conflict: 'Conflict' };
export const localAdminTone: Record<LocalAdminStatus, Tone> = { ok: 'success', pending: 'info', failed: 'danger', unsupported: 'neutral', conflict: 'warning' };
