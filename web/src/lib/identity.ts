// Identity management (docs/design/identity.md) and Intune devices (docs/design/mdm.md).
import type { Tone } from './ui/Badge.svelte';

export type SourceKind = 'ad' | 'entra';

export interface IdentitySource {
	id: string;
	client_id: string;
	kind: SourceKind;
	name: string;
	agent_id: string | null;
	agent_hostname: string | null;
	agent_online: boolean | null;
	tenant_id: string;
	app_client_id: string;
	has_secret: boolean;
	sync_devices: boolean;
	sync_minutes: number;
	enabled: boolean;
	last_sync_at: string | null;
	last_error: string | null;
	users: number;
	groups: number;
	devices: number;
}

export interface DirUser {
	id: string;
	source_id: string;
	source_name: string;
	kind: SourceKind;
	external_id: string;
	username: string;
	upn: string;
	display_name: string;
	email: string;
	enabled: boolean;
	locked: boolean;
	privileged: boolean;
	synced_from_ad: boolean;
	last_logon_at: string | null;
	password_last_set: string | null;
	password_expires_at: string | null;
	mfa_registered: boolean | null;
	department: string;
	title: string;
	contact_id: string | null;
	contact_name: string | null;
	deleted_at: string | null;
	synced_at: string;
}

export interface DirUserDetail extends DirUser {
	client_id: string;
	groups: { id: string; name: string; privileged: boolean }[];
	vault_item_id: string | null;
	can_manage: boolean;
}

export interface DirGroup {
	id: string;
	source_id: string;
	source_name: string;
	name: string;
	description: string;
	privileged: boolean;
	members: number;
}

export type IdentityAction = 'unlock' | 'reset-password' | 'disable' | 'enable' | 'revoke-sessions' | 'remove-groups';

export interface ActionOutcome {
	ok: boolean;
	delivered?: 'shown' | 'vault';
	password?: string;
	item_id?: string;
}

export const kindLabel: Record<SourceKind, string> = { ad: 'Active Directory', entra: 'Entra ID' };

/** Accounts not used for this long count as stale (the server's filter). */
export const STALE_DAYS = 90;

export const userFilters = [
	{ value: 'locked', label: 'Locked' },
	{ value: 'disabled', label: 'Disabled' },
	{ value: 'stale', label: `Not used in ${STALE_DAYS} days` },
	{ value: 'no_mfa', label: 'No MFA' },
	{ value: 'privileged', label: 'Privileged' }
];

/** Why an action can't be offered for this account, if it can't. */
export function unavailable(u: DirUser, a: IdentityAction): string | null {
	if (u.deleted_at) return 'The account is no longer in the directory.';
	if (u.kind === 'entra' && u.synced_from_ad) return 'Synced from on-premises Active Directory: change it there.';
	if (a === 'unlock' && u.kind === 'entra') return 'Entra ID has no unlock; reset the password instead.';
	if (a === 'unlock' && !u.locked) return 'The account isn’t locked.';
	if (a === 'revoke-sessions' && u.kind === 'ad') return 'Active Directory has no sessions to revoke.';
	return null;
}

export interface MdmDevice {
	id: string;
	source_id: string;
	source_name: string;
	external_id: string;
	name: string;
	user_upn: string;
	os: string;
	os_version: string;
	compliance: string;
	encrypted: boolean | null;
	ownership: string;
	serial: string;
	model: string;
	manufacturer: string;
	enrolled_at: string | null;
	last_sync_at: string | null;
	agent_id: string | null;
	agent_hostname: string | null;
	agent_online: boolean | null;
	synced_at: string;
}

export interface MdmSummary {
	sources: number;
	total: number;
	by_compliance: Record<string, number>;
	unmatched: number;
	agents_not_in_intune: { id: string; hostname: string; os_family: string; online: boolean; last_seen_at: string | null }[];
}

export const complianceLabel: Record<string, string> = {
	compliant: 'Compliant',
	noncompliant: 'Not compliant',
	inGracePeriod: 'In grace period',
	conflict: 'Conflict',
	error: 'Error',
	configManager: 'Configuration Manager',
	unknown: 'Unknown'
};

export function complianceTone(c: string): Tone {
	if (c === 'compliant') return 'success';
	if (c === 'noncompliant' || c === 'error') return 'danger';
	if (c === 'inGracePeriod' || c === 'conflict') return 'warning';
	return 'neutral';
}

// Ticket templates and checklists.
export type ChecklistAction = 'identity.disable' | 'identity.reset_password' | 'identity.remove_groups' | 'identity.revoke_sessions';

export const checklistActions: { value: ChecklistAction; label: string }[] = [
	{ value: 'identity.disable', label: 'Disable the account' },
	{ value: 'identity.reset_password', label: 'Reset the password (saved to the vault)' },
	{ value: 'identity.remove_groups', label: 'Remove from every group' },
	{ value: 'identity.revoke_sessions', label: 'Sign out of every session (Entra ID)' }
];

export interface TicketTemplate {
	id: string;
	name: string;
	client_id: string | null;
	client_name: string | null;
	board_id: string | null;
	type_id: string | null;
	priority: number;
	subject: string;
	body: string;
	checklist: { text: string; action?: ChecklistAction | null }[];
	updated_at: string;
}

export interface ChecklistItem {
	id: string;
	position: number;
	text: string;
	action: ChecklistAction | null;
	action_state: string | null;
	done_by: string | null;
	done_by_name: string | null;
	done_at: string | null;
}

export interface Checklist {
	identity_user: { id: string; display_name?: string; username?: string; upn?: string; kind?: SourceKind; enabled?: boolean; privileged?: boolean; deleted?: boolean } | null;
	items: ChecklistItem[];
	outcome?: ActionOutcome;
}
