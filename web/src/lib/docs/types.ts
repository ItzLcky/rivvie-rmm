/** Client documentation and the password vault (docs/design/documentation.md). */

import type { StatusCategory } from '#lib/types.js';

/** A page in a client's list (`body` is null there) or on its own. */
export interface DocRow {
	id: string;
	client_id: string;
	title: string;
	category_id: string | null;
	/** The category's name, "" when there is none. */
	category: string;
	body: string | null;
	updated_by_name: string | null;
	updated_at: string;
	revisions: number;
}

export interface DocRevisionRef {
	id: number;
	title: string;
	edited_by: string | null;
	edited_at: string;
}

export interface DocRevision {
	title: string;
	body: string;
	edited_at: string;
}

export interface DocDetail extends DocRow {
	body: string;
	history: DocRevisionRef[];
	/** Metadata of the vault items the page links to; empty without vault access. */
	credentials: VaultItem[];
	/** True when the page links to credentials the caller may not see. */
	credentials_hidden: boolean;
	/** The tickets that link the page (that the caller may see), newest first, at most 50. */
	tickets: DocTicket[];
}

export interface DocTicket {
	id: string;
	number: number;
	subject: string;
	/** The board status's name. */
	status: string;
	status_category: StatusCategory;
	updated_at: string;
}

export interface DocCategory {
	id: string;
	name: string;
	position: number;
	docs: number;
	templates: number;
}

export interface DocTemplate {
	id: string;
	name: string;
	category_id: string | null;
	category: string;
	description: string;
	/** Null in the list. */
	body: string | null;
	updated_by_name: string | null;
	updated_at: string;
}

/** A credential's metadata. Secrets never come in this shape: they're revealed one at a time. */
export interface VaultItem {
	id: string;
	client_id: string;
	name: string;
	username: string;
	url: string;
	has_password: boolean;
	has_totp: boolean;
	has_notes: boolean;
	/** Pages linking to it. */
	docs: number;
	password_changed_at: string | null;
	updated_at: string;
	updated_by_name: string | null;
	/** Set on items the server keeps (recovery keys, rotated admin passwords): their password and username can't be edited. */
	managed_kind?: ManagedKind | null;
	agent_id?: string | null;
	agent_hostname?: string | null;
	managed_state?: string | null;
}

export type ManagedKind = 'disk_recovery' | 'local_admin' | 'identity';
export const managedKindLabel: Record<ManagedKind, string> = { disk_recovery: 'Disk recovery key', local_admin: 'Local admin', identity: 'Identity reset' };

export interface VaultDetail extends VaultItem {
	linked_docs: { id: string; title: string }[];
	history: { id: number; replaced_at: string; replaced_by_name: string | null }[];
}

export interface TotpCode {
	code: string;
	digits: number;
	period: number;
	/** Seconds the code is still valid for when it was made. */
	remaining: number;
}
