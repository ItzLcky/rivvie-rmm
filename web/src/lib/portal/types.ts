import type { Branding } from '#lib/branding.js';

export type StatusCategory = 'new' | 'open' | 'waiting_client' | 'waiting_vendor' | 'resolved' | 'closed';

export interface PortalContact {
	id: string;
	client_id: string;
	client_name: string;
	site_id: string | null;
	name: string;
	email: string;
	is_primary: boolean;
	portal_all_tickets: boolean;
}

export interface PortalMe {
	contact: PortalContact;
	company_name: string;
	welcome: string;
	devices: boolean;
	sees_all_tickets: boolean;
	has_password: boolean;
	totp_enabled: boolean;
	/** RMM_ATTACHMENT_MAX_MB: the largest file a message can carry. */
	attachment_max_mb?: number;
	/** The contact's client's branding over the instance's (older servers: absent). */
	branding?: Branding;
}

export interface PortalInfo {
	company_name: string;
	welcome: string;
	/** The instance's branding (a client's applies only after sign-in). */
	branding?: Branding;
}

export interface PortalTicket {
	id: string;
	number: number;
	subject: string;
	status_name: string;
	status_category: StatusCategory;
	priority: number;
	contact_name: string | null;
	created_at: string;
	last_activity_at: string;
	merged_into: string | null;
}

export interface PortalEvent {
	id: number;
	kind: 'created' | 'reply' | 'message';
	author_kind: 'staff' | 'contact';
	author_name: string;
	body: string;
	created_at: string;
}

export interface PortalAttachment {
	id: string;
	event_id: number | null;
	name: string;
	content_type: string;
	size: number;
	created_at: string;
}

export interface PortalTicketDetail extends PortalTicket {
	events: PortalEvent[];
	attachments: PortalAttachment[];
	merged_into_number: number | null;
}

export interface KbSummary {
	id: string;
	title: string;
	category: string;
	excerpt: string;
	updated_at: string;
}

export interface KbArticle {
	id: string;
	title: string;
	category: string;
	body: string;
	updated_at: string;
}

export interface PortalDevice {
	id: string;
	hostname: string;
	site_name: string;
	os_name: string;
	os_version: string;
	online: boolean;
	last_seen_at: string | null;
	missing_patches: number;
	reboot_pending: boolean;
}

export interface TotpSetup {
	secret: string;
	otpauth_uri: string;
	qr_svg: string;
}

export interface Survey {
	number: number;
	subject: string;
	rating: 'good' | 'bad' | null;
	comment: string;
	company_name: string;
}
