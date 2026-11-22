import type { User } from './types';

/** Logged-in user, loaded once by the root layout. */
export const session = $state<{ user: User | null; loaded: boolean }>({ user: null, loaded: false });

/** Public company settings (shown on the login page and in the sidebar). */
export const company = $state<{ name: string; attachmentMaxMb?: number }>({ name: '' });

/** "Acme IT RMM" when a company name is set, otherwise "RMM". */
export function brand(): string {
	return company.name ? `${company.name} RMM` : 'RMM';
}

let companyRequested = false;
export function loadCompany(force = false) {
	if (companyRequested && !force) return;
	companyRequested = true;
	fetch('/api/settings/public')
		.then((r) => (r.ok ? r.json() : null))
		.then((d) => {
			if (!d) return;
			company.name = d.company_name ?? '';
			if (typeof d.attachment_max_mb === 'number') company.attachmentMaxMb = d.attachment_max_mb;
		})
		.catch(() => {});
}

export function can(min: 'readonly' | 'technician' | 'admin'): boolean {
	const order = { readonly: 0, technician: 1, admin: 2 };
	return !!session.user && order[session.user.role] >= order[min];
}

export type Permission =
	| 'security.read'
	| 'security.respond'
	| 'security.manage'
	| 'billing.read'
	| 'billing.manage'
	| 'time.approve'
	| 'vault.read'
	| 'vault.manage'
	| 'audit.read';

/** Holds a named permission (the server sends the effective set; older servers: role defaults). */
export function allowed(perm: Permission): boolean {
	const u = session.user;
	if (!u) return false;
	if (u.permissions) return u.permissions.includes(perm);
	if (perm === 'security.read') return true;
	return perm === 'security.respond' || perm === 'vault.read' || perm === 'vault.manage' ? can('technician') : can('admin');
}
