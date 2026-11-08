import type { User } from './types';

/** Logged-in user, loaded once by the root layout. */
export const session = $state<{ user: User | null; loaded: boolean }>({ user: null, loaded: false });

/** Public company settings (shown on the login page and in the sidebar). */
export const company = $state<{ name: string }>({ name: '' });

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
		.then((d) => d && (company.name = d.company_name ?? ''))
		.catch(() => {});
}

export function can(min: 'readonly' | 'technician' | 'admin'): boolean {
	const order = { readonly: 0, technician: 1, admin: 2 };
	return !!session.user && order[session.user.role] >= order[min];
}
