import type { User } from './types';

/** Logged-in user, loaded once by the root layout. */
export const session = $state<{ user: User | null; loaded: boolean }>({ user: null, loaded: false });

export function can(min: 'readonly' | 'technician' | 'admin'): boolean {
	const order = { readonly: 0, technician: 1, admin: 2 };
	return !!session.user && order[session.user.role] >= order[min];
}
