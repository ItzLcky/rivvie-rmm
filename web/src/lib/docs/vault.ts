/**
 * Vault access from the browser. Secrets are fetched one at a time on request and kept only
 * in the component that shows them (never in the URL, storage or a shared store).
 */
import { ApiError, api } from '#lib/api.js';
import { allowed, session } from '#lib/session.svelte.js';
import type { TotpCode } from './types.js';

/** Why the vault can't be used, as the server says it. */
export type VaultProblem = 'mfa' | 'key' | 'perm' | 'notfound' | 'throttled';

export function vaultProblem(e: unknown): VaultProblem | null {
	if (!(e instanceof ApiError)) return null;
	if (e.status === 403 && /two-factor/i.test(e.message)) return 'mfa';
	if (e.status === 409 && /RMM_DATA_KEY/.test(e.message)) return 'key';
	if (e.status === 403) return 'perm';
	if (e.status === 404) return 'notfound';
	if (e.status === 429) return 'throttled';
	return null;
}

/** Seconds to wait after a 429 ("too many requests; try again in 12 seconds"). */
export function retryIn(e: unknown): number | null {
	const m = e instanceof Error ? /in (\d+) seconds?/.exec(e.message) : null;
	return m ? Number(m[1]) : null;
}

/** What the current user can do with credentials, before asking the server. */
export function vaultAccess(): 'ok' | 'mfa' | 'none' {
	if (!allowed('vault.read')) return 'none';
	return session.user?.mfa_enabled || session.user?.sso_session || session.user?.totp_enabled ? 'ok' : 'mfa';
}
export const canManageVault = () => allowed('vault.manage') && !!(session.user?.mfa_enabled || session.user?.sso_session || session.user?.totp_enabled);

/** A one-line, human message for a failed reveal or code. */
export function secretError(e: unknown): string {
	switch (vaultProblem(e)) {
		case 'mfa':
			return 'Turn on two-factor authentication to use the vault.';
		case 'key':
			return 'The vault is unavailable: RMM_DATA_KEY isn’t set on the server.';
		case 'perm':
			return 'You don’t have access to credentials.';
		case 'notfound':
			return 'This credential no longer exists.';
		case 'throttled': {
			const s = retryIn(e);
			return `Too many reveals in a short time. Try again${s ? ` in ${s} s` : ' shortly'}.`;
		}
		default:
			return e instanceof Error ? e.message : String(e);
	}
}

export const reveal = (id: string, field: 'password' | 'notes') => api.post<{ value: string }>(`/vault/${id}/reveal`, { field }).then((r) => r.value);
export const revealHistory = (id: string, history: number) => api.post<{ value: string }>(`/vault/${id}/reveal`, { history }).then((r) => r.value);
export const totpCode = (id: string) => api.post<TotpCode>(`/vault/${id}/totp`, {});

/** How long a revealed password stays on screen. */
export const REVEAL_MS = 30_000;

/**
 * A password from the generator: `crypto.getRandomValues` with rejection sampling (no modulo
 * bias), at least one character of each chosen class.
 */
export interface GenOptions {
	length: number;
	lower: boolean;
	upper: boolean;
	digits: boolean;
	symbols: boolean;
	/** Leave out characters that are easy to misread (0 O o 1 l I |). */
	unambiguous: boolean;
}
export const GEN_DEFAULTS: GenOptions = { length: 20, lower: true, upper: true, digits: true, symbols: true, unambiguous: false };

export function generatePassword(o: GenOptions): string {
	const strip = (s: string) => (o.unambiguous ? s.replace(/[0Oo1lI|]/g, '') : s);
	const classes = [
		o.lower && strip('abcdefghijklmnopqrstuvwxyz'),
		o.upper && strip('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
		o.digits && strip('0123456789'),
		o.symbols && strip('!#$%&*+-.:;=?@^_~')
	].filter((c): c is string => !!c);
	if (!classes.length) return '';
	const length = Math.max(classes.length, Math.min(128, Math.round(o.length)));
	const all = classes.join('');
	const pick = (set: string) => {
		const limit = 256 - (256 % set.length);
		const buf = new Uint8Array(1);
		for (;;) {
			crypto.getRandomValues(buf);
			if (buf[0] < limit) return set[buf[0] % set.length];
		}
	};
	const chars = [...classes.map(pick), ...Array.from({ length: length - classes.length }, () => pick(all))];
	// Shuffle so the guaranteed characters aren't always first (Fisher-Yates, unbiased index).
	for (let i = chars.length - 1; i > 0; i--) {
		const j = Number(pickIndex(i + 1));
		[chars[i], chars[j]] = [chars[j], chars[i]];
	}
	return chars.join('');
}
function pickIndex(n: number): number {
	const limit = 2 ** 32 - (2 ** 32 % n);
	const buf = new Uint32Array(1);
	for (;;) {
		crypto.getRandomValues(buf);
		if (buf[0] < limit) return buf[0] % n;
	}
}
