/** Money is integer minor units (cents). The company currency is only readable with billing.read. */
import { api } from '#lib/api.js';
import { allowed } from '#lib/session.svelte.js';
import type { BillingSettings } from './types';

export const billing = $state<{ currency: string | null; loaded: boolean }>({ currency: null, loaded: false });

let inflight: Promise<void> | null = null;

/** Loads the company currency once (no-op without billing.read). */
export function loadCurrency(): Promise<void> {
	if (billing.loaded || !allowed('billing.read')) return Promise.resolve();
	inflight ??= api
		.get<BillingSettings>('/settings/billing')
		.then((s) => {
			billing.currency = s.currency;
			billing.loaded = true;
		})
		.catch(() => {})
		.finally(() => (inflight = null));
	return inflight;
}

const formatters = new Map<string, Intl.NumberFormat>();
function formatter(currency: string): Intl.NumberFormat {
	let f = formatters.get(currency);
	if (!f) {
		try {
			f = new Intl.NumberFormat(undefined, { style: 'currency', currency });
		} catch {
			f = new Intl.NumberFormat(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
		}
		formatters.set(currency, f);
	}
	return f;
}

/** Minor units as "€1,234.50"; "–" for null. Uses the company currency unless one is given. */
export function money(minor: number | null | undefined, currency: string | null = billing.currency): string {
	if (minor == null || !currency) return '–';
	const f = formatter(currency);
	const digits = f.resolvedOptions().maximumFractionDigits ?? 2;
	return f.format(minor / 10 ** digits);
}

/** Whether money can be shown at all for this user. */
export function showMoney(): boolean {
	return allowed('billing.read') && !!billing.currency;
}
