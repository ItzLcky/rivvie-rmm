import { api } from '#lib/api.js';
import type { BillingSettings, ClientBilling } from './types';

let settings: Promise<BillingSettings> | null = null;

/** The company's billing settings, fetched once per page load (call `refreshSettings` after saving). */
export function billingSettings(): Promise<BillingSettings> {
	settings ??= api.get<BillingSettings>('/settings/billing').catch((e) => {
		settings = null;
		throw e;
	});
	return settings;
}

export function refreshSettings() {
	settings = null;
	perClient.clear();
}

const perClient = new Map<string, Promise<string>>();

/** The currency a client is billed in: its own, else the company's (cached; `forget` after changing it). */
export function clientCurrency(clientId: string): Promise<string> {
	let p = perClient.get(clientId);
	if (!p) {
		p = Promise.all([billingSettings(), api.get<ClientBilling>(`/clients/${clientId}/billing`).catch(() => null)]).then(([s, c]) => c?.currency || s.currency);
		p.catch(() => perClient.delete(clientId));
		perClient.set(clientId, p);
	}
	return p;
}

export function forgetClientCurrency(clientId: string) {
	perClient.delete(clientId);
}

/** Currencies for several clients at once: { client id: code }. */
export async function clientCurrencies(ids: string[]): Promise<Record<string, string>> {
	const uniq = [...new Set(ids)];
	const codes = await Promise.all(uniq.map((id) => clientCurrency(id).catch(() => '')));
	return Object.fromEntries(uniq.map((id, i) => [id, codes[i]]));
}

/** Common ISO 4217 codes for pickers (any three-letter code is accepted). */
export const currencies = [
	'USD', 'EUR', 'GBP', 'CAD', 'AUD', 'NZD', 'CHF', 'SEK', 'NOK', 'DKK', 'PLN', 'CZK', 'HUF', 'JPY', 'CNY', 'HKD', 'SGD', 'INR', 'ZAR',
	'BRL', 'MXN', 'AED', 'SAR', 'ILS', 'KRW', 'TRY', 'BHD', 'KWD'
];
