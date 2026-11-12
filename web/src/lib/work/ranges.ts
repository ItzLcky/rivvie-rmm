/** Report date ranges (inclusive `YYYY-MM-DD`s in the browser's calendar). */
import { addDays, localDay } from './time';

export type Preset = 'last30' | 'this_month' | 'last_month' | 'last_quarter' | 'this_quarter';

export const presets: { value: Preset; label: string }[] = [
	{ value: 'last30', label: 'Last 30 days' },
	{ value: 'this_month', label: 'This month' },
	{ value: 'last_month', label: 'Last month' },
	{ value: 'this_quarter', label: 'This quarter' },
	{ value: 'last_quarter', label: 'Last quarter' }
];

const pad = (n: number) => String(n).padStart(2, '0');
const first = (y: number, m0: number) => {
	const d = new Date(y, m0, 1);
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-01`;
};

export function presetRange(p: Preset, today = new Date()): { from: string; to: string } {
	const y = today.getFullYear();
	const m = today.getMonth();
	const q = Math.floor(m / 3) * 3;
	switch (p) {
		case 'this_month':
			return { from: first(y, m), to: localDay(today) };
		case 'last_month':
			return { from: first(y, m - 1), to: addDays(first(y, m), -1) };
		case 'this_quarter':
			return { from: first(y, q), to: localDay(today) };
		case 'last_quarter':
			return { from: first(y, q - 3), to: addDays(first(y, q), -1) };
		default:
			return { from: addDays(localDay(today), -29), to: localDay(today) };
	}
}

/** The last `n` complete-or-current quarters, newest first. */
export function quarters(n = 8, today = new Date()): { value: string; label: string; from: string; to: string }[] {
	const out = [];
	let y = today.getFullYear();
	let q = Math.floor(today.getMonth() / 3);
	for (let i = 0; i < n; i++) {
		const from = first(y, q * 3);
		const to = addDays(first(y, q * 3 + 3), -1);
		out.push({ value: from, label: `Q${q + 1} ${y}${i === 0 ? ' (so far)' : ''}`, from, to });
		q--;
		if (q < 0) {
			q = 3;
			y--;
		}
	}
	return out;
}
