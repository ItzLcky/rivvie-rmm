/** Durations and dates for time tracking. Durations are whole minutes; days are `YYYY-MM-DD`. */

/** 90 → "1 h 30 min", 45 → "45 min", 120 → "2 h". */
export function fmtMinutes(m: number | null | undefined): string {
	if (m == null) return '–';
	const neg = m < 0;
	m = Math.round(Math.abs(m));
	const h = Math.floor(m / 60);
	const r = m % 60;
	const s = h && r ? `${h} h ${r} min` : h ? `${h} h` : `${r} min`;
	return neg ? `−${s}` : s;
}

/** 90 → "1.5" (hours, up to two decimals). */
export function hours(m: number | null | undefined, digits = 2): string {
	if (m == null) return '–';
	return String(Math.round((m / 60) * 10 ** digits) / 10 ** digits);
}

/** 5400 seconds → "1:30:00". */
export function clock(secs: number): string {
	secs = Math.max(0, Math.floor(secs));
	const h = Math.floor(secs / 3600);
	const m = Math.floor((secs % 3600) / 60);
	const s = secs % 60;
	return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

/**
 * Reads a duration as minutes: "1.5" or "1,5" (hours), "1:30", "90m", "90 min", "2h", "1h 30m",
 * "1 h 30 min". Null when it can't be read or isn't positive.
 */
export function parseDuration(input: string): number | null {
	const s = input.trim().toLowerCase().replace(',', '.');
	if (!s) return null;
	let m: number | null = null;
	let x: RegExpMatchArray | null;
	if ((x = s.match(/^(\d+):([0-5]?\d)$/))) m = Number(x[1]) * 60 + Number(x[2]);
	else if ((x = s.match(/^(\d+(?:\.\d+)?)$/))) m = Number(x[1]) * 60;
	else if ((x = s.match(/^(?:(\d+(?:\.\d+)?)\s*h(?:ours?|rs?)?)?\s*(?:(\d+)\s*m(?:in(?:utes?|s)?)?)?$/)) && (x[1] || x[2]))
		m = Number(x[1] ?? 0) * 60 + Number(x[2] ?? 0);
	if (m == null || !isFinite(m)) return null;
	m = Math.round(m);
	return m > 0 ? m : null;
}

/** Minutes as the decimal-hours text an input starts with. */
export function durationInput(m: number | null | undefined): string {
	if (!m) return '';
	return m % 60 === 0 ? String(m / 60) : m < 60 ? `${m}m` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

const pad = (n: number) => String(n).padStart(2, '0');

/** The local calendar day of a date. */
export function localDay(d: Date = new Date()): string {
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The local "HH:MM" of a date. */
export function localTime(d: Date): string {
	return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** A local day and "HH:MM" as a Date. */
export function fromLocal(day: string, time = '00:00'): Date {
	const [y, mo, d] = day.split('-').map(Number);
	const [h, mi] = time.split(':').map(Number);
	return new Date(y, mo - 1, d, h || 0, mi || 0);
}

/** Calendar arithmetic on `YYYY-MM-DD` (time-zone free). */
export function addDays(day: string, n: number): string {
	const [y, m, d] = day.split('-').map(Number);
	const t = new Date(Date.UTC(y, m - 1, d + n));
	return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`;
}

/** The Monday on or before `day`. */
export function mondayOf(day: string): string {
	const [y, m, d] = day.split('-').map(Number);
	const wd = (new Date(Date.UTC(y, m - 1, d)).getUTCDay() + 6) % 7;
	return addDays(day, -wd);
}

/** Days between two `YYYY-MM-DD`s. */
export function daysBetween(a: string, b: string): number {
	const t = (s: string) => {
		const [y, m, d] = s.split('-').map(Number);
		return Date.UTC(y, m - 1, d);
	};
	return Math.round((t(b) - t(a)) / 86400000);
}

/** "Mon 9 Nov" for a `YYYY-MM-DD`. */
export function dayLabel(day: string, opts: Intl.DateTimeFormatOptions = { weekday: 'short', day: 'numeric', month: 'short' }): string {
	return fromLocal(day).toLocaleDateString(undefined, opts);
}

/** "9 – 15 Nov 2026" for the week starting `monday`. */
export function weekLabel(monday: string): string {
	const a = fromLocal(monday);
	const b = fromLocal(addDays(monday, 6));
	const sameMonth = a.getMonth() === b.getMonth();
	const left = a.toLocaleDateString(undefined, sameMonth ? { day: 'numeric' } : { day: 'numeric', month: 'short' });
	return `${left} – ${b.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}`;
}

/** "14:05" in the browser's zone. */
export function timeOf(iso: string): string {
	return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** A `YYYY-MM-DD` as "12 Nov 2026". */
export function dateText(day: string | null | undefined): string {
	return day ? dayLabel(day, { day: 'numeric', month: 'short', year: 'numeric' }) : '–';
}
