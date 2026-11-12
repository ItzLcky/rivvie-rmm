/**
 * Money is integer minor units with an ISO currency; quantities are thousandths
 * (`quantity_milli`: 1500 = 1.5). Nothing here ever does arithmetic on floats that ends up
 * stored: text is parsed digit by digit.
 */

const ZERO = new Set(['JPY', 'KRW', 'ISK', 'CLP', 'VND']);
const THREE = new Set(['BHD', 'KWD', 'OMR', 'JOD', 'TND']);

/** Digits after the decimal point for a currency (matches the server). */
export function minorDigits(currency: string): number {
	const c = currency.toUpperCase();
	return ZERO.has(c) ? 0 : THREE.has(c) ? 3 : 2;
}

const formatters = new Map<string, Intl.NumberFormat>();
function formatter(currency: string): Intl.NumberFormat | null {
	const c = currency.toUpperCase();
	let f = formatters.get(c);
	if (!f) {
		const d = minorDigits(c);
		try {
			f = new Intl.NumberFormat(undefined, { style: 'currency', currency: c, minimumFractionDigits: d, maximumFractionDigits: d });
		} catch {
			return null;
		}
		formatters.set(c, f);
	}
	return f;
}

/** `formatMoney(123456, 'USD')` → "$1,234.56" (in the browser's locale). */
export function formatMoney(minor: number | null | undefined, currency: string): string {
	if (minor === null || minor === undefined) return '–';
	const d = minorDigits(currency);
	const value = minor / 10 ** d;
	const f = formatter(currency);
	return f ? f.format(value) : `${currency} ${value.toFixed(d)}`;
}

/** Minor units as plain editable text: 123456 USD → "1234.56", 1500 JPY → "1500". */
export function moneyText(minor: number | null | undefined, currency: string): string {
	if (minor === null || minor === undefined) return '';
	const d = minorDigits(currency);
	const neg = minor < 0;
	const abs = Math.abs(Math.trunc(minor));
	const scale = 10 ** d;
	const whole = Math.floor(abs / scale);
	const frac = abs % scale;
	return `${neg ? '-' : ''}${whole}${d ? `.${String(frac).padStart(d, '0')}` : ''}`;
}

/**
 * Parses what someone typed ("1,234.50", "$12", "-3.5", "12,50" with a decimal comma) to minor
 * units, or null when it isn't a number. Extra decimals beyond the currency's are rounded half
 * away from zero.
 */
export function parseMoney(text: string, currency: string): number | null {
	const d = minorDigits(currency);
	const n = parseDecimal(text);
	if (!n) return null;
	return scaleDecimal(n, d);
}

/** Like parseMoney, but empty text is null and anything else must parse (else NaN). */
export function parseOptionalMoney(text: string, currency: string): number | null {
	return text.trim() === '' ? null : (parseMoney(text, currency) ?? NaN);
}

interface Decimal {
	neg: boolean;
	int: string;
	frac: string;
}

function parseDecimal(text: string): Decimal | null {
	let s = text.trim().replace(/[\s ']/g, '');
	let neg = false;
	if (/^\(.*\)$/.test(s)) {
		neg = true;
		s = s.slice(1, -1);
	}
	s = s.replace(/^[^\d.,+-]+|[^\d.,]+$/g, '');
	if (s.startsWith('-')) {
		neg = !neg;
		s = s.slice(1);
	} else if (s.startsWith('+')) s = s.slice(1);
	s = s.replace(/^[^\d.,]+/, '');
	if (!s || !/^[\d.,]+$/.test(s)) return null;
	// The last separator is the decimal one if it's followed by other than exactly three digits,
	// or if both kinds appear; otherwise it groups thousands.
	const lastDot = s.lastIndexOf('.');
	const lastComma = s.lastIndexOf(',');
	let dec = -1;
	if (lastDot >= 0 && lastComma >= 0) dec = Math.max(lastDot, lastComma);
	else {
		const at = Math.max(lastDot, lastComma);
		if (at >= 0) {
			const sep = s[at];
			const count = s.split(sep).length - 1;
			const after = s.length - at - 1;
			dec = count === 1 && (after !== 3 || sep === '.') ? at : -1;
		}
	}
	const intPart = (dec >= 0 ? s.slice(0, dec) : s).replace(/[.,]/g, '');
	const fracPart = dec >= 0 ? s.slice(dec + 1) : '';
	if (/[.,]/.test(fracPart)) return null;
	if (!intPart && !fracPart) return null;
	return { neg, int: intPart || '0', frac: fracPart };
}

function scaleDecimal(n: Decimal, digits: number): number {
	const frac = n.frac.padEnd(digits + 1, '0');
	let v = Number(n.int) * 10 ** digits + Number(frac.slice(0, digits) || '0');
	if (Number(frac[digits]) >= 5) v += 1;
	if (!Number.isSafeInteger(v)) return NaN;
	return n.neg && v !== 0 ? -v : v;
}

/** 1500 → "1.5", 2000 → "2", -250 → "-0.25". */
export function formatQuantity(milli: number): string {
	const neg = milli < 0;
	const abs = Math.abs(Math.trunc(milli));
	const whole = Math.floor(abs / 1000);
	const frac = String(abs % 1000).padStart(3, '0').replace(/0+$/, '');
	return `${neg ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`;
}

/** "1.5" → 1500, "-2" → -2000; null when it isn't a number. */
export function parseQuantity(text: string): number | null {
	const n = parseDecimal(text);
	if (!n) return null;
	const v = scaleDecimal(n, 3);
	return Number.isNaN(v) ? null : v;
}

/** quantity × unit price, rounded half away from zero (as the server does). */
export function lineAmount(quantityMilli: number, unitPrice: number): number {
	const p = quantityMilli * unitPrice;
	return p >= 0 ? Math.floor((p + 500) / 1000) : -Math.floor((-p + 500) / 1000);
}

/** 90 → "1.5" (hours as editable text). */
export function minutesToHours(minutes: number | null | undefined): string {
	if (minutes === null || minutes === undefined) return '';
	return formatQuantity(Math.round((minutes * 1000) / 60));
}

/** "1.5" → 90; null when it isn't a number. Rounded to the minute. */
export function hoursToMinutes(text: string): number | null {
	const q = parseQuantity(text);
	return q === null ? null : Math.round((q * 60) / 1000);
}

/** 90 → "1.5 h", 45 → "45 min", -30 → "-30 min". */
export function formatHours(minutes: number | null | undefined): string {
	if (minutes === null || minutes === undefined) return '–';
	if (Math.abs(minutes) < 60) return `${minutes} min`;
	return `${formatQuantity(Math.round((minutes * 1000) / 60))} h`;
}
