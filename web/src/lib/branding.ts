/**
 * White-labelling (docs/design/branding.md). The server resolves the branding (a client's own
 * over the instance's over the built-in look) and derives the accent palette for both themes;
 * this applies it as the `--brand-light-*` / `--brand-dark-*` custom properties that
 * layout.css falls back from, and caches it for static/theme.js to apply before first paint.
 */

export type Palette = {
	accent: string;
	accent_hover: string;
	accent_soft: string;
	on_accent: string;
	accent_ink: string;
	cta: string;
	cta_hover: string;
	on_cta: string;
	focus: string;
	nav_indicator: string;
};

export type Branding = {
	/** The configured product name, if any. */
	product_name: string | null;
	/** What to call the product: the product name, else "<company> RMM", else "RMM". */
	name: string;
	logo_light: string | null;
	logo_dark: string | null;
	icon: string | null;
	accent: string | null;
	theme: { light: Palette; dark: Palette } | null;
	support: { email: string | null; phone: string | null; url: string | null; hours: string | null };
	/** The AGPL source offer: always shown, whatever the branding. */
	source_url: string;
};

/** Where the source is offered when the server says nothing (an older server). */
export const DEFAULT_SOURCE_URL = 'https://github.com/ItzLcky/rivvie-rmm';

const KEY = 'rmm.brand';
const TOKENS: (keyof Palette)[] = ['accent', 'accent_hover', 'accent_soft', 'on_accent', 'accent_ink', 'cta', 'cta_hover', 'on_cta', 'focus', 'nav_indicator'];

/** The custom properties for a theme, e.g. `--brand-dark-accent-hover`. */
export function themeVars(theme: Branding['theme']): Record<string, string> {
	const out: Record<string, string> = {};
	if (!theme) return out;
	for (const mode of ['light', 'dark'] as const) {
		for (const t of TOKENS) out[`--brand-${mode}-${t.replaceAll('_', '-')}`] = theme[mode][t];
	}
	return out;
}

/** Sets (or clears) the accent palette on <html> and remembers it for the next page load. */
export function applyBranding(b: Branding | null | undefined) {
	if (typeof document === 'undefined') return;
	const style = document.documentElement.style;
	for (const mode of ['light', 'dark']) for (const t of TOKENS) style.removeProperty(`--brand-${mode}-${t.replaceAll('_', '-')}`);
	const vars = themeVars(b?.theme ?? null);
	for (const [k, v] of Object.entries(vars)) style.setProperty(k, v);
	try {
		if (Object.keys(vars).length) localStorage.setItem(KEY, JSON.stringify(vars));
		else localStorage.removeItem(KEY);
	} catch {
		/* storage blocked: applied for this page only */
	}
}

/** "tel:" link target: digits and a leading +. */
export function telHref(phone: string): string {
	return `tel:${phone.replace(/[^\d+]/g, '')}`;
}
