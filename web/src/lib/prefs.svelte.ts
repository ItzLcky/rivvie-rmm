import { api } from './api';

export type Theme = 'system' | 'light' | 'dark';
export type Density = 'compact' | 'comfortable';

/** Per-user UI preferences, stored server-side (`/auth/preferences`) so they follow the user. */
export interface Prefs {
	theme?: Theme;
	density?: Density;
	/** Hidden column ids per table. */
	columns?: Record<string, string[]>;
	pageSize?: number;
	sidebarCollapsed?: boolean;
	terminalFontSize?: number;
}

export const prefs = $state<Prefs>({});

const media = typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)') : null;

/** Applies theme and density to <html>, and mirrors them for static/theme.js's next first paint. */
function apply() {
	const d = document.documentElement;
	const theme = prefs.theme ?? 'system';
	d.dataset.theme = theme === 'dark' || (theme === 'system' && media?.matches) ? 'dark' : 'light';
	d.dataset.density = prefs.density ?? 'compact';
	try {
		localStorage.setItem('rmm.theme', theme);
		localStorage.setItem('rmm.density', prefs.density ?? 'compact');
	} catch {
		/* storage blocked */
	}
}
media?.addEventListener('change', () => apply());

/** Called with the preferences from `/auth/me`. */
export function loadPrefs(p: Prefs | undefined) {
	for (const k of Object.keys(prefs)) delete prefs[k as keyof Prefs];
	Object.assign(prefs, p ?? {});
	// Before sign-in (or with no saved theme) keep whatever theme.js picked from localStorage.
	if (!p?.theme) {
		try {
			const t = localStorage.getItem('rmm.theme') as Theme | null;
			if (t) prefs.theme = t;
		} catch {
			/* ignore */
		}
	}
	apply();
}

let pending: Partial<Prefs> = {};
let timer: ReturnType<typeof setTimeout> | undefined;

/** Updates one preference now and saves it shortly after (batched). */
export function setPref<K extends keyof Prefs>(key: K, value: Prefs[K]) {
	prefs[key] = value;
	pending[key] = value ?? (null as never);
	apply();
	clearTimeout(timer);
	timer = setTimeout(() => {
		const patch = pending;
		pending = {};
		api.put('/auth/preferences', patch).catch(() => {
			/* not signed in yet, or offline: the local value still applies this session */
		});
	}, 600);
}

export function resolvedTheme(): 'light' | 'dark' {
	return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}
