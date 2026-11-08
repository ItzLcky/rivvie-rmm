export function bytes(n: number | null | undefined, digits = 1): string {
	if (n == null || !isFinite(n)) return '–';
	const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
	let i = 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return `${n.toFixed(i === 0 ? 0 : digits)} ${units[i]}`;
}

export function pct(used: number, total: number): number {
	return total > 0 ? (100 * used) / total : 0;
}

export function ago(iso: string | null | undefined): string {
	if (!iso) return 'never';
	const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
	if (s < 5) return 'just now';
	if (s < 60) return `${s}s ago`;
	if (s < 3600) return `${Math.floor(s / 60)}m ago`;
	if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
	return `${Math.floor(s / 86400)}d ago`;
}

export function duration(secs: number): string {
	const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
	return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export function datetime(iso: string | null | undefined): string {
	return iso ? new Date(iso).toLocaleString() : '–';
}

export function maxDiskPct(m: { disks: { total: number; available: number }[] } | null): number {
	if (!m) return 0;
	return Math.max(0, ...m.disks.filter((d) => d.total > 0).map((d) => pct(d.total - d.available, d.total)));
}

export const interpreters = [
	{ value: 'bash', label: 'Bash', os: 'linux' },
	{ value: 'sh', label: 'POSIX sh', os: 'linux' },
	{ value: 'powershell', label: 'PowerShell', os: 'windows' },
	{ value: 'cmd', label: 'cmd.exe', os: 'windows' },
	{ value: 'python', label: 'Python', os: 'any' }
] as const;

const nf = new Intl.NumberFormat();
export function num(n: number | null | undefined): string {
	return n == null ? '–' : nf.format(n);
}

export function plural(n: number, one: string, many = `${one}s`): string {
	return `${num(n)} ${n === 1 ? one : many}`;
}

/** Milliseconds as "820 ms", "4.2 s", "3m 10s". */
export function ms(v: number | null | undefined): string {
	if (v == null) return '–';
	if (v < 1000) return `${v} ms`;
	if (v < 60000) return `${(v / 1000).toFixed(1)} s`;
	const s = Math.round(v / 1000);
	return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export const osLabels: Record<string, string> = { linux: 'Linux', windows: 'Windows', macos: 'macOS', other: 'Other' };

export function interpreterLabel(v: string): string {
	return interpreters.find((i) => i.value === v)?.label ?? v;
}

/** Joins class names, skipping falsy ones. */
export function cx(...c: (string | false | null | undefined)[]): string {
	return c.filter(Boolean).join(' ');
}
