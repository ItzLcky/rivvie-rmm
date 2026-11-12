/** How SLA deadlines read in lists and on the ticket page. */
import type { Tone } from '#lib/ui/Badge.svelte';
import type { SlaTarget, Ticket } from '#lib/types.js';

export const targetLabels: Record<SlaTarget, string> = { respond: 'First response', update: 'Next update', resolve: 'Resolution' };

/** 90 → "1 h 30 min", 2880 → "2 d". */
export function minutes(m: number | null | undefined): string {
	if (!m) return '–';
	if (m % 1440 === 0) return `${m / 1440} d`;
	if (m < 60) return `${m} min`;
	const h = Math.floor(m / 60);
	return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
}

/** "in 25 min", "3 h ago". */
export function until(iso: string, now = Date.now()): string {
	const diff = Math.round((new Date(iso).getTime() - now) / 60000);
	const abs = Math.abs(diff);
	const text = abs < 60 ? `${abs} min` : abs < 2880 ? `${Math.round(abs / 60)} h` : `${Math.round(abs / 1440)} d`;
	return diff >= 0 ? `in ${text}` : `${text} ago`;
}

export interface SlaState {
	label: string;
	tone: Tone;
	/** For a tooltip. */
	title: string;
}

/** The ticket's SLA at a glance, or null when no target applies. */
export function slaState(t: Pick<Ticket, 'sla_due' | 'sla_paused' | 'sla_breached' | 'sla_policy_id' | 'status_category'>, now = Date.now()): SlaState | null {
	if (!t.sla_policy_id) return null;
	if (t.sla_paused && t.status_category === 'waiting_client') return { label: 'Paused', tone: 'neutral', title: 'Waiting on the client: the SLA clock is stopped.' };
	if (!t.sla_due) return t.sla_breached.length ? { label: 'Missed', tone: 'danger', title: `Missed: ${t.sla_breached.map((k) => targetLabels[k]).join(', ')}` } : null;
	const left = new Date(t.sla_due).getTime() - now;
	if (left < 0) return { label: `Overdue ${until(t.sla_due, now).replace(' ago', '')}`, tone: 'danger', title: `Was due ${new Date(t.sla_due).toLocaleString()}` };
	return {
		label: `Due ${until(t.sla_due, now)}`,
		tone: left < 3600_000 ? 'warning' : t.sla_breached.length ? 'danger' : 'neutral',
		title: `Next deadline ${new Date(t.sla_due).toLocaleString()}${t.sla_breached.length ? ` · missed: ${t.sla_breached.map((k) => targetLabels[k]).join(', ')}` : ''}`
	};
}
