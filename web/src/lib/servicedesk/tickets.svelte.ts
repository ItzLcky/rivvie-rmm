/** Service desk shared state and labels: the sidebar's ticket counts, form data, and how statuses and priorities read. */
import { api } from '#lib/api.js';
import { liveReload } from '#lib/live.svelte.js';
import type { Tone } from '#lib/ui/Badge.svelte';
import type { Priority, StatusCategory, TicketMeta, TicketSummary } from '#lib/types.js';

export const priorities: { value: Priority; label: string; short: string; tone: Tone }[] = [
	{ value: 1, label: 'P1 · Critical', short: 'P1', tone: 'danger' },
	{ value: 2, label: 'P2 · High', short: 'P2', tone: 'warning' },
	{ value: 3, label: 'P3 · Medium', short: 'P3', tone: 'neutral' },
	{ value: 4, label: 'P4 · Low', short: 'P4', tone: 'neutral' }
];
export const priorityOf = (p: Priority) => priorities[p - 1] ?? priorities[2];

/** Impact and urgency: 1 high … 3 low. */
export const levels = [
	{ value: 1, label: 'High' },
	{ value: 2, label: 'Medium' },
	{ value: 3, label: 'Low' }
] as const;

/** Same matrix as the server: P1 only when impact and urgency are both high. */
export function matrixPriority(impact: number, urgency: number): Priority {
	const s = impact + urgency;
	return (s <= 2 ? 1 : s === 3 ? 2 : s === 4 ? 3 : 4) as Priority;
}

export const categories: { value: StatusCategory; label: string; tone: Tone; hint: string }[] = [
	{ value: 'new', label: 'New', tone: 'info', hint: 'Not looked at yet. New tickets start in the first status of this kind.' },
	{ value: 'open', label: 'Open', tone: 'accent', hint: 'Being worked on. Client replies to waiting or resolved tickets move them here.' },
	{ value: 'waiting_client', label: 'Waiting on client', tone: 'warning', hint: 'Paused until the client answers (the SLA clock will pause here).' },
	{ value: 'waiting_vendor', label: 'Waiting on vendor', tone: 'warning', hint: 'Blocked on a third party.' },
	{ value: 'resolved', label: 'Resolved', tone: 'success', hint: 'Done; a reply reopens it. Closed automatically after a few days.' },
	{ value: 'closed', label: 'Closed', tone: 'neutral', hint: 'Finished for good; a reply opens a new ticket.' }
];
export const categoryOf = (c: StatusCategory) => categories.find((x) => x.value === c) ?? categories[1];

export const sourceLabels: Record<string, string> = { dashboard: 'Dashboard', email: 'Email', alert: 'Alert', portal: 'Portal', api: 'API', agent: 'From device' };

export const ticketNumber = (n: number) => `T-${n}`;

/** Open ticket counts for the sidebar and the list's tabs, kept fresh by live ticket events. */
export const ticketCounts = $state<TicketSummary & { loaded: boolean }>({ open: 0, mine: 0, unassigned: 0, triage: 0, waiting: 0, team: 0, breached: 0, loaded: false });

async function loadCounts() {
	try {
		Object.assign(ticketCounts, await api.get<TicketSummary>('/tickets/summary'), { loaded: true });
	} catch {
		/* keep the last counts */
	}
}

/** Call once during the root layout's init. */
export function trackTickets(active: () => boolean) {
	$effect(() => {
		if (active()) loadCounts();
	});
	liveReload(() => active() && loadCounts(), (e) => e.type === 'ticket', { debounceMs: 1500, pollMs: 60000 });
}

let metaPromise: Promise<TicketMeta> | null = null;
/** Boards, types and technicians; cached until `fresh` (after editing boards). */
export function ticketMeta(fresh = false): Promise<TicketMeta> {
	if (fresh || !metaPromise) {
		metaPromise = api.get<TicketMeta>('/tickets/meta');
		metaPromise.catch(() => (metaPromise = null));
	}
	return metaPromise;
}
