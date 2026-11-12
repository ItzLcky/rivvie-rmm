import type { Tone } from '#lib/ui/Badge.svelte';
import type { StatusCategory } from './types';

export const ticketNumber = (n: number) => `T-${n}`;

/** Status categories as the client sees them. */
export const statusLabels: Record<StatusCategory, string> = {
	new: 'Received',
	open: 'In progress',
	waiting_client: 'Waiting for you',
	waiting_vendor: 'Waiting on a supplier',
	resolved: 'Resolved',
	closed: 'Closed'
};

export const statusTones: Record<StatusCategory, Tone> = {
	new: 'info',
	open: 'accent',
	waiting_client: 'warning',
	waiting_vendor: 'neutral',
	resolved: 'success',
	closed: 'neutral'
};

export const statusLabel = (c: string) => statusLabels[c as StatusCategory] ?? c;
export const statusTone = (c: string): Tone => statusTones[c as StatusCategory] ?? 'neutral';
export const isDone = (c: string) => c === 'resolved' || c === 'closed';

export type Urgency = 'low' | 'normal' | 'high';
export const urgencies: { value: Urgency; label: string }[] = [
	{ value: 'low', label: 'Low: whenever you get to it' },
	{ value: 'normal', label: 'Normal' },
	{ value: 'high', label: 'High: it stops me working' }
];

/** Builds the multipart body for a new request or a reply. */
export function formWith(fields: Record<string, string>, files: File[]): FormData {
	const f = new FormData();
	for (const [k, v] of Object.entries(fields)) f.append(k, v);
	for (const file of files) f.append('file', file, file.name);
	return f;
}
