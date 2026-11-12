/** Lookups shared by the work pages: work types, products, ticket search, labels. */
import { api, qs } from '#lib/api.js';
import type { Tone } from '#lib/ui/Badge.svelte';
import type { Page } from '#lib/types.js';
import type { Product, ProjectStatus, TaskStatus, TicketRef, WeekStatus, WorkType } from './types';

let types: Promise<WorkType[]> | null = null;
/** Every work type (cached; pass true after a change). */
export function workTypes(fresh = false): Promise<WorkType[]> {
	if (fresh || !types) {
		types = api.get<WorkType[]>('/work-types');
		types.catch(() => (types = null));
	}
	return types;
}

let products: Promise<Product[]> | null = null;
export function productCatalog(fresh = false): Promise<Product[]> {
	if (fresh || !products) {
		products = api.get<Product[]>('/products');
		products.catch(() => (products = null));
	}
	return products;
}

/** Tickets matching a number or words (any status). */
export async function searchTickets(q: string, limit = 8): Promise<TicketRef[]> {
	const p = await api.get<Page<TicketRef>>(`/tickets${qs({ view: 'all', q: q.trim(), limit: String(limit) })}`);
	return p.items;
}

export const weekStatus: Record<WeekStatus, { label: string; tone: Tone }> = {
	open: { label: 'Open', tone: 'neutral' },
	submitted: { label: 'Submitted', tone: 'info' },
	approved: { label: 'Approved', tone: 'success' },
	rejected: { label: 'Rejected', tone: 'danger' }
};

export const projectStatuses: { value: ProjectStatus; label: string; tone: Tone }[] = [
	{ value: 'planned', label: 'Planned', tone: 'neutral' },
	{ value: 'active', label: 'Active', tone: 'accent' },
	{ value: 'on_hold', label: 'On hold', tone: 'warning' },
	{ value: 'done', label: 'Done', tone: 'success' },
	{ value: 'cancelled', label: 'Cancelled', tone: 'neutral' }
];
export const projectStatus = (s: ProjectStatus) => projectStatuses.find((x) => x.value === s) ?? projectStatuses[0];

export const taskStatuses: { value: TaskStatus; label: string; tone: Tone }[] = [
	{ value: 'todo', label: 'To do', tone: 'neutral' },
	{ value: 'doing', label: 'Doing', tone: 'info' },
	{ value: 'done', label: 'Done', tone: 'success' }
];
export const taskStatus = (s: TaskStatus) => taskStatuses.find((x) => x.value === s) ?? taskStatuses[0];

/** What an entry was for, as one line. */
export function entryTarget(e: { ticket_number: number | null; ticket_subject: string | null; project_name: string | null; client_name: string | null }): string {
	if (e.ticket_number != null) return `T-${e.ticket_number} ${e.ticket_subject ?? ''}`.trim();
	if (e.project_name) return e.project_name;
	return e.client_name ?? 'Internal';
}
