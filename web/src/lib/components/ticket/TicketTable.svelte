<script lang="ts">
	import type { Snippet } from 'svelte';
	import { ago, datetime } from '#lib/format.js';
	import { ticketNumber } from '#lib/servicedesk/tickets.svelte.js';
	import type { Page, Ticket } from '#lib/types.js';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import PriorityBadge from './PriorityBadge.svelte';
	import TicketStatus from './TicketStatus.svelte';

	/** A paged ticket list: the Tickets page, and the Tickets tabs of clients, contacts and agents. */
	let {
		id,
		caption,
		list,
		sort,
		selected = $bindable(),
		hide = [],
		toolbar,
		filters,
		activeFilters = 0,
		bulk,
		empty
	}: {
		id: string;
		caption: string;
		list: {
			readonly data: Page<Ticket> | undefined;
			readonly rows: Ticket[];
			readonly loading: boolean;
			readonly busy: boolean;
			readonly pageSize: number;
			next(): void;
			prev(): void;
			first(): void;
			setPageSize(n: number): void;
		};
		sort: { key: string; dir: 'asc' | 'desc'; toggle: (key: string) => void };
		selected?: Set<string>;
		/** Columns that say the same thing on every row here (the client on a client's page). */
		hide?: ('client' | 'assignee')[];
		toolbar?: Snippet;
		filters?: Snippet;
		activeFilters?: number;
		bulk?: Snippet<[number]>;
		empty?: Snippet;
	} = $props();
</script>

{#snippet numberCell(t: Ticket)}<span class="text-muted font-mono text-xs whitespace-nowrap">{ticketNumber(t.number)}</span>{/snippet}
{#snippet subjectCell(t: Ticket)}
	<a class="hover:text-accent font-medium" href="/tickets/{t.id}">{t.subject}</a>
	<div class="text-muted max-w-lg truncate text-xs">
		{[
			...(hide.includes('client') ? [] : [t.client_name ?? 'Triage']),
			t.contact_name ?? (t.requester_name || t.requester_email),
			t.merged_into_number ? `merged into ${ticketNumber(t.merged_into_number)}` : ''
		]
			.filter(Boolean)
			.join(' · ')}<span class="sm:hidden">{` · ${ticketNumber(t.number)} · ${t.status_name}`}</span>
	</div>
{/snippet}
{#snippet priorityCell(t: Ticket)}<PriorityBadge priority={t.priority} />{/snippet}
{#snippet statusCell(t: Ticket)}<TicketStatus name={t.status_name} category={t.status_category} />{/snippet}
{#snippet boardCell(t: Ticket)}<span class="text-muted">{t.board_name}</span>{/snippet}
{#snippet assigneeCell(t: Ticket)}{#if t.assignee_name}{t.assignee_name}{:else}<span class="text-muted">Unassigned</span>{/if}{/snippet}
{#snippet updatedCell(t: Ticket)}<span class="text-muted whitespace-nowrap" title={datetime(t.updated_at)}>{ago(t.updated_at)}</span>{/snippet}
{#snippet createdCell(t: Ticket)}<span class="text-muted whitespace-nowrap" title={datetime(t.created_at)}>{ago(t.created_at)}</span>{/snippet}

<DataTable
	{id}
	{caption}
	rows={list.rows}
	key={(t) => t.id}
	loading={list.loading}
	busy={list.busy}
	{sort}
	bind:selected
	rowHref={(t) => `/tickets/${t.id}`}
	rowClass={(t) => (t.merged_into ? 'opacity-60' : '')}
	{toolbar}
	{filters}
	{activeFilters}
	{bulk}
	{empty}
	columns={[
		{ id: 'number', label: 'No.', sort: 'number', cell: numberCell, class: 'w-24', from: 'sm' },
		{ id: 'subject', label: 'Subject', sort: 'subject', cell: subjectCell, hideable: false },
		{ id: 'priority', label: 'Priority', sort: 'priority', cell: priorityCell, class: 'w-20' },
		{ id: 'status', label: 'Status', sort: 'status', cell: statusCell, from: 'sm' },
		{ id: 'board', label: 'Board', cell: boardCell, from: 'xl', defaultHidden: true },
		...(hide.includes('assignee') ? [] : [{ id: 'assignee', label: 'Assignee', sort: 'assignee', cell: assigneeCell, from: 'md' } as Column<Ticket>]),
		{ id: 'created', label: 'Opened', sort: 'created', cell: createdCell, from: 'lg', defaultHidden: true },
		{ id: 'updated', label: 'Updated', sort: 'updated', cell: updatedCell, from: 'sm' }
	] satisfies Column<Ticket>[]}
>
	{#snippet footer()}
		{#if list.data && (list.data.next || list.data.prev || list.data.total > list.rows.length)}
			<Pagination
				shown={list.rows.length}
				total={list.data.total}
				exact={list.data.total_exact}
				hasPrev={!!list.data.prev}
				hasNext={!!list.data.next}
				pageSize={list.pageSize}
				onprev={list.prev}
				onnext={list.next}
				onfirst={list.first}
				onpagesize={list.setPageSize}
			/>
		{/if}
	{/snippet}
</DataTable>
