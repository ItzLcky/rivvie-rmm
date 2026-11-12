<script lang="ts">
	import { ChevronDown, LifeBuoy, Plus, Search, UserCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { inBatches, paged } from '#lib/paged.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { categories, priorities, ticketCounts, ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { can, session } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { StatusCategory, Ticket, TicketMeta } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import NewTicket from '#lib/components/ticket/NewTicket.svelte';
	import TicketTable from '#lib/components/ticket/TicketTable.svelte';

	const sort = sortState('updated', 'desc');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const scoped = $derived(currentClient());
	const allClients = $derived(session.user?.client_ids === null);
	let meta = $state<TicketMeta | null>(null);
	$effect(() => {
		ticketMeta().then((m) => (meta = m));
	});
	const views = $derived([
		{ value: 'open', label: 'Open', count: !scoped && ticketCounts.loaded ? num(ticketCounts.open) : undefined },
		{ value: 'mine', label: 'Mine', count: !scoped && ticketCounts.loaded && ticketCounts.mine ? num(ticketCounts.mine) : undefined, hidden: !can('technician') },
		{ value: 'unassigned', label: 'Unassigned', count: !scoped && ticketCounts.loaded && ticketCounts.unassigned ? num(ticketCounts.unassigned) : undefined },
		{ value: 'waiting', label: 'Waiting' },
		{ value: 'team', label: 'My teams', count: !scoped && ticketCounts.team ? num(ticketCounts.team) : undefined, hidden: !meta?.teams?.some((t) => t.member_ids.includes(session.user?.id ?? '')) },
		{ value: 'breached', label: 'SLA missed', count: !scoped && ticketCounts.breached ? num(ticketCounts.breached) : undefined },
		{ value: 'due_soon', label: 'Due soon' },
		{ value: 'triage', label: 'Triage', count: ticketCounts.triage ? num(ticketCounts.triage) : undefined, hidden: !allClients || !!scoped },
		{ value: 'done', label: 'Resolved & closed' },
		{ value: 'all', label: 'All' }
	]);
	const view = $derived(views.some((v) => v.value === param('view')) ? param('view') : 'open');
	const board = $derived(param('board'));
	const priority = $derived(param('priority'));
	const assignee = $derived(param('assignee'));
	const team = $derived(param('team'));


	const list = paged<Ticket>(() =>
		`/tickets${qs({ view, board_id: board, priority, assignee, team, client_id: clientId(), q: param('q'), sort: sort.key, dir: sort.dir })}`
	);
	liveReload(() => list.reload(), (e) => e.type === 'ticket', { debounceMs: 1000 });

	let creating = $state(false);
	let selected = $state(new Set<string>());
	const filtered = $derived(!!(param('q') || board || priority || assignee || team));

	async function applyBulk(patch: { status_category?: StatusCategory; priority?: number; assignee_id?: string | null }, done: string) {
		const ids = [...selected];
		// The bulk endpoint takes 500 at a time.
		if (await attempt(() => inBatches(ids, 500, (slice) => api.post('/tickets/bulk', { ids: slice, ...patch })), done)) {
			selected = new Set();
			list.reload();
		}
	}
</script>

<PageHeader
	title="Tickets"
	count={list.data ? `${list.data.total}${list.data.total_exact ? '' : '+'}` : null}
	description={scoped ? `${scoped.name}'s tickets.` : 'Requests from clients by email and the dashboard, and tickets opened by alert policies.'}
>
	{#snippet actions()}{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (creating = true)}>New ticket</Button>{/if}{/snippet}
</PageHeader>

<Tabs label="Views" class="mb-3" value={view} onchange={(v) => setParams({ view: v === 'open' ? null : v })} items={views} />

{#if list.error && !list.data}
	<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
{:else}
	<TicketTable
		id="tickets"
		caption="Tickets"
		{list}
		{sort}
		hide={scoped ? ['client'] : []}
		bind:selected={() => (can('technician') ? selected : undefined), (v) => (selected = v ?? new Set())}
		matching={list.data ? { total: list.data.total, exact: list.data.total_exact, select: async () => (await list.all()).map((t) => t.id) } : undefined}
		activeFilters={(board ? 1 : 0) + (priority ? 1 : 0) + (assignee ? 1 : 0) + (team ? 1 : 0)}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Number, subject or text…" aria-label="Search tickets" class="min-w-0 flex-1 sm:w-72 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Select aria-label="Board" class="w-full sm:w-auto" value={board} onchange={(e) => setParams({ board: e.currentTarget.value })} options={[{ value: '', label: 'Any board' }, ...(meta?.boards ?? []).map((b) => ({ value: b.id, label: b.name }))]} />
			<Select aria-label="Priority" class="w-full sm:w-auto" value={priority} onchange={(e) => setParams({ priority: e.currentTarget.value })} options={[{ value: '', label: 'Any priority' }, ...priorities.map((p) => ({ value: String(p.value), label: p.label }))]} />
			{#if meta?.teams?.length && view !== 'team'}
				<Select
					aria-label="Team"
					class="w-full sm:w-auto"
					value={team}
					onchange={(e) => setParams({ team: e.currentTarget.value })}
					options={[{ value: '', label: 'Any team' }, { value: 'none', label: 'No team' }, ...meta.teams.map((t) => ({ value: t.id, label: t.name }))]}
				/>
			{/if}
			{#if view !== 'mine' && view !== 'unassigned'}
				<Select
					aria-label="Assignee"
					class="w-full sm:w-auto"
					value={assignee}
					onchange={(e) => setParams({ assignee: e.currentTarget.value })}
					options={[{ value: '', label: 'Anyone' }, { value: 'none', label: 'Unassigned' }, ...(meta?.technicians ?? []).map((t) => ({ value: t.id, label: t.name }))]}
				/>
			{/if}
		{/snippet}
		{#snippet bulk(n)}
			<Button size="sm" icon={UserCheck} onclick={() => applyBulk({ assignee_id: session.user!.id }, `Assigned ${n} to you.`)}>Assign to me</Button>
			<Menu label="Set status" align="start" items={categories.map((c) => ({ label: c.label, onSelect: () => applyBulk({ status_category: c.value }, `Moved ${n} to ${c.label}.`) }))}>
				{#snippet trigger(props)}<Button {...props} size="sm" iconRight={ChevronDown}>Set status</Button>{/snippet}
			</Menu>
			<Menu label="Set priority" align="start" items={priorities.map((p) => ({ label: p.label, onSelect: () => applyBulk({ priority: p.value }, `Set ${n} to ${p.short}.`) }))}>
				{#snippet trigger(props)}<Button {...props} size="sm" iconRight={ChevronDown}>Set priority</Button>{/snippet}
			</Menu>
		{/snippet}
		{#snippet empty()}
			{#if filtered || view !== 'open'}
				<EmptyState compact title="No tickets match" />
			{:else}
				<EmptyState icon={LifeBuoy} title="No open tickets" description="Open one here, set up a support mailbox under Company settings → Service desk, or let an alert policy file tickets.">
					{#snippet action()}{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (creating = true)}>New ticket</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</TicketTable>
{/if}

{#if creating}<NewTicket onclose={() => (creating = false)} initial={{ clientId: clientId() || undefined }} />{/if}
