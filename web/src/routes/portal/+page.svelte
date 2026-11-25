<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ChevronRight, Plus, Search, Ticket } from '@lucide/svelte';
	import { ago, datetime } from '#lib/format.js';
	import { portal, qs } from '#lib/portal/api.js';
	import { ticketNumber } from '#lib/portal/format.js';
	import { me } from '#lib/portal/me.svelte.js';
	import StatusBadge from '#lib/portal/StatusBadge.svelte';
	import type { PortalTicket } from '#lib/portal/types.js';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	type Filter = 'open' | 'closed' | 'all';
	const states: { value: Filter; label: string }[] = [
		{ value: 'open', label: 'Open' },
		{ value: 'closed', label: 'Closed' },
		{ value: 'all', label: 'All' }
	];

	const filter = $derived<Filter>((['open', 'closed', 'all'] as const).find((s) => s === page.url.searchParams.get('state')) ?? 'open');
	const q = $derived(page.url.searchParams.get('q') ?? '');
	let search = $state(page.url.searchParams.get('q') ?? '');

	let tickets = $state<PortalTicket[] | null>(null);
	let error = $state('');
	let seq = 0;

	async function load() {
		const n = ++seq;
		error = '';
		try {
			const rows = await portal.get<PortalTicket[]>(`/tickets${qs({ state: filter, q })}`);
			if (n === seq) tickets = rows;
		} catch (e) {
			if (n === seq) error = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		void filter;
		void q;
		tickets = null;
		load();
	});

	function setParams(next: { state?: Filter; q?: string }) {
		const s = next.state ?? filter;
		const query = next.q ?? q;
		goto(`/portal${qs({ state: s === 'open' ? undefined : s, q: query.trim() || undefined })}`, { replace: true, reset: false });
	}

	let timer: ReturnType<typeof setTimeout> | undefined;
	function oninput() {
		clearTimeout(timer);
		timer = setTimeout(() => setParams({ q: search }), 300);
	}
</script>

<div class="space-y-6">
	<div class="flex flex-wrap items-end justify-between gap-4">
		<div class="min-w-0">
			<h1 class="text-2xl font-medium">Your requests</h1>
			<p class="text-muted mt-1 text-sm">
				{me.data?.sees_all_tickets ? `Support requests for ${me.data.contact.client_name}.` : 'Your support requests.'}
				{#if me.data?.welcome}<span class="block whitespace-pre-line">{me.data.welcome}</span>{/if}
			</p>
		</div>
		<Button variant="primary" href="/portal/tickets/new" icon={Plus}>New request</Button>
	</div>

	<section class="card" aria-labelledby="tickets-h">
		<h2 id="tickets-h" class="sr-only">Requests</h2>
		<div class="border-border flex flex-wrap items-center gap-3 border-b px-4 py-3">
			<Segmented label="Show" size="md" value={filter} options={states} onchange={(v) => setParams({ state: v })} />
			<form class="ml-auto w-full sm:w-72" role="search" onsubmit={(e) => (e.preventDefault(), clearTimeout(timer), setParams({ q: search }))}>
				<label for="ticket-search" class="sr-only">Search requests</label>
				<Input id="ticket-search" type="search" icon={Search} placeholder="Search by subject or number" bind:value={search} {oninput} />
			</form>
		</div>

		{#if error}
			<ErrorState {error} onretry={load} />
		{:else if !tickets}
			<div class="p-4"><Skeleton lines={5} /></div>
		{:else if !tickets.length}
			<EmptyState
				icon={Ticket}
				title={q ? 'No matching requests' : filter === 'open' ? 'No open requests' : filter === 'closed' ? 'No closed requests' : 'No requests yet'}
				description={q ? 'Try a different search.' : filter === 'open' ? 'Need help with something? Send us a new request.' : undefined}
			>
				{#snippet action()}
					{#if !q && filter === 'open'}<Button href="/portal/tickets/new" icon={Plus}>New request</Button>{/if}
				{/snippet}
			</EmptyState>
		{:else}
			<ul class="divide-border divide-y">
				{#each tickets as t (t.id)}
					<li>
						<a href="/portal/tickets/{t.id}" class="hover:bg-hover focus-visible:bg-hover group flex items-center gap-3 px-4 py-3 focus-visible:outline-none">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-x-2 gap-y-1">
									<span class="text-muted font-mono text-xs">{ticketNumber(t.number)}</span>
									<span class="min-w-0 font-medium break-words group-focus-visible:underline">{t.subject}</span>
								</div>
								<div class="text-muted mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
									<StatusBadge category={t.status_category} />
									<span>Updated <time datetime={t.last_activity_at} title={datetime(t.last_activity_at)}>{ago(t.last_activity_at)}</time></span>
									{#if me.data?.sees_all_tickets && t.contact_name}<span>From {t.contact_name}</span>{/if}
								</div>
							</div>
							<ChevronRight class="text-subtle size-4 shrink-0" aria-hidden="true" />
						</a>
					</li>
				{/each}
			</ul>
		{/if}
	</section>
</div>
