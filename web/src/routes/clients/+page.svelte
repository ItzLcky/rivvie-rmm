<script lang="ts">
	import { goto } from '$app/navigation';
	import { Building2, Plus, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, num, pct } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Client, ClientHealth, Dashboard } from '#lib/types.js';
	import { param, setParams, sortState } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';

	type Row = Client & { health?: ClientHealth; agents: number; online: number };
	const res = resource(async () => {
		const [clients, dash] = await Promise.all([api.get<Client[]>('/clients'), api.get<Dashboard>('/dashboard')]);
		return clients.map((c): Row => {
			const health = dash.client_health.find((h) => h.id === c.id);
			return { ...c, health, agents: c.sites.reduce((n, s) => n + s.agent_count, 0), online: c.sites.reduce((n, s) => n + s.online_count, 0) };
		});
	});
	liveReload(() => res.reload(), (e) => e.type === 'agent' && !e.last_metrics, { debounceMs: 2000, pollMs: 30000 });

	let q = $state('');
	const sort = sortState('name');
	const keyed: Record<string, (r: Row) => string | number> = {
		name: (r) => r.name.toLowerCase(),
		agents: (r) => r.agents,
		online: (r) => (r.agents ? r.online / r.agents : -1),
		health: (r) => (r.health?.unhealthy ?? 0) * 1e6 + (r.health?.attention ?? 0) * 1e3 + (r.agents - r.online),
		created: (r) => r.created_at
	};
	const rows = $derived.by(() => {
		const f = q.trim().toLowerCase();
		const list = (res.data ?? []).filter((c) => !f || c.name.toLowerCase().includes(f) || c.sites.some((s) => s.name.toLowerCase().includes(f)));
		const k = keyed[sort.key] ?? keyed.name;
		const sign = sort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => (k(a) < k(b) ? -sign : k(a) > k(b) ? sign : 0));
	});

	// "Add client" (also reachable from the command palette as ?new=1).
	let adding = $state(false);
	$effect(() => {
		if (param('new') && can('admin')) {
			adding = true;
			setParams({ new: null });
		}
	});
	let name = $state('');
	let busy = $state(false);
	async function add(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const r = await api.post<{ id: string }>('/clients', { name });
			toast.success(`${name} added, with a site called Main.`);
			adding = false;
			name = '';
			loadClients(true);
			await goto(`/clients/${r.id}?tab=sites`);
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<PageHeader title="Clients & Sites" count={res.data?.length ?? null}>
	{#snippet actions()}
		{#if can('admin')}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>Add client</Button>{/if}
	{/snippet}
</PageHeader>

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	{#snippet nameCell(c: Row)}<a class="hover:text-accent font-medium" href="/clients/{c.id}">{c.name}</a>{/snippet}
	{#snippet sitesCell(c: Row)}<span class="text-muted">{c.sites.map((s) => s.name).join(', ')}</span>{/snippet}
	{#snippet onlineCell(c: Row)}
		{#if c.agents}
			<div class="flex items-center gap-2">
				<span class="bg-sunken border-border h-1.5 w-20 overflow-hidden rounded-full border"><span class="bg-success block h-full" style="width: {pct(c.online, c.agents)}%"></span></span>
				<span class="text-muted text-xs tabular">{num(c.online)} / {num(c.agents)}</span>
			</div>
		{:else}<span class="text-muted text-xs">no agents</span>{/if}
	{/snippet}
	{#snippet healthCell(c: Row)}
		<span class="flex flex-wrap gap-1.5 text-xs">
			{#if c.health?.unhealthy}<a class="bg-danger-soft text-danger rounded px-1.5 py-0.5 font-medium" href="/agents?client={c.id}&health=unhealthy">{c.health.unhealthy} unhealthy</a>{/if}
			{#if c.health?.attention}<a class="bg-warning-soft text-warning rounded px-1.5 py-0.5 font-medium" href="/agents?client={c.id}&health=attention">{c.health.attention} attention</a>{/if}
			{#if c.agents - c.online}<a class="text-muted hover:text-fg px-0.5 py-0.5" href="/agents?client={c.id}&view=offline">{c.agents - c.online} offline</a>{/if}
			{#if c.agents && !c.health?.unhealthy && !c.health?.attention && c.agents === c.online}<span class="text-success">All good</span>{/if}
		</span>
	{/snippet}
	{#snippet createdCell(c: Row)}<span class="text-muted text-xs">{ago(c.created_at)}</span>{/snippet}

	<DataTable
		id="clients"
		caption="Clients"
		{rows}
		key={(c) => c.id}
		loading={res.loading}
		{sort}
		rowHref={(c) => `/clients/${c.id}`}
		scroll={false}
		columns={[
			{ id: 'name', label: 'Client', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'health', label: 'Health', sort: 'health', cell: healthCell },
			{ id: 'online', label: 'Agents online', sort: 'online', cell: onlineCell, from: 'sm' },
			{ id: 'sites', label: 'Sites', cell: sitesCell, from: 'md' },
			{ id: 'created', label: 'Added', sort: 'created', cell: createdCell, from: 'lg', defaultHidden: true }
		] satisfies Column<Row>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Client or site…" aria-label="Filter clients" class="w-full sm:w-64" bind:value={q} />
		{/snippet}
		{#snippet empty()}
			{#if q}
				<EmptyState compact title="No clients match" />
			{:else}
				<EmptyState icon={Building2} title="No clients yet" description="Each customer is a client with one or more sites. Agents enroll into a site.">
					{#snippet action()}{#if can('admin')}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>Add client</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}

{#if adding}
	<Modal title="Add client" description="It starts with one site, Main. Add more sites on its page." onclose={() => (adding = false)} size="sm">
		<form id="add-client" onsubmit={add}>
			<Field label="Name" id="client-name" required>
				<!-- svelte-ignore a11y_autofocus -->
				<Input id="client-name" bind:value={name} required maxlength={200} autofocus autocomplete="off" />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (adding = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="add-client" loading={busy} disabled={!name.trim()}>Add client</Button>
		{/snippet}
	</Modal>
{/if}
