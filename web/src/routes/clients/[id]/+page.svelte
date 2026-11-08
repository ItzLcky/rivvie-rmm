<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ExternalLink, MapPin, Pencil, Plus, Trash2, UserPlus } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num, pct, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Client, Dashboard, Site } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import EnrollDialog from '#lib/components/EnrollDialog.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import Status from '#lib/components/Status.svelte';

	const id = $derived(page.params.id!);
	const tab = $derived(param('tab', 'agents'));
	const client = resource(() => api.get<Client>(`/clients/${id}`), { keep: false });
	const dash = resource(() => api.get<Dashboard>(`/dashboard?client_id=${id}`));
	liveReload(
		() => {
			client.reload();
			dash.reload();
		},
		(e) => e.type === 'agent' && !e.last_metrics,
		{ debounceMs: 2000, pollMs: 30000 }
	);

	const sort = sortState('hostname');
	const agents = paged<AgentSummary>(() => `/agents${qs({ client_id: id, site_id: param('site'), sort: sort.key, dir: sort.dir })}`);

	let enrolling = $state<Site | null>(null);
	let naming = $state<{ kind: 'client' | 'site' | 'new-site'; site?: Site; value: string } | null>(null);
	let busy = $state(false);

	async function saveName(e: SubmitEvent) {
		e.preventDefault();
		if (!naming) return;
		busy = true;
		const n = naming;
		const ok = await attempt(async () => {
			if (n.kind === 'client') await api.put(`/clients/${id}`, { name: n.value });
			else if (n.kind === 'site') await api.put(`/sites/${n.site!.id}`, { name: n.value });
			else await api.post(`/clients/${id}/sites`, { name: n.value });
		}, n.kind === 'new-site' ? `Site ${n.value} added.` : 'Renamed.');
		busy = false;
		if (ok) {
			naming = null;
			await client.reload();
			loadClients(true);
		}
	}

	async function deleteSite(s: Site) {
		const ok = await confirmAction({
			title: `Delete site ${s.name}?`,
			message: s.agent_count ? `Its ${plural(s.agent_count, 'agent')} and their history are deleted too. They must be re-enrolled to be managed again.` : 'It has no agents.',
			confirmLabel: 'Delete site',
			danger: true,
			typeToConfirm: s.agent_count ? s.name : undefined
		});
		if (ok && (await attempt(() => api.del(`/sites/${s.id}`), `Site ${s.name} deleted.`))) {
			await client.reload();
			loadClients(true);
		}
	}

	async function deleteClient(c: Client) {
		const total = c.sites.reduce((n, s) => n + s.agent_count, 0);
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message: `This deletes ${plural(c.sites.length, 'site')} and ${plural(total, 'agent')}, with all their jobs and metrics. It can't be undone.`,
			confirmLabel: 'Delete client',
			danger: true,
			typeToConfirm: c.name
		});
		if (ok && (await attempt(() => api.del(`/clients/${c.id}`)))) {
			toast.success(`${c.name} deleted.`);
			loadClients(true);
			await goto('/clients');
		}
	}
</script>

<svelte:head>{#if client.data}<title>{client.data.name}</title>{/if}</svelte:head>

<Async res={client}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-56" /></div>
		<Skeleton class="mb-4 h-9 w-full" />
		<Skeleton class="h-64 w-full" />
	{/snippet}
	{#snippet children(c)}
		{@const total = c.sites.reduce((n, s) => n + s.agent_count, 0)}
		{@const online = c.sites.reduce((n, s) => n + s.online_count, 0)}
		<PageHeader
			title={c.name}
			description="Client since {datetime(c.created_at).split(',')[0]}"
			crumbs={[{ label: 'Clients', href: '/clients' }, { label: c.name }]}
			menu={can('admin')
				? [
						{ label: 'Rename client', icon: Pencil, onSelect: () => (naming = { kind: 'client', value: c.name }) },
						{ separator: true },
						{ label: 'Delete client…', icon: Trash2, danger: true, onSelect: () => deleteClient(c) }
					]
				: undefined}
		>
			{#snippet actions()}
				<Button icon={ExternalLink} href="/?client={c.id}">Dashboard</Button>
				{#if can('technician') && c.sites.length}
					<Button variant="primary" icon={UserPlus} onclick={() => (enrolling = c.sites[0])}>Enroll agents</Button>
				{/if}
			{/snippet}
		</PageHeader>

		<!-- Health summary: each number links to the filtered agent list. -->
		<div class="mb-4 grid grid-cols-3 gap-3">
			<Stat label="Agents online" value={online} of={total} />
			<Stat label="Need attention" value={(dash.data?.health.attention ?? 0) + (dash.data?.health.unhealthy ?? 0)} tone={dash.data?.health.unhealthy ? 'danger' : 'warning'} href="/agents?client={c.id}&view=attention" />
			<Stat label="Failed jobs (24 h)" value={dash.data?.failed_jobs.length ?? 0} capped={(dash.data?.failed_jobs.length ?? 0) >= 10} tone="danger" href="/jobs?client={c.id}&status=failed" />
		</div>

		<Tabs
			label="Client sections"
			class="mb-4"
			value={tab}
			onchange={(v) => setParams({ tab: v === 'agents' ? null : v }, { push: true })}
			items={[
				{ value: 'agents', label: 'Agents', count: num(total) },
				{ value: 'sites', label: 'Sites & enrollment', count: c.sites.length }
			]}
		/>

		{#if tab === 'agents'}
			{#snippet hostCell(a: AgentSummary)}<a class="hover:text-accent font-medium" href="/agents/{a.id}">{a.hostname}</a>{/snippet}
			{#snippet siteCell(a: AgentSummary)}<span class="text-muted">{a.site_name}</span>{/snippet}
			{#snippet osCell(a: AgentSummary)}<OsBadge os={a.os_family} name={a.os_name} muted />{/snippet}
			{#snippet statusCell(a: AgentSummary)}<Status online={a.online} />{/snippet}
			{#snippet healthCell(a: AgentSummary)}<HealthBadge health={a.health} agent={a} />{/snippet}
			{#snippet seenCell(a: AgentSummary)}<span class="text-muted">{a.online ? 'now' : ago(a.last_seen_at)}</span>{/snippet}
			<DataTable
				id="client-agents"
				caption="Agents of {c.name}"
				rows={agents.rows}
				key={(a) => a.id}
				loading={agents.loading}
				busy={agents.busy}
				{sort}
				rowHref={(a) => `/agents/${a.id}`}
				columns={[
					{ id: 'hostname', label: 'Hostname', sort: 'hostname', cell: hostCell, hideable: false },
					{ id: 'site', label: 'Site', sort: 'client', cell: siteCell, from: 'sm' },
					{ id: 'os', label: 'OS', sort: 'os', cell: osCell, from: 'lg' },
					{ id: 'status', label: 'Status', sort: 'status', cell: statusCell },
					{ id: 'health', label: 'Health', sort: 'health', cell: healthCell, from: 'sm' },
					{ id: 'last_seen', label: 'Last seen', sort: 'last_seen', cell: seenCell, from: 'md' }
				] satisfies Column<AgentSummary>[]}
			>
				{#snippet toolbar()}
					{#if c.sites.length > 1}
						<select class="control w-auto" aria-label="Site" value={param('site')} onchange={(e) => setParams({ site: e.currentTarget.value })}>
							<option value="">All sites</option>
							{#each c.sites as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
						</select>
					{/if}
					<MoreLink href="/agents?client={c.id}">Filters and bulk actions in Agents</MoreLink>
				{/snippet}
				{#snippet empty()}
					<EmptyState title="No agents yet" description="Open a site's enrollment dialog for the install commands.">
						{#snippet action()}{#if can('technician') && c.sites.length}<Button variant="primary" icon={UserPlus} onclick={() => (enrolling = c.sites[0])}>Enroll agents</Button>{/if}{/snippet}
					</EmptyState>
				{/snippet}
				{#snippet footer()}
					{#if agents.data && (agents.data.next || agents.data.prev)}
						<Pagination
							shown={agents.rows.length}
							total={agents.data.total}
							hasPrev={!!agents.data.prev}
							hasNext={!!agents.data.next}
							pageSize={agents.pageSize}
							onprev={agents.prev}
							onnext={agents.next}
							onfirst={agents.first}
							onpagesize={agents.setPageSize}
						/>
					{/if}
				{/snippet}
			</DataTable>
		{:else if tab === 'sites'}
			<section class="card overflow-hidden" aria-label="Sites">
				<header class="border-border flex items-center justify-between border-b px-4 py-2.5">
					<h2 class="text-sm font-semibold">Sites</h2>
					{#if can('admin')}<Button size="sm" icon={Plus} onclick={() => (naming = { kind: 'new-site', value: '' })}>Add site</Button>{/if}
				</header>
				{#if c.sites.length}
					<ul class="divide-border divide-y">
						{#each c.sites as s (s.id)}
							<li class="flex flex-wrap items-center gap-3 px-4 py-3">
								<MapPin class="text-muted size-4 shrink-0" />
								<div class="min-w-0 flex-1">
									<a class="hover:text-accent font-medium" href="/agents?client={c.id}&site={s.id}">{s.name}</a>
									<div class="text-muted mt-0.5 flex items-center gap-2 text-xs">
										{#if s.agent_count}
											<span class="bg-sunken border-border h-1.5 w-16 overflow-hidden rounded-full border"><span class="bg-success block h-full" style="width: {pct(s.online_count, s.agent_count)}%"></span></span>
											{s.online_count} of {plural(s.agent_count, 'agent')} online
										{:else}
											No agents
										{/if}
									</div>
								</div>
								<div class="flex items-center gap-1">
									{#if can('technician')}<Button size="sm" icon={UserPlus} onclick={() => (enrolling = s)}>Enroll agents</Button>{/if}
									{#if can('admin')}
										<IconButton icon={Pencil} label="Rename {s.name}" size="sm" onclick={() => (naming = { kind: 'site', site: s, value: s.name })} />
										<IconButton icon={Trash2} label="Delete {s.name}" size="sm" variant="danger-ghost" onclick={() => deleteSite(s)} />
									{/if}
								</div>
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={MapPin} title="No sites" description="Agents enroll into a site, so add one first." />
				{/if}
			</section>
		{/if}

		{#if enrolling}<EnrollDialog client={c} site={enrolling} onclose={() => (enrolling = null)} />{/if}
		{#if naming}
			<Modal title={naming.kind === 'client' ? 'Rename client' : naming.kind === 'site' ? `Rename ${naming.site?.name}` : `Add a site to ${c.name}`} onclose={() => (naming = null)} size="sm">
				<form id="name-form" onsubmit={saveName}>
					<Field label="Name" id="name-input" required>
						<!-- svelte-ignore a11y_autofocus -->
						<Input id="name-input" bind:value={naming.value} required maxlength={200} autofocus autocomplete="off" />
					</Field>
				</form>
				{#snippet footer()}
					<Button onclick={() => (naming = null)}>Cancel</Button>
					<Button variant="primary" type="submit" form="name-form" loading={busy} disabled={!naming?.value.trim()}>{naming?.kind === 'new-site' ? 'Add site' : 'Save'}</Button>
				{/snippet}
			</Modal>
		{/if}
	{/snippet}
</Async>
