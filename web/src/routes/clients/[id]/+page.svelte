<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Contact as ContactIcon, ExternalLink, LifeBuoy, MapPin, Pencil, Plus, Star, Trash2, UserPlus } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num, pct, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Client, Contact, Dashboard, Site, Ticket } from '#lib/types.js';
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
	import Switch from '#lib/ui/Switch.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import EnrollDialog from '#lib/components/EnrollDialog.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import Status from '#lib/components/Status.svelte';
	import ContactEditor from '#lib/components/ticket/ContactEditor.svelte';
	import NewTicket from '#lib/components/ticket/NewTicket.svelte';
	import TicketTable from '#lib/components/ticket/TicketTable.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

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

	// Service desk: tickets and contacts.
	const ticketSort = sortState('updated', 'desc');
	const ticketView = $derived(param('tview') === 'all' ? 'all' : 'open');
	const tickets = paged<Ticket>(() => (tab === 'tickets' ? `/tickets${qs({ client_id: id, view: ticketView, sort: ticketSort.key, dir: ticketSort.dir })}` : `/tickets?limit=1&client_id=${id}`));
	liveReload(() => tab === 'tickets' && tickets.reload(), (e) => e.type === 'ticket');
	let ticketing = $state(false);
	const contacts = resource(() => (tab === 'contacts' ? api.get<Contact[]>(`/contacts?client_id=${id}`) : Promise.resolve([] as Contact[])));
	let editingContact = $state<Contact | 'new' | null>(null);
	async function deleteContact(c: Contact) {
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message: c.open_tickets ? `${plural(c.open_tickets, 'open ticket')} keep their history but lose the contact; replies to them stop being emailed.` : 'Their tickets keep their history.',
			confirmLabel: 'Delete contact',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/contacts/${c.id}`), `${c.name} deleted.`))) contacts.reload();
	}
	let domains = $state('');
	let domainsBusy = $state(false);
	$effect(() => {
		if (client.data) domains = client.data.email_domains.join('\n');
	});
	async function saveDomains(c: Client) {
		domainsBusy = true;
		const list = domains.split(/[\s,;]+/).map((d) => d.trim()).filter(Boolean);
		if (await attempt(() => api.put<{ domains: string[] }>(`/clients/${c.id}/email-domains`, { domains: list }).then((r) => (c.email_domains = r.domains)), 'Email domains saved.')) {
			domains = c.email_domains.join('\n');
		}
		domainsBusy = false;
	}

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

	let consentBusy = $state(false);
	async function setConsent(c: Client, consent: boolean) {
		consentBusy = true;
		const ok = await attempt(
			() => api.put(`/clients/${c.id}/desktop`, { consent }),
			consent ? `${c.name}: the person at the machine is asked first.` : `${c.name}: remote desktop sessions start without asking.`
		);
		consentBusy = false;
		if (ok) c.desktop_consent = consent;
		else await client.reload();
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
				{ value: 'sites', label: 'Sites & enrollment', count: c.sites.length },
				{ value: 'tickets', label: 'Tickets' },
				{ value: 'contacts', label: 'Contacts' },
				{ value: 'settings', label: 'Settings', hidden: !can('admin') }
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
		{:else if tab === 'tickets'}
			<TicketTable id="client-tickets" caption="Tickets of {c.name}" list={tickets} sort={ticketSort} hide={['client']}>
				{#snippet toolbar()}
					<Segmented label="Tickets" value={ticketView} onchange={(v) => setParams({ tview: v === 'open' ? null : v })} options={[{ value: 'open', label: 'Open' }, { value: 'all', label: 'All' }]} />
					{#if can('technician')}<Button size="sm" icon={LifeBuoy} class="ml-auto" onclick={() => (ticketing = true)}>New ticket</Button>{/if}
				{/snippet}
				{#snippet empty()}<EmptyState compact title={ticketView === 'open' ? 'No open tickets' : 'No tickets yet'} />{/snippet}
			</TicketTable>
		{:else if tab === 'contacts'}
			<section class="card" aria-label="Contacts">
				<header class="border-border flex items-center justify-between gap-3 border-b px-4 py-2.5">
					<div>
						<h2 class="text-sm font-semibold">Contacts</h2>
						<p class="text-muted text-xs">People at {c.name}. Mail from their address is filed on their tickets.</p>
					</div>
					{#if can('technician')}<Button size="sm" icon={Plus} onclick={() => (editingContact = 'new')}>Add contact</Button>{/if}
				</header>
				<Async res={contacts} compact>
					{#snippet children(list)}
						{#if list.length}
							<ul class="divide-border divide-y">
								{#each list as p (p.id)}
									<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
										<div class="min-w-0 flex-1">
											<div class="font-medium">{p.name}{#if p.is_primary} <Star class="text-warning inline size-3.5 align-[-2px]" aria-label="Primary contact" />{/if}{#if p.job_title}<span class="text-muted font-normal"> · {p.job_title}</span>{/if}</div>
											<div class="text-muted truncate text-xs">{[p.email, p.phone, p.site_name].filter(Boolean).join(' · ') || 'No contact details'}</div>
										</div>
										{#if p.open_tickets}<a class="link text-xs" href="/tickets?client={c.id}&q={encodeURIComponent(p.email || p.name)}">{plural(p.open_tickets, 'open ticket')}</a>{/if}
										{#if can('technician')}
											<IconButton icon={Pencil} size="sm" label="Edit {p.name}" onclick={() => (editingContact = p)} />
											<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {p.name}" onclick={() => deleteContact(p)} />
										{/if}
									</li>
								{/each}
							</ul>
						{:else}
							<EmptyState compact icon={ContactIcon} title="No contacts yet" description="Add the people who raise tickets, so their mail is filed here and replies reach them." />
						{/if}
					{/snippet}
				</Async>
			</section>
		{:else if tab === 'settings' && can('admin')}
			<div class="max-w-2xl space-y-5">
				<section class="card space-y-3 p-5" aria-labelledby="domains-heading">
					<div>
						<h2 id="domains-heading" class="font-semibold">Email domains</h2>
						<p class="text-muted text-xs">Mail to a support mailbox from these domains is filed under {c.name}, even when the sender isn't a contact yet. Contacts are never created automatically.</p>
					</div>
					<Field label="Domains" id="client-domains" hint="One per line, e.g. example.com.">
						<Textarea id="client-domains" rows={3} class="font-mono text-xs" bind:value={domains} spellcheck="false" />
					</Field>
					<div class="flex justify-end"><Button variant="primary" loading={domainsBusy} disabled={domains === c.email_domains.join('\n')} onclick={() => saveDomains(c)}>Save</Button></div>
				</section>
				<section class="card space-y-4 p-5" aria-labelledby="desktop-heading">
					<h2 id="desktop-heading" class="font-semibold">Remote desktop</h2>
					<div>
						<Switch checked={c.desktop_consent} disabled={consentBusy} onchange={(v) => setConsent(c, v)}>Ask the user before connecting</Switch>
						<p class="hint ml-11.5">
							The person at the machine gets an Allow / Deny prompt, and the session is refused if nobody answers within 30 seconds. If nobody is signed in, the session starts without asking.
						</p>
					</div>
				</section>
			</div>
		{/if}

		{#if enrolling}<EnrollDialog client={c} site={enrolling} onclose={() => (enrolling = null)} />{/if}
		{#if ticketing}<NewTicket onclose={() => (ticketing = false)} initial={{ clientId: c.id }} />{/if}
		{#if editingContact}
			<ContactEditor contact={editingContact === 'new' ? null : editingContact} clientId={c.id} onclose={() => (editingContact = null)} onsaved={() => contacts.reload()} />
		{/if}
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
