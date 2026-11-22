<script lang="ts">
	import { KeyRound, Pencil, Plus, Radar, Save, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import CredentialDialog from '#lib/components/network/CredentialDialog.svelte';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import type { Credential, SiteNetwork } from '#lib/network.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	// Credentials belong to one client, so one client at a time: the switcher's, or chosen here.
	const client = $derived(clients.list.find((c) => c.id === (clientId() || param('c'))) ?? (clientId() ? undefined : clients.list[0]));
	const creds = resource(() => (client ? api.get<Credential[]>(`/clients/${client.id}/network-credentials`) : Promise.resolve([] as Credential[])));
	$effect(() => {
		client?.id;
		creds.reload();
	});
	const canEdit = can('technician');

	let editing = $state<Credential | 'new' | null>(null);
	async function removeCred(c: Credential) {
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message: c.devices ? `${c.devices} monitored device${c.devices === 1 ? ' uses' : 's use'} it; remove or change those first.` : 'Sites that scan with it stop trying it.',
			confirmLabel: 'Delete credentials',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/network-credentials/${c.id}`), `${c.name} deleted.`))) creds.reload();
	}

	// One form per site.
	const sites = resource(async () => (client ? await Promise.all(client.sites.map((s) => api.get<SiteNetwork>(`/sites/${s.id}/network`))) : []));
	$effect(() => {
		client?.id;
		sites.reload();
	});
	liveReload(() => sites.reload(), (e) => e.type === 'agent', { debounceMs: 2000 });

	type Draft = { agent_id: string; subnets: string; discovery_hours: number; poll_secs: number; credential_ids: string[] };
	let drafts = $state<Record<string, Draft>>({});
	let saving = $state<string | null>(null);
	$effect(() => {
		for (const s of sites.data ?? []) {
			drafts[s.site_id] ??= { agent_id: s.agent_id ?? '', subnets: s.subnets.join('\n'), discovery_hours: s.discovery_hours, poll_secs: s.poll_secs, credential_ids: [...s.credential_ids] };
		}
	});
	async function save(s: SiteNetwork) {
		const d = drafts[s.site_id];
		saving = s.site_id;
		try {
			await api.put(`/sites/${s.site_id}/network`, {
				agent_id: d.agent_id || null,
				subnets: d.subnets.split(/[\s,]+/).filter(Boolean),
				discovery_hours: Number(d.discovery_hours),
				poll_secs: Number(d.poll_secs),
				credential_ids: d.credential_ids
			});
			toast.success(`${s.site_name} saved.`);
			delete drafts[s.site_id];
			sites.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = null;
		}
	}
	async function scan(s: SiteNetwork) {
		if (await attempt(() => api.post(`/sites/${s.site_id}/network/scan`), `Scan started on ${s.agent_hostname}. New hosts show up under Discovered.`)) setTimeout(() => sites.reload(), 2000);
	}
	const scanTone = { done: 'success', running: 'info', failed: 'danger', pending: 'info' } as Record<string, 'success' | 'info' | 'danger'>;
</script>

<PageHeader title="Network settings" crumbs={[{ label: 'Network', href: withClient('/network') }, { label: 'Settings' }]} description="Pick the agent that looks at each site's network, what it may scan, and the SNMP credentials it tries.">
	{#snippet actions()}
		{#if !clientId() && clients.list.length > 1}
			<Select aria-label="Client" value={client?.id ?? ''} onchange={(e) => setParams({ c: e.currentTarget.value })} options={clients.list.map((c) => ({ value: c.id, label: c.name }))} />
		{/if}
	{/snippet}
</PageHeader>

{#if !client}
	<div class="card"><EmptyState title="Choose a client" description="Settings belong to a client's sites: pick one in the switcher at the top." /></div>
{:else}
	<section class="card mb-6" aria-labelledby="cred-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="cred-h" class="font-semibold">SNMP credentials · {client.name}</h2>
				<p class="text-muted text-xs">v2c community strings and v3 users. Sealed on the server; only the site's designated agent receives them, when it scans or reads. They are never shown again.</p>
			</div>
			{#if canEdit}<Button variant="primary" icon={Plus} onclick={() => (editing = 'new')}>New credentials</Button>{/if}
		</header>
		{#if creds.data?.length}
			<ul class="divide-border divide-y">
				{#each creds.data as c (c.id)}
					<li class="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
						<KeyRound class="text-muted size-4" aria-hidden="true" />
						<span class="font-medium">{c.name}</span>
						<Badge tone="neutral">SNMP {c.version}</Badge>
						<span class="text-muted text-xs">{c.version === 'v3' ? `${c.username} · ${c.auth_proto ? c.auth_proto.toUpperCase() : 'no auth'}${c.priv_proto ? ` + ${c.priv_proto.toUpperCase()}` : ''}` : 'community string'}{c.devices ? ` · ${c.devices} device${c.devices === 1 ? '' : 's'}` : ''}</span>
						{#if canEdit}
							<span class="ml-auto flex gap-1.5">
								<Button size="xs" icon={Pencil} onclick={() => (editing = c)}>Edit</Button>
								<Button size="xs" variant="danger-ghost" icon={Trash2} onclick={() => removeCred(c)}>Delete</Button>
							</span>
						{/if}
					</li>
				{/each}
			</ul>
		{:else if creds.data}
			<EmptyState compact title="No credentials yet" description="Add a read-only community string or SNMPv3 user. Sites try the ones you tick, in order, on each host they find." />
		{/if}
	</section>

	<h2 class="mb-3 text-lg font-semibold">Sites</h2>
	{#if sites.data?.length === 0}
		<div class="card"><EmptyState compact title="This client has no sites" /></div>
	{/if}
	<div class="space-y-5">
		{#each sites.data ?? [] as s (s.site_id)}
			{@const d = drafts[s.site_id]}
			{#if d}
				<form class="card" aria-labelledby="site-{s.site_id}" onsubmit={(e) => { e.preventDefault(); save(s); }}>
					<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
						<div>
							<h3 id="site-{s.site_id}" class="font-semibold">{s.site_name}</h3>
							<p class="text-muted text-xs">
								{#if s.agent_id}
									Designated agent {s.agent_hostname} is {s.agent_online ? 'online' : 'offline'}{s.agent_capable ? '' : ', and too old for network features'} · {num(s.devices)} monitored device{s.devices === 1 ? '' : 's'}
								{:else}Network features are off for this site.{/if}
							</p>
						</div>
						<div class="flex gap-2">
							{#if canEdit}
								<Button type="button" icon={Radar} disabled={!s.agent_id || !s.agent_online || !s.agent_capable} onclick={() => scan(s)}>Scan now</Button>
								<Button type="submit" variant="primary" icon={Save} loading={saving === s.site_id}>Save</Button>
							{/if}
						</div>
					</header>
					<fieldset class="grid gap-4 p-5 lg:grid-cols-2" disabled={!canEdit}>
						<div class="space-y-4">
							<Field label="Designated agent" id="ag-{s.site_id}" hint="The machine that scans and reads. Pick one that is always on, on the network you want to see.">
								<Select
									id="ag-{s.site_id}"
									class="w-full"
									bind:value={d.agent_id}
									options={[{ value: '', label: 'None (off)' }, ...s.candidates.map((c) => ({ value: c.id, label: `${c.hostname}${c.online ? '' : ' (offline)'}${c.capable ? '' : ' (update it first)'}`, disabled: !c.capable }))]}
								/>
							</Field>
							<Field label="Networks to scan" id="sn-{s.site_id}" hint="One per line, as 192.168.1.0/24. Private ranges only, at most 4096 addresses. Empty: the subnets the agent is on.">
								<Textarea id="sn-{s.site_id}" rows={3} class="font-mono text-[13px]" bind:value={d.subnets} placeholder={'192.168.1.0/24\n10.20.0.0/22'} />
							</Field>
							<div class="grid gap-3 sm:grid-cols-2">
								<Field label="Scan automatically every (hours)" id="dh-{s.site_id}" hint="0: only when you ask."><Input id="dh-{s.site_id}" type="number" min="0" max="720" bind:value={d.discovery_hours} /></Field>
								<Field label="Read devices every (seconds)" id="ps-{s.site_id}" hint="60 to 3600."><Input id="ps-{s.site_id}" type="number" min="60" max="3600" bind:value={d.poll_secs} /></Field>
							</div>
						</div>
						<div class="space-y-4">
							<div>
								<span class="label">Credentials to try on discovered hosts</span>
								<div class="mt-1 space-y-1.5">
									{#each creds.data ?? [] as c (c.id)}
										<div>
											<Checkbox checked={d.credential_ids.includes(c.id)} onchange={(on) => (d.credential_ids = on ? [...d.credential_ids, c.id] : d.credential_ids.filter((x) => x !== c.id))}>{c.name} <span class="text-muted text-xs">SNMP {c.version}</span></Checkbox>
										</div>
									{:else}
										<p class="text-muted text-sm">None yet: add credentials above.</p>
									{/each}
								</div>
							</div>
							<div class="text-sm">
								<span class="label">Last scan</span>
								{#if s.last_scan}
									{@const l = s.last_scan}
									<p><Badge tone={scanTone[l.status] ?? 'neutral'}>{l.status}</Badge> <span class="text-muted" title={datetime(l.created_at)}>{ago(l.created_at)}{l.requested_by_name ? ` · by ${l.requested_by_name}` : ' · scheduled'}</span></p>
									<p class="text-muted text-xs">{l.status === 'done' ? `${num(l.scanned)} addresses in ${l.subnets.join(', ') || 'its subnets'}: ${num(l.found)} hosts, ${num(l.new_hosts)} new.` : (l.error ?? '')}</p>
								{:else}
									<p class="text-muted">Never scanned.</p>
								{/if}
							</div>
						</div>
					</fieldset>
				</form>
			{/if}
		{/each}
	</div>
{/if}

{#if editing && client}
	<CredentialDialog clientId={client.id} credential={editing === 'new' ? null : editing} onclose={() => (editing = null)} ondone={() => ((editing = null), creds.reload())} />
{/if}
