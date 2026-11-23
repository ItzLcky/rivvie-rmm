<script lang="ts">
	import { Plus, RefreshCw, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { opLabels, providerLabels, runLabel, runTone, standing, wantLabels, type AgentSoftware, type SoftwareDevice, type SoftwarePackage, type SoftwareRun } from '#lib/software.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentDetail } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	/** One device's managed software: what the catalog says is installed, what its policies ask, and recent runs. */
	let { agent }: { agent: AgentDetail } = $props();
	const id = $derived(agent.id);

	let showAll = $state(false);
	const res = resource(() => api.get<AgentSoftware>(`/agents/${id}/software${showAll ? '?all=true' : ''}`));
	liveReload(() => res.reload(), (e) => e.type === 'software' && e.agent_id === id, { debounceMs: 400 });
	$effect(() => {
		showAll;
		res.reload();
	});
	let q = $state('');
	let adding = $state(false);
	let pick = $state('');
	let op = $state<'install' | 'upgrade' | 'uninstall'>('install');
	let bootstrap = $state(false);
	let busy = $state(false);
	const catalog = resource(() => (adding ? api.get<SoftwarePackage[]>(`/software/packages?platform=${agent.os_family === 'windows' ? 'windows' : 'linux'}`) : Promise.resolve([] as SoftwarePackage[])));
	const catalogItems = $derived((catalog.data ?? []).filter((p) => !p.client_id || p.client_id === agent.client_id).map((p) => ({ value: p.id, label: p.name, hint: p.client_name ?? undefined })));
	const chosen = $derived(catalog.data?.find((p) => p.id === pick));

	const rows = (d: AgentSoftware) => d.items.filter((i) => !q.trim() || `${i.package_name}`.toLowerCase().includes(q.trim().toLowerCase()));
	const running = $derived((res.data?.runs ?? []).find((r) => r.status === 'queued' || r.status === 'sent'));

	async function scan() {
		if (await attempt(() => api.post('/software/scan', { agent_ids: [id] }), 'Scan requested. Results arrive when the device finishes.')) res.reload();
	}
	async function act(packageId: string, o: typeof op, name: string) {
		await attempt(async () => {
			const r = await api.post<{ runs: unknown[]; skipped: { reason: string }[] }>('/software/deploy', { package_id: packageId, op: o, agent_ids: [id], bootstrap_choco: bootstrap });
			if (!r.runs.length) throw new Error(r.skipped[0]?.reason ?? 'nothing was started');
		}, `${opLabels[o]} of ${name} started.`);
		res.reload();
	}
	async function submit() {
		if (!chosen) return;
		busy = true;
		await act(chosen.id, op, chosen.name);
		busy = false;
		adding = false;
		pick = '';
	}
	function runLine(r: SoftwareRun): string {
		if (r.status === 'sent') return r.progress ?? (r.stage ? `${r.stage}…` : 'starting…');
		if (r.status === 'queued') return 'waiting for the device to connect';
		return r.error ?? [r.from_version && r.to_version && r.from_version !== r.to_version ? `${r.from_version} → ${r.to_version}` : r.to_version, r.provider ? providerLabels[r.provider] : null].filter(Boolean).join(' · ');
	}
</script>

<Async {res}>
	{#snippet skeleton()}
		<div class="card p-4"><Skeleton lines={5} /></div>
	{/snippet}
	{#snippet children(d)}
		{#if !d.capable}
			<div class="card"><EmptyState title="This agent can’t deploy software yet" description="Its version predates software deployment. Update the agent (overflow menu above) and it starts reporting." /></div>
		{:else}
			{@const asked = d.items.filter((i) => i.desired)}
			<div class="mb-4 grid gap-4 lg:grid-cols-2">
				<section class="card p-4" aria-label="Scan">
					<div class="mb-2 flex items-start justify-between gap-2">
						<h2 class="panel-title">Managed software</h2>
						{#if can('technician')}<Button size="sm" icon={RefreshCw} loading={!!d.scan_requested_at} disabled={!agent.online} title={agent.online ? undefined : 'The agent is offline'} onclick={scan}>{d.scan_requested_at ? 'Scanning' : 'Scan now'}</Button>{/if}
					</div>
					<p class="text-sm">
						{#if d.scanned_at}Scanned {ago(d.scanned_at)}{:else}Not scanned yet{/if}
						{#if d.providers.length} with {d.providers.map((p) => providerLabels[p] ?? p).join(', ')}{/if}
					</p>
					<p class="text-muted mt-1 text-xs">Packages come from the <a class="link" href="/software">catalog</a>. Required ones are set in this device’s <a class="link" href="/agents/{id}?tab=policy">policy</a>.</p>
					{#if d.scan_error}<pre class="text-danger mt-2 max-h-32 overflow-auto text-xs whitespace-pre-wrap" role="alert">{d.scan_error}</pre>{/if}
				</section>
				<section class="card p-4" aria-label="Summary">
					<h2 class="panel-title mb-2">Policy</h2>
					<p class="text-sm"><span class="text-2xl font-semibold tabular {asked.some((i) => i.compliant === false) ? 'text-warning' : ''}">{asked.filter((i) => i.compliant === false).length}</span> <span class="text-muted">of {plural(asked.length, 'required package')} not met</span></p>
					<p class="text-muted mt-1 text-xs">{d.items.filter((i) => i.installed && i.available).length} with an update on offer.</p>
				</section>
			</div>

			<div class="grid gap-4 xl:grid-cols-[1fr_22rem]">
				{#snippet pkgCell(i: SoftwareDevice)}<a class="hover:text-accent font-medium" href="/software/{i.package_id}">{i.package_name}</a>{#if i.pin}<div class="text-muted text-xs">pinned to {i.pin}</div>{/if}{/snippet}
				{#snippet versionCell(i: SoftwareDevice)}
					{#if i.installed}<span class="font-mono text-xs">{i.installed}</span>{#if i.available}<span class="text-warning ml-1 text-xs">→ {i.available}</span>{/if}{:else}<span class="text-muted">Not installed</span>{/if}
				{/snippet}
				{#snippet wantCell(i: SoftwareDevice)}{#if i.desired}{wantLabels[i.desired]}{:else}<span class="text-muted">No policy</span>{/if}{/snippet}
				{#snippet stateCell(i: SoftwareDevice)}
					{@const s = standing(i)}
					{#if s}<Badge tone={s.tone} title={s.title}>{s.label}</Badge>{:else}<span class="text-muted" aria-label="none">–</span>{/if}
					{#if i.fail_count && i.last_error}<div class="text-danger mt-0.5 max-w-xs truncate text-xs" title={i.last_error}>{i.last_error}</div>{/if}
				{/snippet}
				{#snippet actCell(i: SoftwareDevice)}
					{#if can('technician')}
						<span class="flex justify-end gap-1">
							{#if !i.installed}<Button size="sm" disabled={!!running} onclick={() => act(i.package_id, 'install', i.package_name)}>Install</Button>{/if}
							{#if i.installed && i.available}<Button size="sm" disabled={!!running} onclick={() => act(i.package_id, 'upgrade', i.package_name)}>Upgrade</Button>{/if}
							{#if i.installed}<Button size="sm" variant="ghost" disabled={!!running} onclick={() => act(i.package_id, 'uninstall', i.package_name)}>Uninstall</Button>{/if}
						</span>
					{/if}
				{/snippet}
				<DataTable
					id="agent-deployments"
					caption="Catalog software on this device"
					rows={rows(d)}
					key={(i) => i.package_id}
					scroll={false}
					columns={[
						{ id: 'pkg', label: 'Package', cell: pkgCell, hideable: false },
						{ id: 'version', label: 'Version', cell: versionCell },
						{ id: 'want', label: 'Policy asks', cell: wantCell, from: 'md' },
						{ id: 'state', label: 'State', cell: stateCell },
						{ id: 'act', label: 'Actions', cell: actCell, align: 'right', hideable: false }
					] satisfies Column<SoftwareDevice>[]}
				>
					{#snippet toolbar()}
						<Input icon={Search} data-search placeholder="Filter packages…" aria-label="Filter packages" class="min-w-0 flex-1 sm:w-56 sm:flex-none" bind:value={q} />
						<Segmented label="Show" value={showAll ? 'all' : 'mine'} onchange={(v) => (showAll = v === 'all')} options={[{ value: 'mine', label: 'Installed or required' }, { value: 'all', label: 'Whole catalog' }]} />
						{#if can('technician')}<Button size="sm" variant="primary" icon={Plus} class="sm:ml-auto" onclick={() => (adding = true)}>Deploy a package…</Button>{/if}
					{/snippet}
					{#snippet empty()}<EmptyState compact title={q ? 'No packages match' : 'Nothing from the catalog here yet'} description={q ? undefined : 'Deploy a package, or require one in this device’s policy set.'} />{/snippet}
				</DataTable>

				<section class="card self-start" aria-label="Recent runs">
					<header class="border-border flex min-h-12 items-center justify-between border-b px-4 py-3">
						<h2 class="panel-title">Recent runs</h2>
						<MoreLink href="/software?tab=runs">History</MoreLink>
					</header>
					{#if d.runs.length}
						<ul class="divide-border divide-y">
							{#each d.runs.slice(0, 8) as r (r.id)}
								<li>
									<a href="/software/runs/{r.id}" class="hover:bg-hover/60 block px-4 py-2 text-sm">
										<div class="flex items-center gap-2"><Badge tone={runTone[r.status]}>{runLabel[r.status]}</Badge><span class="min-w-0 truncate font-medium">{opLabels[r.op]} {r.package_name}</span><span class="text-muted ml-auto shrink-0 text-xs">{ago(r.created_at)}</span></div>
										<div class="text-muted mt-0.5 truncate text-xs">{runLine(r)}</div>
										<div class="text-muted text-xs">{r.trigger === 'policy' ? 'Policy' : (r.created_by_name ?? 'Manual')}</div>
									</a>
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact title="No runs yet" />
					{/if}
				</section>
			</div>
		{/if}

		{#if adding}
			<Modal title="Deploy a package" description="To {agent.hostname}." size="sm" onclose={() => (adding = false)}>
				<div class="space-y-3">
					<div>
						<label class="label" for="dp-pkg">Package</label>
						{#if catalog.data}<Combobox id="dp-pkg" bind:value={pick} items={catalogItems} placeholder="Pick a catalog package" label="Package" />{:else}<Skeleton class="h-8 w-full" />{/if}
					</div>
					<Segmented label="Action" value={op} onchange={(v) => (op = v)} options={[{ value: 'install', label: 'Install' }, { value: 'upgrade', label: 'Upgrade' }, { value: 'uninstall', label: 'Uninstall' }]} />
					{#if chosen?.choco_id && !chosen.winget_id && agent.os_family === 'windows'}
						<label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={bootstrap} class="mt-0.5" /> <span>Install Chocolatey first if the device doesn’t have it <span class="text-muted block text-xs">Downloads and runs Chocolatey’s install script.</span></span></label>
					{/if}
				</div>
				{#snippet footer()}
					<Button variant="ghost" onclick={() => (adding = false)}>Cancel</Button>
					<Button variant="primary" loading={busy} disabled={!chosen} onclick={submit}>{opLabels[op]}</Button>
				{/snippet}
			</Modal>
		{/if}
	{/snippet}
</Async>
