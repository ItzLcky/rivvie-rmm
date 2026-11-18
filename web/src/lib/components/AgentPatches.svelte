<script lang="ts">
	import { Ban, Check, Download, RefreshCw, RotateCcw, Search, ShieldAlert } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, bytes, datetime, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { categoryLabel, providerLabels, rebootLabel, windowLabel } from '#lib/patches.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { AgentDetail, AgentPatch, AgentPatches, Approval, PatchRun } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import InstallPatches from './InstallPatches.svelte';
	import PatchBadge from './PatchBadge.svelte';

	let { agent }: { agent: AgentDetail } = $props();
	const id = $derived(agent.id);

	const res = resource(() => api.get<AgentPatches>(`/agents/${id}/patches`));
	liveReload(() => res.reload(), (e) => e.type === 'patches' && e.agent_id === id, { debounceMs: 400 });

	type Show = 'outstanding' | 'installed' | 'all';
	let show = $state<Show>('outstanding');
	let q = $state('');
	let selected = $state(new Set<string>());
	let installing = $state<{ ids: string[] | null; summary: string } | null>(null);

	const outstanding = $derived((res.data?.patches ?? []).filter((p) => p.state !== 'installed'));
	const rows = $derived.by(() => {
		const f = q.trim().toLowerCase();
		return (res.data?.patches ?? []).filter(
			(p) =>
				(show === 'all' || (show === 'installed') === (p.state === 'installed')) &&
				(!f || `${p.title} ${p.kb ?? ''} ${p.update_id}`.toLowerCase().includes(f))
		);
	});
	const approvedOutstanding = $derived(outstanding.filter((p) => p.approval === 'approved'));
	const running = $derived((res.data?.runs ?? []).find((r) => r.status === 'queued' || r.status === 'sent'));

	async function scan() {
		if (await attempt(() => api.post('/patches/scan', { agent_ids: [id] }), 'Scan requested. Results arrive when the agent finishes (this can take a few minutes).')) res.reload();
	}
	async function decide(decision: Approval, ids: string[]) {
		const verb = decision === 'approved' ? 'Approved' : decision === 'declined' ? 'Declined' : 'Reset to the policy:';
		if (await attempt(() => api.post('/patches/approval', { decision, update_ids: ids, agent_ids: [id] }), `${verb} ${plural(ids.length, 'update')}.`)) {
			selected = new Set();
			res.reload();
		}
	}
	function installSelected() {
		const ids = [...selected].filter((u) => outstanding.some((p) => p.update_id === u));
		installing = { ids, summary: `${plural(ids.length, 'update')} on ${agent.hostname}` };
	}

	function approvalTitle(p: AgentPatch): string {
		if (p.approval_manual) return `${p.approval === 'declined' ? 'Declined' : 'Approved'} by ${p.approved_by_name ?? 'a user'}${p.approved_at ? ` ${ago(p.approved_at)}` : ''}`;
		return p.approval === 'approved' ? 'Approved by the patch policy' : 'The patch policy doesn’t approve this; approve it by hand to install it';
	}
	function runLine(r: PatchRun): string {
		if (r.status === 'sent') return r.progress ?? (r.stage ? `${r.stage}…` : 'starting…');
		if (r.status === 'queued') return 'waiting for the agent to connect';
		if (r.error && !r.succeeded) return r.error;
		return `${r.succeeded} of ${plural(r.updates, 'update')} installed${r.rebooting ? ', restarting' : r.reboot_required ? ', restart pending' : ''}`;
	}
	/** The window automatic installs use: the patch policy's own, else the site's. */
	const winOf = (d: AgentPatches) => d.policy?.window ?? d.window;
</script>

<Async {res}>
	{#snippet skeleton()}
		<div class="grid gap-4 lg:grid-cols-3"><div class="card p-4"><Skeleton lines={3} /></div><div class="card p-4"><Skeleton lines={3} /></div><div class="card p-4"><Skeleton lines={3} /></div></div>
	{/snippet}
	{#snippet children(d)}
		{@const s = d.status}
		{#if !s.supported}
			<div class="card">
				<EmptyState title="This agent can’t be patched yet" description="Its version predates patch management. Update the agent (overflow menu above) and it starts reporting updates." />
			</div>
		{:else}
			<div class="mb-4 grid gap-4 lg:grid-cols-3">
				<section class="card p-4" aria-label="Scan">
					<div class="mb-2 flex items-start justify-between gap-2">
						<h2 class="panel-title">Updates</h2>
						{#if can('technician')}
							<Button size="sm" icon={RefreshCw} loading={!!s.scan_requested_at} disabled={!s.online} title={s.online ? undefined : 'The agent is offline'} onclick={scan}>
								{s.scan_requested_at ? 'Scanning' : 'Scan now'}
							</Button>
						{/if}
					</div>
					<div class="flex items-baseline gap-2">
						<span class="text-2xl font-semibold tabular {outstanding.length ? 'text-warning' : ''}">{num(outstanding.length)}</span>
						<span class="text-muted text-sm">outstanding · {num(approvedOutstanding.length)} approved</span>
					</div>
					<p class="text-muted mt-1 text-xs">
						{#if s.scanned_at}Scanned {ago(s.scanned_at)} with {providerLabels[s.provider ?? ''] ?? s.provider}{:else}Not scanned yet{/if}
					</p>
					{#if s.reboot_pending}<div class="mt-2"><Badge tone="warning" icon={RotateCcw}>Restart pending</Badge></div>{/if}
				</section>
				<section class="card p-4" aria-label="Policy">
					<div class="mb-2 flex items-start justify-between gap-2">
						<h2 class="panel-title">Policy</h2>
						{#if d.policy}<MoreLink href="/policies/sets/{d.policy.set_id}?section=patching">Open</MoreLink>{/if}
					</div>
					{#if d.policy}
						{@const p = d.policy}
						<p class="text-sm">Patching in <a class="link" href="/policies/sets/{p.set_id}?section=patching">{p.source}</a></p>
						<p class="text-muted mt-1 text-xs">
							Approves {[...p.auto_approve_categories.map(categoryLabel), ...p.auto_approve_severities.map((x) => `${x} severity`)].join(', ') || 'nothing automatically'}{p.deferral_days ? ` after ${plural(p.deferral_days, 'day')}` : ''}.
							{p.auto_install ? 'Installs automatically' : 'Installs only when someone starts it'} · {rebootLabel(p.reboot_policy).toLowerCase()}.
						</p>
					{/if}
				</section>
				<section class="card p-4" aria-label="Install window">
					<h2 class="mb-2 panel-title">{d.policy?.own_window ? 'Install window' : 'Maintenance window'}</h2>
					<p class="text-sm">{windowLabel(winOf(d))}</p>
					<p class="text-muted mt-1 text-xs">
						{#if d.policy?.own_window}The patch policy's own window, not the site's. {/if}{#if !winOf(d).days?.length}Automatic installs may start whenever updates are eligible.{:else if winOf(d).open_now}Open now.{:else}Next opens {datetime(winOf(d).next_start)}.{/if}
					</p>
				</section>
			</div>

			{#if s.scan_error}
				<div class="border-danger/40 bg-danger-soft mb-4 rounded-md border p-3" role="alert">
					<p class="text-danger text-sm font-medium">The last scan failed</p>
					<pre class="text-fg mt-1 max-h-40 overflow-auto text-xs whitespace-pre-wrap">{s.scan_error}</pre>
				</div>
			{/if}
			{#if s.all_or_nothing}
				<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-xs">pacman can only upgrade everything at once: an install covers every outstanding update, and automatic installs wait until all of them are approved.</p>
			{/if}

			<div class="grid gap-4 xl:grid-cols-[1fr_22rem]">
				{#snippet titleCell(p: AgentPatch)}
					<div class="min-w-0">
						<div class="font-medium break-words">{p.title}</div>
						<div class="text-muted mt-0.5 flex flex-wrap gap-x-2 text-xs">
							{#if p.kb}<span class="font-mono">{p.kb}</span>{/if}
							{#if p.current_version && p.version}<span class="font-mono">{p.current_version} → {p.version}</span>{/if}
							{#if p.requires_reboot}<span>needs restart</span>{/if}
						</div>
						{#if p.last_error && p.state === 'failed'}<div class="text-danger mt-0.5 text-xs">{p.last_error}{p.fail_count > 1 ? ` (${p.fail_count} attempts)` : ''}</div>{/if}
					</div>
				{/snippet}
				{#snippet sevCell(p: AgentPatch)}<PatchBadge kind="severity" value={p.severity} />{/snippet}
				{#snippet catCell(p: AgentPatch)}<span class="text-muted whitespace-nowrap">{categoryLabel(p.category)}</span>{/snippet}
				{#snippet stateCell(p: AgentPatch)}<PatchBadge kind="state" value={p.state} title={p.installed_at ? `Installed ${datetime(p.installed_at)}` : undefined} />{/snippet}
				{#snippet approvalCell(p: AgentPatch)}
					<span class="inline-flex flex-wrap items-center gap-1">
						<PatchBadge kind="approval" value={p.approval} title={approvalTitle(p)} />
						{#if p.deferred_until}<span class="text-muted text-xs" title="Deferred by the policy">from {datetime(p.deferred_until)}</span>{/if}
					</span>
				{/snippet}
				{#snippet sizeCell(p: AgentPatch)}<span class="text-muted tabular">{p.size ? bytes(p.size) : '–'}</span>{/snippet}
				{#snippet seenCell(p: AgentPatch)}<span class="text-muted whitespace-nowrap" title={datetime(p.first_seen_at)}>{ago(p.first_seen_at)}</span>{/snippet}
				<DataTable
					id="agent-patches"
					caption="Updates for this agent"
					rows={rows}
					key={(p) => p.update_id}
					bind:selected
					scroll={false}
					columns={[
						{ id: 'title', label: 'Update', cell: titleCell, hideable: false },
						{ id: 'severity', label: 'Severity', cell: sevCell, from: 'sm' },
						{ id: 'category', label: 'Category', cell: catCell, from: 'lg' },
						{ id: 'state', label: 'State', cell: stateCell },
						{ id: 'approval', label: 'Approval', cell: approvalCell, from: 'md' },
						{ id: 'size', label: 'Size', cell: sizeCell, align: 'right', from: 'xl', defaultHidden: true },
						{ id: 'seen', label: 'First seen', cell: seenCell, align: 'right', from: 'lg' }
					] satisfies Column<AgentPatch>[]}
				>
					{#snippet toolbar()}
						<Segmented label="Show" value={show} onchange={(v) => (show = v)} options={[{ value: 'outstanding', label: 'Outstanding', count: outstanding.length }, { value: 'installed', label: 'Installed' }, { value: 'all', label: 'All' }]} />
						<Input icon={Search} data-search placeholder="Filter updates…" aria-label="Filter updates" class="min-w-0 flex-1 sm:w-56 sm:flex-none" bind:value={q} />
						{#if can('technician') && approvedOutstanding.length}
							<Button size="sm" variant="primary" icon={Download} class="sm:ml-auto" disabled={!!running} title={running ? 'An install is already running' : undefined}
								onclick={() => (installing = { ids: null, summary: `${plural(approvedOutstanding.length, 'approved update')} on ${agent.hostname}` })}>
								Install approved
							</Button>
						{/if}
					{/snippet}
					{#snippet bulk(n)}
						{#if can('technician')}
							<Button size="sm" icon={Check} onclick={() => decide('approved', [...selected])}>Approve</Button>
							<Button size="sm" icon={Ban} onclick={() => decide('declined', [...selected])}>Decline</Button>
							<Button size="sm" variant="ghost" icon={RotateCcw} onclick={() => decide('pending', [...selected])} title="Forget the manual decision and let the policy decide">Reset</Button>
							<Button size="sm" variant="primary" icon={Download} disabled={!!running} onclick={installSelected}>Install {n === 1 ? 'it' : 'them'} now</Button>
						{/if}
					{/snippet}
					{#snippet empty()}
						{#if q}
							<EmptyState compact title="No updates match" />
						{:else if show === 'outstanding'}
							<EmptyState compact title={s.scanned_at ? 'Up to date' : 'No scan yet'} description={s.scanned_at ? `Nothing outstanding as of ${ago(s.scanned_at)}.` : 'The agent scans when it connects and every few hours.'} />
						{:else}
							<EmptyState compact title="Nothing installed through scans in the last 30 days" />
						{/if}
					{/snippet}
				</DataTable>

				<section class="card self-start" aria-label="Recent installs">
					<header class="border-border flex items-center justify-between min-h-12 border-b px-4 py-3">
						<h2 class="panel-title">Recent installs</h2>
						<MoreLink href="/patches?tab=history&agent={id}">History</MoreLink>
					</header>
					{#if d.runs.length}
						<ul class="divide-border divide-y">
							{#each d.runs.slice(0, 8) as r (r.id)}
								<li>
									<a href="/patches/runs/{r.id}" class="hover:bg-hover/60 block px-4 py-2 text-sm">
										<div class="flex items-center gap-2">
											<PatchBadge kind="run" value={r.status} />
											{#if r.status === 'sent' && r.percent != null}<span class="text-muted text-xs tabular">{r.percent}%</span>{/if}
											<span class="text-muted ml-auto shrink-0 text-xs">{ago(r.created_at)}</span>
										</div>
										<div class="text-muted mt-0.5 truncate text-xs">{runLine(r)}</div>
										<div class="text-muted text-xs">{r.trigger === 'policy' ? 'Automatic' : (r.created_by_name ?? 'Manual')}</div>
									</a>
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact title="No installs yet" />
					{/if}
				</section>
			</div>
			{#if outstanding.some((p) => p.severity === 'critical' && p.approval !== 'declined')}
				<p class="text-danger mt-3 inline-flex items-center gap-1.5 text-xs"><ShieldAlert class="size-3.5" />Critical updates are outstanding.</p>
			{/if}
		{/if}

		{#if installing}
			<InstallPatches agentIds={[id]} updateIds={installing.ids} summary={installing.summary} allOrNothing={s.all_or_nothing} onclose={() => (installing = null)} ondone={() => { selected = new Set(); res.reload(); }} />
		{/if}
	{/snippet}
</Async>
