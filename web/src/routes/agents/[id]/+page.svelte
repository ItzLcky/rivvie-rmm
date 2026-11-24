<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { BellOff, CloudDownload, Copy, LifeBuoy, MonitorUp, Pencil, Pin, Play, Power, RefreshCw, Search, SquareTerminal, Tag, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime, duration, ms, num, pct } from '#lib/format.js';
	import { liveReload, onLive } from '#lib/live.svelte.js';
	import { forgetAgent, rememberAgent } from '#lib/recent.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentDetail, AuditRow, Job, MetricPoint, Page, Release, Software } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { wake } from '#lib/wake.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';
	import SubNav from '#lib/ui/SubNav.svelte';
	import Chart from '#lib/components/Chart.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import RunScript from '#lib/components/RunScript.svelte';
	import Status from '#lib/components/Status.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import AgentAlerts from '#lib/components/agent/AgentAlerts.svelte';
	import AgentPolicy from '#lib/components/policy/AgentPolicy.svelte';
	import AgentFiles from '#lib/components/agent/AgentFiles.svelte';
	import AgentProcesses from '#lib/components/agent/AgentProcesses.svelte';
	import MuteDialog from '#lib/components/MuteDialog.svelte';
	import AgentLogs from '#lib/components/agent/AgentLogs.svelte';
	import AgentNotes from '#lib/components/agent/AgentNotes.svelte';
	import FieldsCard from '#lib/components/fields/FieldsCard.svelte';
	import TagChip from '#lib/components/tags/TagChip.svelte';
	import TagPicker from '#lib/components/tags/TagPicker.svelte';
	import AgentSecurity from '#lib/components/agent/AgentSecurity.svelte';
	import AgentServices from '#lib/components/agent/AgentServices.svelte';
	import NewTicket from '#lib/components/ticket/NewTicket.svelte';
	import TicketTable from '#lib/components/ticket/TicketTable.svelte';
	import { paged } from '#lib/paged.svelte.js';
	import { actionLabels, productLabels, verdictLabels } from '#lib/security.js';
	import type { ProductKind, SecurityAction, Verdict } from '#lib/types.js';
	import { qs, sortState } from '#lib/url.svelte.js';
	import type { Ticket } from '#lib/types.js';

	const id = $derived(page.params.id!);
	const tab = $derived(param('tab', 'overview'));
	const ranges = { '1h': 1, '24h': 24, '7d': 168, '30d': 720, '90d': 2160 } as const;
	type Range = keyof typeof ranges;
	const range = $derived((param('range', '24h') in ranges ? param('range', '24h') : '24h') as Range);

	const agent = resource(() => api.get<AgentDetail>(`/agents/${id}`), { keep: false });
	const history = resource(() => api.get<MetricPoint[]>(`/agents/${id}/metrics?hours=${ranges[range]}`));
	const recentJobs = resource(() => api.get<Page<Job>>(`/jobs?agent_id=${id}&limit=6`));

	$effect(() => {
		const a = agent.data;
		if (a) rememberAgent(a);
	});

	onLive((e) => {
		if (e.type === 'agent' && e.id === id && agent.data) {
			agent.data.online = e.online;
			if (e.last_metrics) agent.data.last_metrics = e.last_metrics;
		}
	});
	liveReload(() => agent.reload(), (e) => (e.type === 'agent' && e.id === id && !e.last_metrics) || (e.type === 'alert' && e.agent_id === id), { debounceMs: 500, pollMs: 15000 });
	liveReload(() => recentJobs.reload(), (e) => (e.type === 'job' && e.agent_id === id && !e.output) || e.type === 'jobs', { debounceMs: 500 });
	// Metrics charts: refresh every minute, the heartbeat events carry only the latest sample.
	$effect(() => {
		const t = setInterval(() => history.reload(), 60000);
		return () => clearInterval(t);
	});

	const releases = resource(() => (can('admin') ? api.get<{ releases: Release[] }>('/agent-updates').then((r) => r.releases) : Promise.resolve([] as Release[])));
	const release = $derived(agent.data ? releases.data?.find((r) => r.platform === `${agent.data!.os_family}-${agent.data!.arch}`) : undefined);
	const updateLabels: Record<string, string> = {
		offered: 'offered', downloading: 'downloading', waiting: 'waiting for jobs', applying: 'restarting',
		completed: 'updated', rolled_back: 'rolled back', failed: 'failed'
	};

	let running = $state(false);
	let ticketing = $state(false);
	let snoozing = $state(false);
	let tagging = $state(false);
	/** Terminal or desktop opened from a ticket: the session is recorded there. */
	const fromTicket = $derived(param('ticket'));

	const ticketSort = sortState('updated', 'desc');
	const ticketView = $derived(param('tview') === 'all' ? 'all' : 'open');
	const tickets = paged<Ticket>(() => (tab === 'tickets' ? `/tickets${qs({ agent_id: id, view: ticketView, sort: ticketSort.key, dir: ticketSort.dir })}` : '/tickets?limit=1&view=open&agent_id=' + id));
	liveReload(() => tab === 'tickets' && tickets.reload(), (e) => e.type === 'ticket');

	async function update() {
		await attempt(async () => {
			const r = await api.post<{ version: string }>(`/agents/${id}/update`);
			toast.success(`Update to v${r.version} sent. The agent downloads it, waits for running jobs, then restarts.`);
		});
	}
	let waking = $state(false);
	async function wakeAgent() {
		waking = true;
		await wake([id]);
		waking = false;
	}
	async function refreshInventory() {
		await attempt(() => api.post(`/agents/${id}/inventory/refresh`), 'Inventory refresh requested; it updates in a few seconds.');
		setTimeout(() => agent.reload(), 4000);
	}
	async function remove() {
		const a = agent.data!;
		const ok = await confirmAction({
			title: `Remove ${a.hostname}?`,
			message: 'The agent is disconnected and its history deleted. To manage the machine again it must be re-enrolled.',
			confirmLabel: 'Remove agent',
			danger: true,
			typeToConfirm: a.hostname
		});
		if (!ok) return;
		if (await attempt(() => api.del(`/agents/${id}`), `${a.hostname} removed.`)) {
			forgetAgent(id);
			await goto('/agents');
		}
	}

	const cpuSeries = $derived((history.data ?? []).map((p) => ({ t: Date.parse(p.ts), v: p.cpu_percent })));
	const memSeries = $derived((history.data ?? []).map((p) => ({ t: Date.parse(p.ts), v: pct(p.mem_used, p.mem_total) })));
	const diskSeries = $derived((history.data ?? []).map((p) => ({ t: Date.parse(p.ts), v: p.disk_max_pct })));

	// Software: filtered and sorted locally (it's one agent's list).
	let swq = $state('');
	let swSort = $state<{ key: string; dir: 'asc' | 'desc' }>({ key: 'name', dir: 'asc' });
	const swSortState = {
		get key() {
			return swSort.key;
		},
		get dir() {
			return swSort.dir;
		},
		toggle: (k: string) => (swSort = { key: k, dir: swSort.key === k && swSort.dir === 'asc' ? 'desc' : 'asc' })
	};
	const software = $derived.by(() => {
		const q = swq.trim().toLowerCase();
		const list = (agent.data?.inventory?.software ?? []).filter((s) => !q || `${s.name} ${s.publisher ?? ''} ${s.version}`.toLowerCase().includes(q));
		const k = swSort.key as keyof Software;
		const sign = swSort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => sign * String(a[k] ?? '').localeCompare(String(b[k] ?? ''), undefined, { numeric: true, sensitivity: 'base' }));
	});

	const jobs = resource(() => (tab === 'jobs' ? api.get<Page<Job>>(`/jobs?agent_id=${id}&limit=200`) : Promise.resolve(null)));
	const activity = resource(() => (tab === 'activity' ? api.get<AuditRow[]>(`/agents/${id}/activity`) : Promise.resolve(null)));
	liveReload(() => tab === 'jobs' && jobs.reload(), (e) => e.type === 'job' && e.agent_id === id && !e.output);

	function describe(r: AuditRow): string {
		const d = r.details as Record<string, string>;
		const rp = (r.details.params ?? {}) as { pid?: number; tree?: boolean; path?: string; allow?: string[] };
		const fromDetection = r.details.detection ? ' (from a detection)' : '';
		const labels: Record<string, string> = {
			'agent.delete': 'Removed the agent',
			'agent.update_offer': `Offered update to v${d.version}`,
			'agent.update_completed': `Updated to v${d.version}`,
			'agent.update_rolled_back': `Update to v${d.version} rolled back${d.detail ? `: ${d.detail}` : ''}`,
			'agent.update_failed': `Update to v${d.version} failed${d.detail ? `: ${d.detail}` : ''}`,
			'service.start': `Started ${d.service}${d.ok ? '' : ` (failed: ${d.message})`}`,
			'service.stop': `Stopped ${d.service}${d.ok ? '' : ` (failed: ${d.message})`}`,
			'service.restart': `Restarted ${d.service}${d.ok ? '' : ` (failed: ${d.message})`}`,
			'agent.patch_install': `Started installing ${d.updates} update${Number(d.updates) === 1 ? '' : 's'}`,
			'agent.patch_cancel': 'Cancelled a queued install',
			'agent.process_kill': `${d.ok ? 'Killed' : 'Tried to kill'} ${d.name ? `${d.name} (${r.details.pid})` : `process ${r.details.pid}`}${r.details.tree ? ' and its children' : ''}${d.ok ? '' : `: ${d.message}`}`,
			'agent.file_download': `Downloaded ${d.path}`,
			'agent.file_upload': `${d.ok ? 'Uploaded' : 'Failed to upload'} ${d.path}${d.ok ? '' : `: ${d.error}`}`,
			'alert.mute': r.details.ends_at ? `Snoozed alerts until ${datetime(String(r.details.ends_at))}${d.reason ? ` (${d.reason})` : ''}` : `Added an alert maintenance window${d.reason ? ` (${d.reason})` : ''}`,
			'alert.unmute': 'Ended an alert snooze or maintenance window',
			'policy.exclude_agent': `Left out of the policy ${d.name}`,
			'policy.include_agent': `Covered by the policy ${d.name} again`,
			'agent.tags': `Changed tags${Array.isArray(r.details.added) && r.details.added.length ? `, added ${(r.details.added as string[]).join(', ')}` : ''}${Array.isArray(r.details.removed) && r.details.removed.length ? `, removed ${(r.details.removed as string[]).join(', ')}` : ''}`,
			'agent.tags_bulk': 'Changed tags together with other agents',
			'agent.fields': `Changed ${Object.keys(r.details).join(', ')}`,
			'agent.field_script': `A script set ${((r.details.set as { name: string }[] | undefined) ?? []).map((f) => f.name).join(', ') || 'no fields'}${((r.details.refused as unknown[] | undefined) ?? []).length ? ` (${(r.details.refused as unknown[]).length} refused)` : ''}`,
			'agent.note_create': 'Added a note',
			'agent.note_update': r.details.edited ? 'Edited a note' : r.details.pinned ? 'Pinned a note' : 'Unpinned a note',
			'agent.note_delete': 'Deleted a note',
			'agent.policy_pin': d.policy_set_id ? 'Pinned a policy set' : 'Unpinned its policy set',
			'agent.policy_customize': 'Customized its policies (a set of its own, pinned)',
			'security.quick_scan': `Started a quick scan (${productLabels[d.product as ProductKind] ?? d.product})`,
			'security.full_scan': `Started a full scan (${productLabels[d.product as ProductKind] ?? d.product})`,
			'security.update_signatures': `Started a signature update (${productLabels[d.product as ProductKind] ?? d.product})`,
			'security.succeeded': `${actionLabels[d.action as SecurityAction] ?? d.action} finished${d.message ? `: ${d.message}` : ''}`,
			'security.failed': `${actionLabels[d.action as SecurityAction] ?? d.action} failed${d.message ? `: ${d.message}` : ''}`,
			'security.kill_process': `Killed process ${rp.pid ?? ''}${rp.tree ? ' and its children' : ''}${fromDetection}`,
			'security.quarantine_file': `Quarantined ${rp.path ?? 'a file'}${fromDetection}`,
			'security.restore_file': `Restored a file from quarantine${fromDetection}`,
			'security.delete_quarantined': 'Deleted a quarantined file permanently',
			'security.isolate': `Isolated the machine from the network${Array.isArray(rp.allow) && rp.allow.length ? ` (also allowing ${rp.allow.join(', ')})` : ''}${fromDetection}`,
			'security.release': 'Released the machine from network isolation',
			'security.collect_triage': `Started collecting a triage package${fromDetection}`,
			'security.scan_path': `Started a scan of ${rp.path ?? 'a path'}`,
			'security.triage_download': 'Downloaded a triage package',
			'security.verdict': r.details.verdict ? `Marked a detection as ${verdictLabels[r.details.verdict as Verdict]?.toLowerCase() ?? r.details.verdict}` : 'Reopened a detection',
			'agent.patch_result': `Install ${d.status === 'succeeded' ? 'succeeded' : d.status === 'partial' ? 'partly failed' : 'failed'}: ${d.installed} of ${d.requested} installed${d.rebooting ? ', restarting' : ''}${d.error ? ` (${d.error})` : ''}`
		};
		return labels[r.action] ?? r.action;
	}

	// Loaded with its tab.
	const patches = $derived(tab === 'patches' ? import('#lib/components/AgentPatches.svelte') : null);
	const deployments = $derived(tab === 'deployments' ? import('#lib/components/AgentDeployments.svelte') : null);
	// The terminal (xterm.js) loads only when its tab opens.
	const terminal = $derived(tab === 'terminal' ? import('#lib/components/Terminal.svelte') : null);
	const desktop = $derived(tab === 'desktop' ? import('#lib/components/RemoteDesktop.svelte') : null);
	/** Why remote desktop can't start, if it can't. */
	function desktopBlocked(a: AgentDetail): string | undefined {
		if (!a.capabilities?.includes('desktop')) return 'This agent version doesn’t support remote desktop; update the agent';
		if (!a.online) return 'The agent is offline';
	}
</script>

<svelte:head>{#if agent.data}<title>{agent.data.hostname}</title>{/if}</svelte:head>

<Async res={agent}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
		<Skeleton class="mb-4 h-9 w-full" />
		<div class="grid gap-4 lg:grid-cols-[20rem_1fr]"><div class="card space-y-2 p-4"><Skeleton lines={8} /></div><div class="card space-y-2 p-4"><Skeleton class="h-40 w-full" /></div></div>
	{/snippet}
	{#snippet children(a)}
		{@const m = a.last_metrics}
		{@const inv = a.inventory}
		<PageHeader
			title={a.hostname}
			crumbs={[{ label: 'Clients', href: '/clients' }, { label: a.client_name, href: `/clients/${a.client_id}` }, { label: a.site_name, href: `/agents?client=${a.client_id}&site=${a.site_id}` }, { label: a.hostname }]}
			menu={[
				...(can('technician') ? [{ label: 'New ticket for this agent', icon: LifeBuoy, onSelect: () => (ticketing = true) }] : []),
				...(can('technician') ? [{ label: 'Refresh inventory', icon: RefreshCw, onSelect: refreshInventory, disabled: !a.online }] : []),
				...(can('technician') ? [{ label: 'Snooze alerts…', icon: BellOff, onSelect: () => (snoozing = true) }] : []),
				...(can('technician') ? [{ label: 'Edit tags…', icon: Tag, onSelect: () => (tagging = true) }] : []),
				...(can('admin') && release && release.version !== a.agent_version ? [{ label: `Update agent to v${release.version}`, icon: CloudDownload, onSelect: update, disabled: !a.online }] : []),
				{ label: 'Copy agent ID', icon: Copy, onSelect: () => navigator.clipboard?.writeText(a.id).then(() => toast.success('Agent ID copied.')) },
				...(can('admin') ? [{ separator: true } as const, { label: 'Remove agent…', icon: Trash2, onSelect: remove, danger: true }] : [])
			]}
		>
			{#snippet subtitle()}
				<Status online={a.online} size="md" />
				<HealthBadge health={a.health} agent={a} />
				<OsBadge os={a.os_family} name={a.os_version || a.os_name} />
				{#if a.alerts_muted}<Badge tone="neutral" icon={BellOff} title="A maintenance window or snooze is holding this agent's alerts back">Alerts muted</Badge>{/if}
				<span>{a.client_name} › {a.site_name}</span>
				{#each a.tags ?? [] as t (t.id)}<TagChip name={t.name} color={t.color} href="/agents?tag={t.id}" />{/each}
			{/snippet}
			{#snippet actions()}
				{#if can('technician')}
					{#if !a.online}<Button icon={Power} loading={waking} onclick={wakeAgent} title="Send a Wake-on-LAN packet through another online agent at the site">Wake</Button>{/if}
					<Button icon={SquareTerminal} disabled={!a.online} onclick={() => setParams({ tab: 'terminal' })} title={a.online ? undefined : 'The agent is offline'}>Terminal</Button>
					<Button icon={MonitorUp} class="max-sm:hidden" disabled={!!desktopBlocked(a)} onclick={() => setParams({ tab: 'desktop' })} title={desktopBlocked(a)}>Remote desktop</Button>
					<Button variant="primary" icon={Play} onclick={() => (running = true)}>Run script</Button>
				{/if}
			{/snippet}
		</PageHeader>

		{#if a.pinned_note}
			<aside class="card border-accent/40 mb-4 flex items-start gap-3 p-3 text-sm" aria-label="Pinned note">
				<Pin class="text-accent mt-0.5 size-4 shrink-0" />
				<div class="min-w-0 flex-1">
					<p class="break-words whitespace-pre-wrap">{a.pinned_note.body}</p>
					<p class="text-muted mt-1 text-xs">{a.pinned_note.author_name} · {ago(a.pinned_note.created_at)} · <a class="link" href="?tab=notes">All notes</a></p>
				</div>
			</aside>
		{/if}

		<div class="lg:grid lg:grid-cols-[11rem_minmax(0,1fr)] lg:gap-6">
		<SubNav
			label="Agent sections"
			class="mb-4 lg:sticky lg:top-4 lg:mb-0 lg:self-start"
			value={tab}
			first="overview"
			onchange={(v) => setParams({ tab: v === 'overview' ? null : v }, { push: true })}
			groups={[
				{ items: [
					{ value: 'overview', label: 'Overview' },
					{ value: 'alerts', label: 'Alerts', count: a.open_alerts ? num(a.open_alerts) : undefined },
					{ value: 'tickets', label: 'Tickets' },
					{ value: 'notes', label: 'Notes' },
					{ value: 'activity', label: 'Activity' }
				] },
				{ label: 'Inventory', items: [
					{ value: 'inventory', label: 'Hardware & network' },
					{ value: 'software', label: 'Software', count: inv ? num(inv.software.length) : undefined }
				] },
				{ label: 'Monitoring', items: [
					{ value: 'services', label: 'Services' },
					{ value: 'processes', label: 'Processes', hidden: !can('technician') },
					{ value: 'logs', label: 'Event log' }
				] },
				{ label: 'Management', items: [
					{ value: 'policy', label: 'Policy' },
					{ value: 'patches', label: 'Patches', count: a.patches_overdue || a.patches_failed ? num(a.patches_overdue + a.patches_failed) : undefined, title: a.patches_overdue || a.patches_failed ? 'Overdue security updates and failed installs' : undefined },
					{ value: 'deployments', label: 'Deployments' },
					{ value: 'security', label: 'Security' },
					{ value: 'jobs', label: 'Jobs' },
					{ value: 'files', label: 'Files', hidden: !can('technician') }
				] },
				{ label: 'Remote', items: [
					{ value: 'terminal', label: 'Terminal', hidden: !can('technician') },
					{ value: 'desktop', label: 'Remote desktop', hidden: !can('technician') }
				] }
			]}
		/>
		<div class="min-w-0">

		{#if tab === 'overview'}
			<div class="grid gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
				<div class="min-w-0 space-y-4 self-start">
				<section class="card p-4" aria-label="System">
					<h2 class="mb-3 panel-title">System</h2>
					<dl class="dl">
						<dt>Client</dt><dd><a class="link" href="/clients/{a.client_id}">{a.client_name}</a><span class="text-subtle mx-1" aria-hidden="true">›</span>{a.site_name}</dd>
						{#if a.policy_set_name}<dt>Policy</dt><dd><a class="link" href="?tab=policy">{a.policy_set_name}</a><span class="text-muted block text-xs">{a.category_name}</span></dd>{/if}
						<dt>OS</dt><dd>{a.os_version || a.os_name}</dd>
						<dt>Kernel</dt><dd class="font-mono text-[13px]">{a.kernel_version || '–'}</dd>
						<dt>Arch</dt><dd>{a.arch}</dd>
						<dt>CPU</dt><dd>{inv?.cpu_brand ?? '–'}{#if inv}<span class="text-muted block text-xs">{inv.cpu_cores_physical ?? '?'} cores, {inv.cpu_cores_logical} threads</span>{/if}</dd>
						<dt>Memory</dt><dd>{bytes(inv?.mem_total ?? m?.mem_total)}</dd>
						<dt>Uptime</dt><dd>{m ? duration(m.uptime_secs) : '–'}</dd>
						<dt>Signed in</dt><dd>{inv?.logged_in_users.join(', ') || '–'}</dd>
						<dt>Last seen</dt><dd>{a.online ? 'now' : ago(a.last_seen_at)}</dd>
						<dt>Enrolled</dt><dd>{datetime(a.enrolled_at)}</dd>
						<dt>Agent</dt>
						<dd>
							<span class="font-mono text-[13px]">v{a.agent_version}</span>
							{#if (a.update_state && a.update_version && a.update_version !== a.agent_version) || a.update_state === 'rolled_back' || a.update_state === 'failed'}
								<Badge tone={a.update_state === 'failed' || a.update_state === 'rolled_back' ? 'danger' : 'info'} title={a.update_detail ?? ''}>
									v{a.update_version}: {updateLabels[a.update_state ?? ''] ?? a.update_state}
								</Badge>
								{#if (a.update_state === 'failed' || a.update_state === 'rolled_back') && a.update_detail}
									<p class="text-muted mt-1 text-[13px] break-words">{a.update_detail}</p>
								{/if}
							{/if}
						</dd>
						<dt>Agent ID</dt><dd class="text-muted font-mono text-[13px] break-all">{a.id}</dd>
						<dt>Tags</dt>
						<dd class="flex flex-wrap items-center gap-1">
							{#each a.tags ?? [] as t (t.id)}<TagChip name={t.name} color={t.color} href="/agents?tag={t.id}" />{:else}<span class="text-muted">–</span>{/each}
							{#if can('technician')}<button class="text-muted hover:text-fg ml-1 cursor-pointer" aria-label="Edit tags" onclick={() => (tagging = true)}><Pencil class="size-3.5" /></button>{/if}
						</dd>
					</dl>
				</section>
				{#key a.id}<FieldsCard entity="agent" id={a.id} />{/key}
				</div>

				<div class="min-w-0 space-y-4">
					<section class="card p-4" aria-label="Performance">
						<div class="mb-3 flex flex-wrap items-center justify-between gap-2">
							<h2 class="panel-title">Performance</h2>
							<Segmented label="Time range" value={range} onchange={(v) => setParams({ range: v === '24h' ? null : v })} options={Object.keys(ranges).map((r) => ({ value: r as Range, label: r }))} />
						</div>
						{#if m}
							<div class="mb-4 grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-4">
								<div><div class="label text-muted">CPU</div><UsageBar value={a.online ? m.cpu_percent : 0} /></div>
								<div><div class="label text-muted">Memory <span class="font-normal">{bytes(m.mem_used)} / {bytes(m.mem_total)}</span></div><UsageBar value={pct(m.mem_used, m.mem_total)} /></div>
								<div><div class="label text-muted">Swap</div><UsageBar value={pct(m.swap_used, m.swap_total)} /></div>
								<div><div class="label text-muted">Load · processes</div><span class="text-sm tabular">{m.load_avg ? m.load_avg.map((l) => l.toFixed(2)).join(' ') : '–'} · {m.process_count}</span></div>
							</div>
						{/if}
						<div class="space-y-4" aria-busy={history.busy}>
							<Chart label="CPU" points={cpuSeries} />
							<Chart label="Memory" points={memSeries} />
							<Chart label="Fullest disk" points={diskSeries} />
						</div>
					</section>

					<div class="grid gap-4 xl:grid-cols-2">
						<section class="card" aria-label="Recent jobs">
							<header class="border-border flex items-center justify-between min-h-12 border-b px-4 py-3">
								<h2 class="panel-title">Recent jobs</h2>
								<MoreLink onclick={() => setParams({ tab: 'jobs' }, { push: true })}>All jobs</MoreLink>
							</header>
							{#if recentJobs.data?.items.length}
								<ul class="divide-border divide-y">
									{#each recentJobs.data.items as j (j.id)}
										<li>
											<a href="/jobs/{j.id}" class="hover:bg-hover/60 flex items-center gap-3 px-4 py-2 text-sm">
												<JobBadge status={j.status} />
												<span class="min-w-0 flex-1 truncate">{j.script_name ?? `Ad-hoc ${j.interpreter}`}</span>
												<span class="text-muted shrink-0 text-xs">{ago(j.created_at)}</span>
											</a>
										</li>
									{/each}
								</ul>
							{:else if recentJobs.loading}
								<div class="space-y-2 p-4"><Skeleton lines={3} /></div>
							{:else}
								<EmptyState compact title="No jobs yet" />
							{/if}
						</section>
						<section class="card" aria-label="Volumes">
							<header class="border-border min-h-12 border-b px-4 py-3"><h2 class="panel-title">Volumes</h2></header>
							{#if m?.disks.length}
								<ul class="divide-border divide-y">
									{#each m.disks as d (d.mount)}
										<li class="grid grid-cols-[minmax(0,1fr)_9rem] items-center gap-3 px-4 py-2 text-sm">
											<div class="min-w-0"><div class="truncate font-mono text-xs">{d.mount}</div><div class="text-muted text-xs">{bytes(d.available)} free of {bytes(d.total)}</div></div>
											<UsageBar value={pct(d.total - d.available, d.total)} />
										</li>
									{/each}
								</ul>
							{:else}
								<EmptyState compact title="No volume data yet" />
							{/if}
						</section>
					</div>
				</div>
			</div>
		{:else if tab === 'inventory'}
			<div class="mb-3 flex items-center gap-3">
				<span class="text-muted text-xs">Collected {ago(a.inventory_at)}</span>
				{#if can('technician')}<Button size="sm" icon={RefreshCw} class="ml-auto" disabled={!a.online} onclick={refreshInventory}>Refresh</Button>{/if}
			</div>
			<div class="grid gap-4 xl:grid-cols-2">
				<section class="card overflow-x-auto" aria-label="Disks">
					<header class="border-border min-h-12 border-b px-4 py-3"><h2 class="panel-title">Disks</h2></header>
					<table class="table">
						<thead><tr><th>Device</th><th>Mount</th><th>FS</th><th>Type</th><th class="text-right">Size</th></tr></thead>
						<tbody>
							{#each inv?.disks ?? [] as d (d.mount)}
								<tr><td class="font-mono text-xs">{d.name}</td><td class="font-mono text-xs">{d.mount}</td><td>{d.fs}</td><td>{d.kind}{d.removable ? ' (removable)' : ''}</td><td class="text-right tabular">{bytes(d.total)}</td></tr>
							{:else}
								<tr><td colspan="5" class="text-muted py-6 text-center">No inventory yet.</td></tr>
							{/each}
						</tbody>
					</table>
				</section>
				<section class="card overflow-x-auto" aria-label="Network interfaces">
					<header class="border-border min-h-12 border-b px-4 py-3"><h2 class="panel-title">Network interfaces</h2></header>
					<table class="table">
						<thead><tr><th>Name</th><th>MAC</th><th>Addresses</th></tr></thead>
						<tbody>
							{#each inv?.network ?? [] as n (n.name)}
								<tr><td>{n.name}</td><td class="font-mono text-xs">{n.mac}</td><td class="font-mono text-xs">{n.addrs.join(', ')}</td></tr>
							{:else}
								<tr><td colspan="3" class="text-muted py-6 text-center">No inventory yet.</td></tr>
							{/each}
						</tbody>
					</table>
				</section>
			</div>
		{:else if tab === 'software'}
			{#snippet nameCell(s: Software)}<span class="font-medium">{s.name}</span>{/snippet}
			{#snippet versionCell(s: Software)}<span class="font-mono text-xs">{s.version}</span>{/snippet}
			{#snippet publisherCell(s: Software)}<span class="text-muted">{s.publisher ?? ''}</span>{/snippet}
			{#snippet sourceCell(s: Software)}<span class="text-muted text-xs">{s.source}</span>{/snippet}
			<DataTable
				id="software"
				caption="Installed software"
				rows={software.slice(0, 2000)}
				key={(s) => `${s.source}|${s.name}|${s.version}`}
				sort={swSortState}
				columns={[
					{ id: 'name', label: 'Name', sort: 'name', cell: nameCell, hideable: false },
					{ id: 'version', label: 'Version', sort: 'version', cell: versionCell },
					{ id: 'publisher', label: 'Publisher', sort: 'publisher', cell: publisherCell, from: 'md' },
					{ id: 'source', label: 'Source', sort: 'source', cell: sourceCell, from: 'sm' }
				] satisfies Column<Software>[]}
			>
				{#snippet toolbar()}
					<Input icon={Search} data-search placeholder="Filter software…" aria-label="Filter software" class="w-full sm:w-72" bind:value={swq} />
					<span class="text-muted text-xs">{num(software.length)} packages · collected {ago(a.inventory_at)}</span>
				{/snippet}
				{#snippet empty()}<EmptyState compact title={swq ? 'No packages match' : 'No software inventory yet'} />{/snippet}
				{#snippet footer()}{#if software.length > 2000}<p class="text-muted px-3 py-2 text-xs">Showing 2,000 of {num(software.length)}; refine the filter.</p>{/if}{/snippet}
			</DataTable>
		{:else if tab === 'patches'}
			{#if patches}
				{#await patches}
					<div class="card flex h-40 items-center justify-center" aria-busy="true"><Spinner label="Loading" /></div>
				{:then P}
					<P.default agent={a} />
				{/await}
			{/if}
		{:else if tab === 'deployments'}
			{#if deployments}
				{#await deployments}
					<div class="card flex h-40 items-center justify-center" aria-busy="true"><Spinner label="Loading" /></div>
				{:then P}
					<P.default agent={a} />
				{/await}
			{/if}
		{:else if tab === 'jobs'}
			{#snippet startedCell(j: Job)}<a class="hover:text-accent" href="/jobs/{j.id}">{datetime(j.created_at)}</a>{/snippet}
			{#snippet scriptCell(j: Job)}{j.script_name ?? `Ad-hoc ${j.interpreter}`}{/snippet}
			{#snippet statusCell(j: Job)}<JobBadge status={j.status} />{/snippet}
			{#snippet exitCell(j: Job)}{#if j.exit_code != null}{j.exit_code}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
			{#snippet durCell(j: Job)}{#if j.duration_ms != null}{ms(j.duration_ms)}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
			{#snippet byCell(j: Job)}<span class="text-muted">{j.created_by_name ?? '–'}</span>{/snippet}
			<DataTable
				id="agent-jobs"
				caption="Jobs on this agent"
				rows={jobs.data?.items ?? []}
				key={(j) => j.id}
				loading={jobs.loading}
				rowHref={(j) => `/jobs/${j.id}`}
				scroll={false}
				columns={[
					{ id: 'created', label: 'Started', cell: startedCell, hideable: false },
					{ id: 'script', label: 'Script', cell: scriptCell },
					{ id: 'status', label: 'Status', cell: statusCell },
					{ id: 'exit', label: 'Exit', cell: exitCell, align: 'right', from: 'sm' },
					{ id: 'duration', label: 'Duration', cell: durCell, align: 'right', from: 'sm' },
					{ id: 'by', label: 'By', cell: byCell, from: 'md' }
				] satisfies Column<Job>[]}
			>
				{#snippet empty()}<EmptyState compact title="No jobs on this agent yet" />{/snippet}
				{#snippet footer()}{#if jobs.data?.next}<p class="text-muted px-3 py-2 text-xs">Showing the latest 200. <a class="link" href="/jobs?q={encodeURIComponent(a.hostname)}">See all in Jobs</a></p>{/if}{/snippet}
			</DataTable>
		{:else if tab === 'policy'}
			<AgentPolicy agent={a} onchange={() => agent.reload()} />
		{:else if tab === 'notes'}
			<AgentNotes agentId={a.id} onchange={() => agent.reload()} />
		{:else if tab === 'alerts'}
			<AgentAlerts agentId={a.id} hostname={a.hostname} onchange={() => agent.reload()} />
		{:else if tab === 'processes'}
			<AgentProcesses agent={a} />
		{:else if tab === 'files'}
			<AgentFiles agent={a} />
		{:else if tab === 'tickets'}
			<TicketTable id="agent-tickets" caption="Tickets about {a.hostname}" list={tickets} sort={ticketSort} hide={['client']}>
				{#snippet toolbar()}
					<Segmented label="Tickets" value={ticketView} onchange={(v) => setParams({ tview: v === 'open' ? null : v })} options={[{ value: 'open', label: 'Open' }, { value: 'all', label: 'All' }]} />
					{#if can('technician')}<Button size="sm" icon={LifeBuoy} class="ml-auto" onclick={() => (ticketing = true)}>New ticket</Button>{/if}
				{/snippet}
				{#snippet empty()}<EmptyState compact title={ticketView === 'open' ? 'No open tickets about this agent' : 'No tickets about this agent'} description="Tickets list the agents they're about; alert tickets link theirs automatically." />{/snippet}
			</TicketTable>
		{:else if tab === 'security'}
			<AgentSecurity agentId={a.id} hostname={a.hostname} os={a.os_family} />
		{:else if tab === 'services'}
			<AgentServices agentId={a.id} online={a.online} hostname={a.hostname} />
		{:else if tab === 'logs'}
			<AgentLogs agentId={a.id} />
		{:else if tab === 'activity'}
			<section class="card" aria-label="Activity">
				<Async res={activity} compact>
					{#snippet children(rows)}
						{#if rows?.length}
							<ol class="divide-border divide-y">
								{#each rows as r (r.id)}
									<li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-4 py-2.5 text-sm">
										<span class="min-w-0 flex-1">{describe(r)}</span>
										<span class="text-muted text-xs">{r.user_name ?? 'System'} · <time datetime={r.ts} title={datetime(r.ts)}>{ago(r.ts)}</time></span>
									</li>
								{/each}
							</ol>
						{:else}
							<EmptyState compact title="No activity recorded yet" description="Agent updates, patch installs, antivirus scans, and service starts and stops show up here. Jobs have their own tab." />
						{/if}
					{/snippet}
				</Async>
			</section>
		{:else if tab === 'terminal'}
			{#if fromTicket}<p class="text-muted mb-2 text-xs">Opened from a <a class="link" href="/tickets/{fromTicket}">ticket</a>: the session's start and end are added to it.</p>{/if}
			{#if !a.online}
				<div class="card"><EmptyState title="The agent is offline" description="The terminal opens once the agent reconnects." /></div>
			{:else if terminal}
				{#await terminal}
					<div class="card flex h-64 items-center justify-center"><Spinner label="Loading terminal" /></div>
				{:then T}
					<T.default agentId={a.id} hostname={a.hostname} ticketId={fromTicket || undefined} />
				{/await}
			{/if}
		{:else if tab === 'desktop'}
			{#if fromTicket}<p class="text-muted mb-2 text-xs">Opened from a <a class="link" href="/tickets/{fromTicket}">ticket</a>: the session's start and end are added to it.</p>{/if}
			{#if !a.capabilities?.includes('desktop')}
				<div class="card">
					<EmptyState icon={MonitorUp} title="Remote desktop needs a newer agent" description="This agent's version (v{a.agent_version}) can't share its screen. Update the agent, then reopen this tab." />
				</div>
			{:else if !a.online}
				<div class="card"><EmptyState icon={MonitorUp} title="The agent is offline" description="Remote desktop opens once the agent reconnects." /></div>
			{:else if desktop}
				{#await desktop}
					<div class="card flex h-64 items-center justify-center"><Spinner label="Loading remote desktop" /></div>
				{:then D}
					{#key a.id}<D.default agentId={a.id} hostname={a.hostname} ticketId={fromTicket || undefined} />{/key}
				{/await}
			{/if}
		{/if}

		</div>
		</div>

		{#if tagging}<TagPicker agentId={a.id} hostname={a.hostname} current={a.tags ?? []} onclose={() => (tagging = false)} ondone={() => agent.reload()} />{/if}
		{#if running}<RunScript agents={[a]} onclose={() => (running = false)} />{/if}
		{#if snoozing}<MuteDialog target={{ agent_id: a.id, name: a.hostname }} onclose={() => (snoozing = false)} onsaved={() => agent.reload()} />{/if}
		{#if ticketing}<NewTicket onclose={() => (ticketing = false)} initial={{ clientId: a.client_id, agents: [a] }} />{/if}
	{/snippet}
</Async>
