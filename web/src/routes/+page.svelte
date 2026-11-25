<script lang="ts">
	import { BellRing, CircleSlash, HardDrive, ListX, Plus, Stethoscope, WifiOff } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, num, osLabels, pct } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { Dashboard, Job } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import OsIcon from '#lib/components/OsIcon.svelte';
	import VulnStrip from '#lib/components/vulns/VulnStrip.svelte';

	const res = resource(() => api.get<Dashboard>(`/dashboard${qs({ client_id: clientId() })}`));
	liveReload(() => res.reload(), (e) => e.type === 'jobs' || e.type === 'alert' || (e.type === 'job' && !e.output) || (e.type === 'agent' && !e.last_metrics), {
		debounceMs: 1500,
		pollMs: 20000
	});

	const scoped = $derived(currentClient());
	const link = (path: string) => withClient(path);
	const failedCount = (d: Dashboard) => (['failed', 'error', 'timed_out', 'lost'] as const).reduce((n, s) => n + (d.jobs_24h[s] ?? 0), 0);

	/** One feed of what needs a look, worst first: open alerts, full disks, failed jobs, then offline agents. */
	type Item = { key: string; kind: string; tone: 'danger' | 'warning' | 'info' | 'neutral'; href: string; title: string; where: string; when: string };
	const sevTone = { critical: 'danger', warning: 'warning', info: 'info' } as const;
	const openAlerts = (d: Dashboard) => (d.alerts.critical ?? 0) + (d.alerts.warning ?? 0) + (d.alerts.info ?? 0);
	function feed(d: Dashboard): Item[] {
		const alerts: Item[] = d.open_alerts.map((a) => ({ key: `a-${a.id}`, kind: a.severity === 'critical' ? 'Critical' : a.severity === 'warning' ? 'Warning' : 'Info', tone: sevTone[a.severity], href: `/alerts/${a.id}`, title: a.hostname ? `${a.hostname}: ${a.title}` : a.title, where: a.client_name, when: ago(a.opened_at) }));
		const disks: Item[] = d.high_disk.map((a) => ({ key: `d-${a.id}`, kind: `Disk ${a.disk_max_pct.toFixed(0)}%`, tone: 'danger', href: `/agents/${a.id}`, title: a.hostname, where: a.client_name, when: a.online ? 'now' : ago(a.last_seen_at) }));
		const jobs: Item[] = d.failed_jobs.map((j: Job) => ({ key: `j-${j.id}`, kind: j.status === 'failed' || j.status === 'error' ? 'Job failed' : j.status === 'timed_out' ? 'Job timed out' : 'Job lost', tone: j.status === 'failed' || j.status === 'error' ? 'danger' : 'warning', href: `/jobs/${j.id}`, title: j.script_name ?? `Ad-hoc ${j.interpreter}`, where: j.hostname, when: ago(j.created_at) }));
		const off: Item[] = d.offline.map((a) => ({ key: `o-${a.id}`, kind: 'Offline', tone: 'neutral', href: `/agents/${a.id}`, title: a.hostname, where: `${a.client_name} › ${a.site_name}`, when: ago(a.last_seen_at) }));
		// An alert usually says the same as the disk or job row; keep the alert.
		const alerted = new Set(d.open_alerts.map((a) => `${a.kind}:${a.agent_id}`));
		return [...alerts, ...disks.filter((x) => !alerted.has(`disk:${x.key.slice(2)}`)), ...jobs, ...off.filter((x) => !alerted.has(`offline:${x.key.slice(2)}`))];
	}
	import OnCallChip from '#lib/oncall/OnCallChip.svelte';
</script>

<PageHeader
	title={scoped ? scoped.name : 'Dashboard'}
	description={scoped ? 'Dashboard for this client. Pick “All clients” at the top to see everything.' : 'Fleet health across every client, worst first.'}
/>

<div class="mb-4"><OnCallChip /></div>

<Async {res}>
	{#snippet skeleton()}
		<div class="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
			{#each Array(5) as _, i (i)}<div class="card space-y-4 p-4"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-16" /></div>{/each}
		</div>
		<div class="mt-6 grid gap-6 xl:grid-cols-[3fr_2fr]">
			<div class="card space-y-3 p-4"><Skeleton class="h-4 w-40" /><Skeleton lines={5} /></div>
			<div class="card space-y-3 p-4"><Skeleton class="h-4 w-32" /><Skeleton lines={5} /></div>
		</div>
	{/snippet}
	{#snippet children(d)}
		{#if d.agents_total === 0}
			<div class="card">
				<EmptyState title="No agents yet" description="Enroll your first machine: create a client, then copy the install command for one of its sites.">
					{#snippet action()}
						{#if can('technician')}<Button variant="primary" icon={Plus} href={link('/clients')}>Enroll agents</Button>{/if}
					{/snippet}
				</EmptyState>
			</div>
		{:else}
			<!-- Every number links to the matching filtered list. -->
			<section aria-label="Needs attention" class="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
				<Stat label="Open alerts" icon={BellRing} value={openAlerts(d)} tone={d.alerts.critical ? 'danger' : 'warning'} href={link('/alerts')} />
				<Stat label="Offline" icon={WifiOff} value={d.agents_total - d.agents_online} of={d.agents_total} tone="warning" href={link('/agents?view=offline')} />
				<Stat label="Need attention" icon={Stethoscope} value={(d.health.attention ?? 0) + (d.health.unhealthy ?? 0)} tone={(d.health.unhealthy ?? 0) ? 'danger' : 'warning'} href={link('/agents?view=attention')} />
				<Stat label="Failed jobs (24 h)" icon={CircleSlash} value={failedCount(d)} tone="danger" href={link('/jobs?status=failed')} />
				<Stat label="Disks over 90%" icon={HardDrive} value={d.high_disk.length} capped={d.high_disk.length >= 10} tone="danger" href={link('/agents?sort=disk&dir=desc')} />
			</section>
			<VulnStrip clientId={clientId()} class="mt-4" />

			{@const items = feed(d)}
			<div class="mt-6 grid items-start gap-6 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
				<section class="card" aria-label="Problems">
					<header class="panel-head">
						<h2 class="panel-title">Needs a look</h2>
						{#if items.length}<span class="text-muted text-xs tabular">{num(items.length)} {items.length === 1 ? 'item' : 'items'}</span>{/if}
					</header>
					{#if items.length}
						<ul class="divide-border divide-y">
							{#each items as it (it.key)}
								<li>
									<a href={it.href} class="hover:bg-hover/60 flex items-center gap-3 px-4 py-2.5 text-sm transition-colors">
										<span class="w-28 shrink-0"><Badge tone={it.tone}>{it.kind}</Badge></span>
										<span class="min-w-0 flex-1 truncate font-medium">{it.title}</span>
										<span class="text-muted hidden max-w-48 truncate sm:block">{it.where}</span>
										<span class="text-muted w-16 shrink-0 text-right tabular">{it.when}</span>
									</a>
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact icon={ListX} title="Nothing needs attention" description="No open alerts, every agent is online, no disk is over 90% and no job failed in the last day." />
					{/if}
				</section>

				<div class="space-y-6">
					{#if !scoped && d.client_health.length}
						<section class="card">
							<header class="panel-head">
								<h2 class="panel-title">Clients</h2>
								<MoreLink href="/clients">All clients</MoreLink>
							</header>
							<table class="w-full text-sm">
								<thead class="bg-sunken text-muted text-xs">
									<tr>
										<th scope="col" class="px-4 py-2 text-left font-semibold">Client</th>
										<th scope="col" class="w-14 py-2 text-right font-semibold">Agents</th>
										<th scope="col" class="w-14 py-2 text-right font-semibold">Offline</th>
										<th scope="col" class="w-20 py-2 text-right font-semibold">Attention</th>
										<th scope="col" class="w-24 py-2 pr-4 text-right font-semibold">Unhealthy</th>
									</tr>
								</thead>
								<tbody class="divide-border divide-y border-t border-border">
									{#each d.client_health as c (c.id)}
										{@const off = c.agents - c.online}
										<tr>
											<td class="max-w-0 truncate px-4 py-2.5 font-medium"><a href={withClient('/', c.id)} class="hover:text-accent">{c.name}</a></td>
											<td class="text-muted py-2.5 text-right tabular">{c.agents || '–'}</td>
											<td class="py-2.5 text-right tabular">{#if off}<a class="hover:underline" href={withClient('/agents?view=offline', c.id)}>{off}</a>{:else}<span class="text-muted">–</span>{/if}</td>
											<td class="py-2.5 text-right tabular">{#if c.attention}<a class="text-warning font-medium hover:underline" href={withClient('/agents?health=attention', c.id)}>{c.attention}</a>{:else}<span class="text-muted">–</span>{/if}</td>
											<td class="py-2.5 pr-4 text-right tabular">{#if c.unhealthy}<a class="text-danger font-medium hover:underline" href={withClient('/agents?health=unhealthy', c.id)}>{c.unhealthy}</a>{:else}<span class="text-muted">–</span>{/if}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</section>
					{/if}

					<section class="card">
						<header class="panel-head"><h2 class="panel-title">Operating systems</h2></header>
						<ul class="space-y-3 p-4">
							{#each Object.entries(d.by_os).sort((a, b) => b[1] - a[1]) as [os, n] (os)}
								<li class="flex items-center gap-2 text-sm">
									<OsIcon {os} />
									<span class="w-20">{osLabels[os] ?? os}</span>
									<span class="bg-sunken h-2 flex-1 overflow-hidden rounded-full"><span class="bg-accent block h-full rounded-full" style="width: {pct(n, d.agents_total)}%"></span></span>
									<span class="text-muted w-10 text-right tabular">{num(n)}</span>
								</li>
							{/each}
						</ul>
					</section>
				</div>
			</div>
		{/if}
	{/snippet}
</Async>
