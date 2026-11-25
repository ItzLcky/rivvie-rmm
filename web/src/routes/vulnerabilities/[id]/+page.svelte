<script lang="ts">
	import { ExternalLink } from '@lucide/svelte';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { qs } from '#lib/url.svelte.js';
	import { cveUrl, epssPct, type VulnAcceptance, type VulnDetail, type VulnDevice } from '#lib/vulns.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import AcceptDialog from '#lib/components/vulns/AcceptDialog.svelte';
	import RemediationAction from '#lib/components/vulns/RemediationAction.svelte';
	import VulnSeverity from '#lib/components/vulns/VulnSeverity.svelte';

	const id = $derived(page.params.id ?? '');
	const scoped = $derived(currentClient());
	const detail = resource(() => api.get<VulnDetail>(`/vulnerabilities/${encodeURIComponent(id)}`));
	const devices = resource(() => api.get<VulnDevice[]>(`/vulnerabilities/${encodeURIComponent(id)}/devices${qs({ client_id: clientId() })}`));
	let accepting = $state<{ agent: { id: string; hostname: string; client_id: string } | null } | null>(null);
	const clients = $derived([...new Map((devices.data ?? []).map((d) => [d.client_id, { id: d.client_id, name: d.client_name }])).values()]);
	const sourceLabel = (s: string) => (s === 'nvd' ? 'NVD' : s === 'arch' ? 'Arch Linux' : s.replace(/^osv:/, ''));
	function reload() {
		detail.reload();
		devices.reload();
	}
	async function unaccept(a: VulnAcceptance) {
		if (!(await confirmAction({ title: 'Remove this acceptance?', message: 'The findings count towards alerts and totals again.', confirmLabel: 'Remove' }))) return;
		if (await attempt(() => api.del(`/vulnerabilities/acceptances/${a.id}`), 'Acceptance removed.')) reload();
	}
</script>

<svelte:head><title>{id}</title></svelte:head>

<Async res={detail}>
	{#snippet children(d)}
		{@const link = cveUrl(d.key)}
		<PageHeader title={d.key} description={d.summary} crumbs={[{ label: 'Vulnerabilities', href: '/vulnerabilities' }, { label: d.key }]}>
			{#snippet actions()}
				{#if link}<a class="link inline-flex items-center gap-1 text-sm" href={link} target="_blank" rel="noreferrer"><ExternalLink class="size-3.5" aria-hidden="true" />CVE record</a>{/if}
				{#if allowed('security.respond') && clients.length}<Button onclick={() => (accepting = { agent: null })}>Accept risk</Button>{/if}
			{/snippet}
		</PageHeader>

		<section aria-label="Scores" class="card mb-4 grid gap-4 p-4 sm:grid-cols-2 lg:grid-cols-4">
			<div><div class="label text-muted">Severity</div><VulnSeverity severity={d.severity} cvss={d.cvss} /></div>
			<div>
				<div class="label text-muted">EPSS</div>
				<span class="font-semibold tabular">{epssPct(d.epss)}</span>
				{#if d.epss_percentile != null}<span class="text-muted text-xs"> · {Math.round(d.epss_percentile * 100)}th percentile</span>{/if}
				<div class="text-muted text-xs">Chance of exploitation in the next 30 days</div>
			</div>
			<div>
				<div class="label text-muted">Known exploited</div>
				{#if d.kev}<Badge tone="danger">In CISA KEV</Badge><div class="text-muted text-xs">Added {d.kev_added}{d.kev_due ? ` · federal due date ${d.kev_due}` : ''}</div>{:else}<span class="text-muted">No</span>{/if}
			</div>
			<div>
				<div class="label text-muted">Devices</div>
				<span class="font-semibold tabular">{num(d.devices)}</span>{#if d.accepted_devices}<span class="text-muted text-xs"> · {num(d.accepted_devices)} accepted</span>{/if}
			</div>
			{#if d.cvss_vector}<div class="sm:col-span-2 lg:col-span-4"><div class="label text-muted">CVSS vector</div><code class="font-mono text-xs break-all">{d.cvss_vector}</code></div>{/if}
		</section>

		<section class="mb-4" aria-labelledby="dev-h">
			<h2 id="dev-h" class="panel-title mb-2">Affected devices{scoped ? ` at ${scoped.name}` : ''}</h2>
			{#snippet devCell(r: VulnDevice)}
				<a class="hover:text-accent font-medium whitespace-nowrap" href="/agents/{r.agent_id}?tab=vulnerabilities">{r.hostname}</a>
				<div class="text-muted text-xs whitespace-nowrap">{scoped ? r.site_name : `${r.client_name} › ${r.site_name}`}{r.online ? '' : ' · offline'}</div>
			{/snippet}
			{#snippet pkgCell(r: VulnDevice)}<span class="font-medium">{r.software_name}</span><div class="text-muted font-mono text-xs">{r.installed_version}</div>{/snippet}
			{#snippet fixedCell(r: VulnDevice)}{#if r.fixed_version}<span class="font-mono text-xs">{r.fixed_version}</span>{:else}<span class="text-muted">No fix yet</span>{/if}{/snippet}
			{#snippet actCell(r: VulnDevice)}
				{#if r.accepted}<Badge>Accepted</Badge>{:else}<RemediationAction agentId={r.agent_id} remediation={r.remediation} fixed={r.fixed_version} ondone={reload} />{/if}
			{/snippet}
			{#snippet seenCell(r: VulnDevice)}<span class="text-muted whitespace-nowrap" title={datetime(r.first_seen)}>{ago(r.first_seen)}</span>{/snippet}
			{#snippet acceptCell(r: VulnDevice)}
				{#if !r.accepted && allowed('security.respond')}<button type="button" class="text-muted hover:text-fg text-xs font-medium whitespace-nowrap" onclick={() => (accepting = { agent: { id: r.agent_id, hostname: r.hostname, client_id: r.client_id } })}>Accept risk</button>{/if}
			{/snippet}
			<DataTable
				id="vuln-cve-devices"
				caption="Devices with {d.key}"
				rows={devices.data ?? []}
				key={(r) => `${r.agent_id}/${r.vuln_id}/${r.package}`}
				loading={devices.loading && !devices.data}
				columns={[
					{ id: 'device', label: 'Device', cell: devCell, hideable: false },
					{ id: 'package', label: 'Installed', cell: pkgCell },
					{ id: 'fixed', label: 'Fixed in', cell: fixedCell, from: 'sm' },
					{ id: 'fix', label: 'Fix', cell: actCell },
					{ id: 'seen', label: 'Found', cell: seenCell, from: 'lg' },
					{ id: 'accept', label: 'Actions', cell: acceptCell, from: 'md' }
				] satisfies Column<VulnDevice>[]}
			>
				{#snippet empty()}<EmptyState compact title="No device has it open" description="Every finding is fixed, or the advisory doesn’t affect what is installed." />{/snippet}
			</DataTable>
		</section>

		{#if d.acceptances.length}
			<section class="card mb-4" aria-labelledby="acc-h">
				<h2 id="acc-h" class="panel-title border-border border-b px-4 py-3">Accepted risk</h2>
				<ul class="divide-border divide-y">
					{#each d.acceptances as a (a.id)}
						<li class="flex flex-wrap items-start gap-3 px-4 py-2.5 text-sm">
							<div class="min-w-0 flex-1">
								<div><span class="font-medium">{a.hostname ?? `Every device of ${a.client_name}`}</span>{#if a.hostname}<span class="text-muted"> · {a.client_name}</span>{/if}</div>
								{#if a.note}<p class="text-muted text-xs">{a.note}</p>{/if}
								<p class="text-muted text-xs">{a.by_name ?? 'Someone'} · {ago(a.created_at)} · {a.expires_at ? (a.active ? `until ${datetime(a.expires_at)}` : `expired ${ago(a.expires_at)}`) : 'until removed'}</p>
							</div>
							{#if !a.active}<Badge>Expired</Badge>{/if}
							{#if allowed('security.respond')}<Button size="xs" variant="ghost" onclick={() => unaccept(a)}>Remove</Button>{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		<section class="card" aria-labelledby="adv-h">
			<h2 id="adv-h" class="panel-title border-border border-b px-4 py-3">Advisories</h2>
			<ul class="divide-border divide-y">
				{#each d.advisories as a (a.id)}
					{@const ranges = d.ranges.filter((r) => r.vuln_id === a.id)}
					<li class="space-y-1.5 px-4 py-3 text-sm">
						<div class="flex flex-wrap items-center gap-2">
							<span class="font-mono text-[13px] font-medium">{a.id}</span>
							<Badge>{sourceLabel(a.source)}</Badge>
							<VulnSeverity severity={a.severity} cvss={a.cvss} />
							{#if a.url}<a class="link text-xs" href={a.url} target="_blank" rel="noreferrer">Source</a>{/if}
							{#if a.published}<span class="text-muted text-xs">published {datetime(a.published)}</span>{/if}
						</div>
						{#if a.details && a.details !== a.summary}<p class="text-muted text-sm whitespace-pre-line">{a.details}</p>{/if}
						{#if ranges.length}
							<table class="table text-xs">
								<thead><tr><th scope="col">Ecosystem</th><th scope="col">Package</th><th scope="col">Affected from</th><th scope="col">Fixed in</th></tr></thead>
								<tbody>
									{#each ranges as r, i (i)}
										<tr>
											<td>{r.ecosystem === 'NVD' ? 'Windows (NVD)' : r.ecosystem}</td>
											<td class="font-mono">{r.package}</td>
											<td class="font-mono">{!r.introduced || r.introduced === '0' ? 'any' : r.introduced}</td>
											<td class="font-mono">{r.fixed ?? (r.last_affected ? `after ${r.last_affected}` : 'not yet')}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						{/if}
					</li>
				{/each}
			</ul>
		</section>
	{/snippet}
</Async>

{#if accepting}
	<AcceptDialog vulnId={id} {clients} agent={accepting.agent} onclose={() => (accepting = null)} ondone={() => { accepting = null; reload(); }} />
{/if}
