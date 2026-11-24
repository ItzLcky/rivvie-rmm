<script lang="ts">
	import { ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { epssPct, unassessedLabel, type AgentFinding, type AgentVulns } from '#lib/vulns.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import AcceptDialog from '#lib/components/vulns/AcceptDialog.svelte';
	import RemediationAction from '#lib/components/vulns/RemediationAction.svelte';
	import VulnSeverity from '#lib/components/vulns/VulnSeverity.svelte';

	/** The device's vulnerable software: findings worst first, with the fix and accept-risk. */
	let { agentId, hostname, clientId, clientName }: { agentId: string; hostname: string; clientId: string; clientName: string } = $props();
	const data = resource(() => api.get<AgentVulns>(`/agents/${agentId}/vulnerabilities`));
	let accepting = $state<string | null>(null);
	const ecoLabel = (e: string) => (e === 'Windows' ? 'Windows applications (product map and NVD)' : e === 'Arch' ? 'Arch Linux packages' : `${e} packages`);
</script>

<Async res={data}>
	{#snippet children(v)}
		{#if v}
			{@const open = v.findings.filter((f) => !f.accepted)}
			{#if v.unassessed}
				<section class="card p-4" aria-label="Vulnerabilities">
					<EmptyState compact title="Not assessed: {unassessedLabel[v.unassessed] ?? v.unassessed}" description={v.unassessed === 'old_agent' ? 'This agent predates operating-system reporting; update it and its software is checked against its distribution’s advisories.' : v.unassessed === 'no_inventory' ? 'The device hasn’t sent its software inventory yet.' : 'Vulnerabilities are assessed on Debian, Ubuntu, RHEL, AlmaLinux, Rocky, SUSE, Alpine and Arch packages and on mapped Windows applications. macOS isn’t covered.'} />
				</section>
			{:else}
				<section aria-label="Vulnerability counts" class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
					<Stat label="Critical" value={v.critical} tone="danger" />
					<Stat label="High" value={v.high} tone="warning" />
					<Stat label="Known exploited" value={new Set(open.filter((f) => f.kev).map((f) => f.key)).size} tone="danger" />
					<Stat label="Open in all" value={new Set(open.map((f) => f.key)).size} />
				</section>
				{#snippet cveCell(f: AgentFinding)}
					<a class="hover:text-accent font-mono text-[13px] font-medium whitespace-nowrap" href="/vulnerabilities/{encodeURIComponent(f.key)}">{f.key}</a>
					<div class="text-muted max-w-96 truncate text-xs" title={f.summary}>{f.summary}</div>
				{/snippet}
				{#snippet sevCell(f: AgentFinding)}
					<VulnSeverity severity={f.severity} cvss={f.cvss} kev={f.kev} />
					{#if f.epss != null}<div class="text-muted mt-0.5 text-xs" title="EPSS: probability of exploitation in the next 30 days">EPSS {epssPct(f.epss)}</div>{/if}
				{/snippet}
				{#snippet pkgCell(f: AgentFinding)}
					<span class="font-medium break-all">{f.software_name}</span>{#if f.software_name !== f.package}<span class="text-muted text-xs"> ({f.package})</span>{/if}
					<div class="text-muted font-mono text-xs break-all">{f.installed_version}</div>
				{/snippet}
				{#snippet fixCell(f: AgentFinding)}
					{#if f.accepted}
						<Badge>Accepted</Badge>
					{:else}
						<RemediationAction {agentId} remediation={f.remediation} fixed={f.fixed_version} ondone={() => data.reload()} />
						{#if allowed('security.respond')}<div><button type="button" class="text-muted hover:text-fg mt-1 text-xs font-medium whitespace-nowrap" onclick={() => (accepting = f.key)}>Accept risk</button></div>{/if}
					{/if}
				{/snippet}
				{#snippet seenCell(f: AgentFinding)}<span class="text-muted whitespace-nowrap" title={datetime(f.first_seen)}>{ago(f.first_seen)}</span>{/snippet}
				<DataTable
					id="agent-vulns"
					caption="Vulnerabilities on {hostname}"
					rows={v.findings}
					key={(f) => `${f.vuln_id}/${f.package}`}
					columns={[
						{ id: 'cve', label: 'Vulnerability', cell: cveCell, hideable: false },
						{ id: 'severity', label: 'Severity', cell: sevCell },
						{ id: 'package', label: 'Package', cell: pkgCell, from: 'sm' },
						{ id: 'fix', label: 'Fix', cell: fixCell },
						{ id: 'seen', label: 'Found', cell: seenCell, from: 'xl' }
					] satisfies Column<AgentFinding>[]}
				>
					{#snippet empty()}<EmptyState compact icon={ShieldCheck} title="No known vulnerabilities" description="Nothing installed matches an advisory with a fix, a high or critical rating, or a known exploit." />{/snippet}
					{#snippet footer()}
						<p class="text-muted px-3 py-2 text-xs">{ecoLabel(v.ecosystem ?? '')}{v.evaluated_at ? ` · checked ${ago(v.evaluated_at)}` : ''}{v.findings.length >= 2000 ? ` · showing ${num(2000)}` : ''}</p>
					{/snippet}
				</DataTable>
			{/if}
		{/if}
	{/snippet}
</Async>

{#if accepting}
	<AcceptDialog vulnId={accepting} clients={[{ id: clientId, name: clientName }]} agent={{ id: agentId, hostname, client_id: clientId }} onclose={() => (accepting = null)} ondone={() => { accepting = null; data.reload(); }} />
{/if}
