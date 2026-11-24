<script lang="ts">
	import { Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId } from '#lib/scope.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import type { VulnSoftware } from '#lib/vulns.js';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import VulnSeverity from '#lib/components/vulns/VulnSeverity.svelte';

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const rows = resource(() => api.get<VulnSoftware[]>(`/vulnerabilities/software${qs({ client_id: clientId(), q: param('q') })}`));
</script>

{#if rows.error && !rows.data}
	<div class="card"><ErrorState error={rows.error} onretry={() => rows.reload()} /></div>
{:else}
	{#snippet pkgCell(r: VulnSoftware)}
		<a class="hover:text-accent font-medium" href="/vulnerabilities?q={encodeURIComponent(r.product_name ? r.package : r.package)}">{r.product_name ?? r.package}</a>
		<div class="text-muted text-xs">{r.product_name ? r.package : r.ecosystems.filter(Boolean).join(', ')}</div>
	{/snippet}
	{#snippet sevCell(r: VulnSoftware)}<VulnSeverity severity={r.severity} kev={r.kev} />{/snippet}
	{#snippet cveCell(r: VulnSoftware)}<span class="tabular">{num(r.cves)}</span>{/snippet}
	{#snippet devCell(r: VulnSoftware)}<span class="font-semibold tabular">{num(r.devices)}</span>{/snippet}
	{#snippet fixCell(r: VulnSoftware)}
		{#if r.fixed_versions.length}<span class="font-mono text-xs" title={r.fixed_versions.join(', ')}>{r.fixed_versions[r.fixed_versions.length - 1]}</span>{:else}<span class="text-muted">No fix yet</span>{/if}
		{#if r.product_id && !r.package_id}<div class="text-muted text-xs">Not in the software catalog</div>{/if}
	{/snippet}
	<DataTable
		id="vuln-software"
		caption="Vulnerable software"
		rows={rows.data ?? []}
		key={(r) => r.package}
		loading={rows.loading && !rows.data}
		columns={[
			{ id: 'package', label: 'Software', cell: pkgCell, hideable: false },
			{ id: 'severity', label: 'Worst', cell: sevCell },
			{ id: 'cves', label: 'CVEs', cell: cveCell, align: 'right', from: 'sm' },
			{ id: 'devices', label: 'Devices', cell: devCell, align: 'right' },
			{ id: 'fix', label: 'Fixed in', cell: fixCell, from: 'md' }
		] satisfies Column<VulnSoftware>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Package or title…" aria-label="Search software" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet empty()}<EmptyState icon={ShieldCheck} title="No vulnerable software" description="Nothing installed matches an advisory." />{/snippet}
	</DataTable>
{/if}
