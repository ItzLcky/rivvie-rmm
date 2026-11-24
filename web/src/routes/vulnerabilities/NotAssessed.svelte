<script lang="ts">
	import { api } from '#lib/api.js';
	import { num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId } from '#lib/scope.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { qs } from '#lib/url.svelte.js';
	import { unassessedLabel, type Unassessed } from '#lib/vulns.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ProductDialog from './ProductDialog.svelte';

	const data = resource(() => api.get<Unassessed>(`/vulnerabilities/unassessed${qs({ client_id: clientId() })}`));
	let mapping = $state<{ title: string; publisher: string | null } | null>(null);
	type Device = Unassessed['devices'][number];
	type Title = Unassessed['titles'][number];
</script>

<Async res={data}>
	{#snippet children(d)}
		<div class="space-y-6">
			{#snippet devCell(r: Device)}<a class="hover:text-accent font-medium" href="/agents/{r.agent_id}?tab=vulnerabilities">{r.hostname}</a><div class="text-muted text-xs">{r.client_name}</div>{/snippet}
			{#snippet osCell(r: Device)}{r.os_name}<div class="text-muted text-xs">agent {r.agent_version}</div>{/snippet}
			{#snippet whyCell(r: Device)}<Badge tone={r.reason === 'old_agent' ? 'warning' : 'neutral'}>{unassessedLabel[r.reason] ?? r.reason}</Badge>{/snippet}
			<DataTable
				id="vuln-unassessed"
				caption="Devices not assessed"
				rows={d.devices}
				key={(r) => r.agent_id}
				columns={[
					{ id: 'device', label: 'Device', cell: devCell, hideable: false },
					{ id: 'os', label: 'System', cell: osCell, from: 'sm' },
					{ id: 'why', label: 'Why', cell: whyCell }
				] satisfies Column<Device>[]}
			>
				{#snippet empty()}<EmptyState compact title="Every device is assessed" description="Linux distributions with a feed, Arch, and Windows." />{/snippet}
			</DataTable>

			<section aria-labelledby="titles-h">
				<h2 id="titles-h" class="panel-title mb-1">Windows applications not in the product map</h2>
				<p class="text-muted mb-3 text-sm">Windows applications are matched to NVD through a curated map ({num(d.products)} products), never by guessing: a title that isn’t mapped isn’t assessed. Map the ones that matter.</p>
				{#snippet titleCell(r: Title)}<span class="font-medium">{r.title}</span>{#if r.publisher}<div class="text-muted text-xs">{r.publisher}</div>{/if}{/snippet}
				{#snippet verCell(r: Title)}<span class="text-muted font-mono text-xs">{r.versions.join(', ')}</span>{/snippet}
				{#snippet countCell(r: Title)}<span class="tabular">{num(r.devices)}</span>{/snippet}
				{#snippet mapCell(r: Title)}{#if allowed('security.manage')}<Button size="xs" onclick={() => (mapping = { title: r.title, publisher: r.publisher })}>Map</Button>{/if}{/snippet}
				<DataTable
					id="vuln-titles"
					caption="Unmapped Windows applications"
					rows={d.titles}
					key={(r) => `${r.title}/${r.publisher ?? ''}`}
					columns={[
						{ id: 'title', label: 'Installed title', cell: titleCell, hideable: false },
						{ id: 'versions', label: 'Versions', cell: verCell, from: 'md' },
						{ id: 'devices', label: 'Devices', cell: countCell, align: 'right' },
						{ id: 'map', label: 'Actions', cell: mapCell }
					] satisfies Column<Title>[]}
				>
					{#snippet empty()}<EmptyState compact title="Every Windows application is mapped" description="Or no Windows device has reported its software yet." />{/snippet}
				</DataTable>
			</section>
		</div>
	{/snippet}
</Async>

{#if mapping}
	<ProductDialog product={null} title={mapping.title} publisher={mapping.publisher} onclose={() => (mapping = null)} ondone={() => { mapping = null; data.reload(); }} />
{/if}
