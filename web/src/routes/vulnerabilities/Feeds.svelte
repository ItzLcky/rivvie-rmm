<script lang="ts">
	import { RefreshCw } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { VulnFeed, VulnFeeds, VulnProduct } from '#lib/vulns.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import ProductDialog from './ProductDialog.svelte';

	const feeds = resource(() => api.get<VulnFeeds>('/vulnerabilities/feeds'));
	const products = resource(() => api.get<VulnProduct[]>('/vulnerabilities/products'));
	let editing = $state<VulnProduct | 'new' | null>(null);

	// While a sync runs, follow its progress.
	$effect(() => {
		if (!feeds.data?.running) return;
		const t = setInterval(() => feeds.reload(), 3000);
		return () => clearInterval(t);
	});

	async function sync(force: boolean) {
		if (await attempt(() => api.post('/vulnerabilities/sync', { force }), 'Sync started.')) feeds.reload();
	}
	async function toggle(f: VulnFeed, on: boolean) {
		if (await attempt(() => api.put(`/vulnerabilities/feeds/${encodeURIComponent(f.name)}`, { enabled: on }))) feeds.reload();
	}
	async function remove(p: VulnProduct) {
		if (!(await confirmAction({ title: `Remove ${p.name}?`, message: 'Its titles stop being assessed. Built-in mappings can be added again.', confirmLabel: 'Remove', danger: true }))) return;
		if (await attempt(() => api.del(`/vulnerabilities/products/${p.id}`), 'Mapping removed.')) products.reload();
	}
</script>

<div class="space-y-6">
	<Async res={feeds}>
		{#snippet children(d)}
			<section aria-labelledby="feeds-h">
				<div class="mb-3 flex flex-wrap items-end justify-between gap-3">
					<div>
						<h2 id="feeds-h" class="panel-title">Advisory feeds</h2>
						<p class="text-muted text-sm">Mirrored here, daily, for the systems in the fleet: no inventory leaves the server.{d.automatic ? '' : ' Automatic sync is off (RMM_VULN_SYNC_HOURS=0).'}{d.nvd_api_key ? '' : ' Without RMM_NVD_API_KEY, NVD is fetched slowly (5 requests in 30 seconds).'}</p>
					</div>
					<div class="flex gap-2">
						<Button icon={RefreshCw} loading={d.running} onclick={() => sync(false)}>{d.running ? 'Syncing…' : 'Sync now'}</Button>
						<Button variant="ghost" disabled={d.running} onclick={() => sync(true)}>Download everything again</Button>
					</div>
				</div>
				{#snippet nameCell(f: VulnFeed)}<span class="font-medium">{f.label}</span>{#if !f.needed}<div class="text-muted text-xs">Not needed by any device</div>{/if}{/snippet}
				{#snippet syncCell(f: VulnFeed)}
					{#if f.progress}<Badge tone="info">{f.progress}</Badge>
					{:else if f.error}<Badge tone="danger" title={f.error}>Failed</Badge><div class="text-muted max-w-72 truncate text-xs" title={f.error}>{f.error}</div>
					{:else}<span class="text-muted whitespace-nowrap" title={datetime(f.last_sync_at)}>{f.last_sync_at ? ago(f.last_sync_at) : 'never'}</span>{/if}
				{/snippet}
				{#snippet countCell(f: VulnFeed)}<span class="tabular">{num(f.records)}</span>{/snippet}
				{#snippet onCell(f: VulnFeed)}<Switch checked={f.enabled} label="Sync {f.label}" onchange={(on) => toggle(f, on)} />{/snippet}
				<DataTable
					id="vuln-feeds"
					caption="Advisory feeds"
					rows={d.feeds}
					key={(f) => f.name}
					columns={[
						{ id: 'name', label: 'Feed', cell: nameCell, hideable: false },
						{ id: 'sync', label: 'Last sync', cell: syncCell },
						{ id: 'records', label: 'Records', cell: countCell, align: 'right', from: 'sm' },
						{ id: 'on', label: 'Enabled', cell: onCell }
					] satisfies Column<VulnFeed>[]}
				/>
				<ul class="text-muted mt-3 space-y-0.5 text-xs">
					{#each d.attribution as a (a)}<li>{a}</li>{/each}
				</ul>
			</section>
		{/snippet}
	</Async>

	<Async res={products}>
		{#snippet children(list)}
			<section aria-labelledby="products-h">
				<div class="mb-3 flex flex-wrap items-end justify-between gap-3">
					<div>
						<h2 id="products-h" class="panel-title">Windows product map</h2>
						<p class="text-muted text-sm">Installed titles matched to NVD products. Only what is mapped is assessed; titles are never guessed.</p>
					</div>
					<Button onclick={() => (editing = 'new')}>Map a product</Button>
				</div>
				{#snippet pName(p: VulnProduct)}<span class="font-medium">{p.name}</span>{#if p.builtin}<span class="text-muted text-xs"> · built in</span>{/if}<div class="text-muted max-w-80 truncate text-xs" title={p.name_patterns.join(', ')}>{p.name_patterns.join(', ')}</div>{/snippet}
				{#snippet pCpe(p: VulnProduct)}<span class="font-mono text-xs">{p.vendor}:{p.product}</span>{/snippet}
				{#snippet pPkg(p: VulnProduct)}{#if p.package_name}{p.package_name}{:else}<span class="text-muted">–</span>{/if}{/snippet}
				{#snippet pDev(p: VulnProduct)}<span class="tabular">{num(p.devices)}</span>{/snippet}
				{#snippet pAct(p: VulnProduct)}
					<span class="flex gap-1">
						<Button size="xs" variant="ghost" onclick={() => (editing = p)}>Edit</Button>
						<Button size="xs" variant="danger-ghost" onclick={() => remove(p)}>Remove</Button>
					</span>
				{/snippet}
				<DataTable
					id="vuln-products"
					caption="Windows product map"
					rows={list}
					key={(p) => p.id}
					columns={[
						{ id: 'name', label: 'Product', cell: pName, hideable: false },
						{ id: 'cpe', label: 'CPE', cell: pCpe, from: 'md' },
						{ id: 'package', label: 'Catalog package', cell: pPkg, from: 'lg' },
						{ id: 'devices', label: 'Affected devices', cell: pDev, align: 'right', from: 'sm' },
						{ id: 'actions', label: 'Actions', cell: pAct }
					] satisfies Column<VulnProduct>[]}
				/>
			</section>
		{/snippet}
	</Async>
</div>

{#if editing}
	<ProductDialog product={editing === 'new' ? null : editing} onclose={() => (editing = null)} ondone={() => { editing = null; products.reload(); }} />
{/if}
