<script lang="ts">
	import { Ban, Download, RefreshCw, RotateCcw, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, plural } from '#lib/format.js';
	import type { Resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { providerLabels, type SoftwareDevice, type SoftwareUpdates } from '#lib/software.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import OsIcon from '#lib/components/OsIcon.svelte';

	/**
	 * Installed catalog packages with a newer version on offer, one row per device and package.
	 * Upgrading is the approval: it starts a run now. A version can be ignored (a newer one shows
	 * again); a policy that keeps the package current upgrades without anyone asking.
	 */
	let { res, q, onsearch, onrescan }: { res: Resource<SoftwareUpdates>; q: string; onsearch: (v: string) => void; onrescan?: () => void } = $props();

	let selected = $state(new Set<string>());
	const keyOf = (d: SoftwareDevice) => `${d.agent_id}:${d.package_id}`;
	const picked = $derived((res.data?.items ?? []).filter((d) => selected.has(keyOf(d))));
	const items = (list: SoftwareDevice[]) => list.map((d) => ({ agent_id: d.agent_id, package_id: d.package_id }));

	async function upgrade(list: SoftwareDevice[]) {
		const ok = await attempt(async () => {
			const out = await api.post<{ runs: unknown[]; skipped: { hostname: string; reason: string }[] }>('/software/updates/install', { items: items(list) });
			if (out.skipped.length) toast.error(`Skipped ${plural(out.skipped.length, 'device')}: ${out.skipped[0].hostname}: ${out.skipped[0].reason}`);
		}, `Upgrading ${plural(list.length, 'device')}.`);
		if (ok) {
			selected = new Set();
			res.reload();
		}
	}
	async function ignore(list: SoftwareDevice[], on: boolean) {
		if (await attempt(() => api.post('/software/updates/ignore', { items: items(list), ignore: on }), on ? 'Skipping this version. A newer one will show again.' : 'Offering it again.')) {
			selected = new Set();
			res.reload();
		}
	}
</script>

{#snippet hostCell(d: SoftwareDevice)}
	<span class="inline-flex items-center gap-1.5"><OsIcon os={d.os_family} class="size-4" /><a class="hover:text-accent font-medium" href="/agents/{d.agent_id}?tab=deployments">{d.hostname}</a></span>
	<div class="text-muted text-xs">{d.client_name} › {d.site_name}</div>
{/snippet}
{#snippet pkgCell(d: SoftwareDevice)}<a class="hover:text-accent font-medium" href="/software/{d.package_id}">{d.package_name}</a>{/snippet}
{#snippet versionCell(d: SoftwareDevice)}
	<span class="font-mono text-xs whitespace-nowrap">{d.installed} → {d.available}</span>
	{#if d.ignored === d.available}<Badge class="ml-1">Skipped</Badge>{/if}
{/snippet}
{#snippet policyCell(d: SoftwareDevice)}
	{#if d.desired === 'latest' && !d.pin}<Badge tone="info" title="A policy keeps it current; it upgrades inside its window">Automatic</Badge>{:else if d.pin}<Badge title="The package is held at {d.pin}">Pinned</Badge>{:else}<span class="text-muted">By hand</span>{/if}
{/snippet}
{#snippet viaCell(d: SoftwareDevice)}<span class="text-muted">{d.provider ? (providerLabels[d.provider] ?? d.provider) : '–'}</span>{/snippet}
{#snippet seenCell(d: SoftwareDevice)}<span class="text-muted whitespace-nowrap">{ago(d.checked_at)}</span>{/snippet}

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	<DataTable
		id="software-updates"
		caption="Updates available for catalog software"
		rows={res.data?.items ?? []}
		key={keyOf}
		loading={res.loading}
		busy={res.busy}
		bind:selected
		columns={[
			{ id: 'host', label: 'Device', cell: hostCell, hideable: false },
			{ id: 'pkg', label: 'Package', cell: pkgCell, hideable: false },
			{ id: 'version', label: 'Installed → available', cell: versionCell },
			{ id: 'policy', label: 'Upgrades', cell: policyCell, from: 'md' },
			{ id: 'via', label: 'Found by', cell: viaCell, from: 'xl' },
			{ id: 'seen', label: 'Checked', cell: seenCell, align: 'right', from: 'lg' }
		] satisfies Column<SoftwareDevice>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Device or package…" aria-label="Search updates" class="min-w-0 flex-1 sm:w-64 sm:flex-none" value={q} oninput={(e) => onsearch(e.currentTarget.value)} />
			<span class="text-muted text-xs">From the winget, Chocolatey, apt and dnf scans of catalog packages.</span>
			{#if can('technician') && onrescan}<Button size="sm" variant="ghost" icon={RefreshCw} class="sm:ml-auto" onclick={onrescan}>Rescan these devices</Button>{/if}
		{/snippet}
		{#snippet bulk()}
			{#if can('technician')}
				<Button size="sm" variant="primary" icon={Download} onclick={() => upgrade(picked)}>Upgrade now</Button>
				<Button size="sm" icon={Ban} onclick={() => ignore(picked, true)} title="Don’t offer this version again">Skip this version</Button>
				<Button size="sm" variant="ghost" icon={RotateCcw} onclick={() => ignore(picked, false)}>Offer again</Button>
			{/if}
		{/snippet}
		{#snippet empty()}
			<EmptyState compact title={q ? 'No updates match' : 'Everything is up to date'} description={q ? undefined : 'Devices report what they have of the catalog every few hours. Packages kept current by a policy upgrade on their own.'} />
		{/snippet}
	</DataTable>
{/if}
