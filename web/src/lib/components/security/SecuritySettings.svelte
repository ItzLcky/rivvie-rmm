<script lang="ts">
	import { Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, loadClients } from '#lib/scope.svelte.js';
	import { exclusionKindHints, exclusionKindLabels } from '#lib/security.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { ExclusionKind, ExclusionRow, SecurityPolicyRow } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import SensorPolicyEditor from './SensorPolicyEditor.svelte';

	/** Sensor policies, exclusions and canary clients. Changing them needs security.manage. */
	let { canManage }: { canManage: boolean } = $props();
	$effect(() => {
		loadClients();
	});

	// --- Policies -------------------------------------------------------------------------------
	const policies = resource(() => api.get<SecurityPolicyRow[]>('/security/policies'));
	let editing = $state<{ policy: SecurityPolicyRow | null } | null>(null);
	const shown = $derived((policies.data ?? []).filter((p) => !clientId() || !p.client_id || p.client_id === clientId()));
	const scope = (p: { client_name: string | null; site_name: string | null }) => (p.site_name ? `${p.client_name} › ${p.site_name}` : (p.client_name ?? 'MSP-wide'));
	async function removePolicy(p: SecurityPolicyRow) {
		const ok = await confirmAction({
			title: `Delete the security policy for ${scope(p)}?`,
			message: `Its agents fall back to the ${p.site_id ? 'client’s policy, or the MSP-wide one' : 'MSP-wide policy'}.`,
			confirmLabel: 'Delete policy',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/security/policies/${p.id}`), 'Policy deleted.'))) policies.reload();
	}

	// --- Exclusions -----------------------------------------------------------------------------
	const exclusions = resource(() => api.get<ExclusionRow[]>('/security/exclusions'));
	const shownExclusions = $derived((exclusions.data ?? []).filter((x) => !clientId() || !x.client_id || x.client_id === clientId()));
	const kinds: ExclusionKind[] = ['path', 'sha256', 'process', 'rule'];
	let exClient = $state(clientId());
	let exKind = $state<ExclusionKind>('path');
	let exValue = $state('');
	let exComment = $state('');
	let exError = $state('');
	let adding = $state(false);
	async function addExclusion(e: SubmitEvent) {
		e.preventDefault();
		const value = exValue.trim();
		if (!value) {
			exError = 'Enter what to exclude';
			return;
		}
		if (exKind === 'sha256' && !/^[0-9a-f]{64}$/i.test(value)) {
			exError = 'A SHA-256 is 64 hex characters';
			return;
		}
		exError = '';
		adding = true;
		try {
			await api.post('/security/exclusions', { client_id: exClient || null, kind: exKind, value, comment: exComment.trim() });
			toast.success('Exclusion added. Agents pick it up within a minute.');
			exValue = '';
			exComment = '';
			exclusions.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			adding = false;
		}
	}
	async function removeExclusion(x: ExclusionRow) {
		const ok = await confirmAction({
			title: 'Remove this exclusion?',
			message: `${exclusionKindLabels[x.kind]} ${x.value} is scanned and detected again${x.client_name ? ` on ${x.client_name}’s agents` : ' everywhere'}.`,
			confirmLabel: 'Remove',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/security/exclusions/${x.id}`), 'Exclusion removed.'))) exclusions.reload();
	}

	// --- Canary clients -------------------------------------------------------------------------
	let saving = $state<string | null>(null);
	async function setCanary(id: string, canary: boolean) {
		saving = id;
		const c = clients.list.find((x) => x.id === id);
		if (await attempt(() => api.put(`/clients/${id}/security`, { canary }), canary ? `${c?.name} gets new content first.` : `${c?.name} now waits for general content.`)) {
			if (c) c.security_canary = canary;
		}
		saving = null;
	}
</script>

<!-- Policies -->
<section class="card mb-6" aria-labelledby="sp-h">
	<header class="border-border flex flex-wrap items-center gap-x-3 gap-y-2 border-b px-4 py-2.5">
		<div class="min-w-0 flex-1">
			<h2 id="sp-h" class="text-sm font-semibold">Sensor policies</h2>
			<p class="text-muted text-xs">The most specific one applies to each agent: site, then client, then MSP-wide.</p>
		</div>
		{#if canManage}<Button size="sm" icon={Plus} onclick={() => (editing = { policy: null })}>New policy</Button>{/if}
	</header>
	<Async res={policies} compact>
		{#snippet children()}
			<ul class="divide-border divide-y">
				{#each shown as p (p.id)}
					<li class="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
						<div class="min-w-0 flex-1">
							<div class="text-sm font-medium">{scope(p)}</div>
							<div class="mt-1 flex flex-wrap gap-1.5 text-xs">
								{#if p.sensor_enabled}
									<Badge>Sensor on</Badge>
									{#if p.prevention}<Badge tone="accent">Prevention</Badge>{:else}<Badge>Detect only</Badge>{/if}
									{#if p.auto_quarantine}<Badge>Auto-quarantine</Badge>{/if}
									{#if p.canaries}<Badge>Decoy files</Badge>{/if}
									<Badge>{p.quick_scan_hours ? `Quick scan every ${p.quick_scan_hours} h` : 'No quick scans'}</Badge>
									<Badge>{p.full_scan_days ? `Full scan every ${p.full_scan_days} d` : 'No full scans'}</Badge>
									<Badge>{p.telemetry_mb} MB telemetry</Badge>
								{:else}
									<Badge>Sensor off</Badge>
								{/if}
							</div>
							<p class="text-muted mt-1 text-xs">Updated <span title={datetime(p.updated_at)}>{ago(p.updated_at)}</span>{p.updated_by_name ? ` by ${p.updated_by_name}` : ''}</p>
						</div>
						{#if canManage}
							<div class="flex gap-1">
								<Button size="sm" icon={Pencil} onclick={() => (editing = { policy: p })}>Edit</Button>
								{#if p.client_id}<IconButton icon={Trash2} label="Delete policy for {scope(p)}" size="sm" onclick={() => removePolicy(p)} />{/if}
							</div>
						{/if}
					</li>
				{:else}
					<li><EmptyState compact title="No policies" /></li>
				{/each}
			</ul>
		{/snippet}
	</Async>
</section>

<!-- Exclusions -->
<section class="mb-6" aria-labelledby="ex-h">

	{#snippet exValueCell(x: ExclusionRow)}
		<div class="font-mono text-xs break-all">{x.value}</div>
		{#if x.comment}<div class="text-muted text-xs break-words">{x.comment}</div>{/if}
	{/snippet}
	{#snippet exKindCell(x: ExclusionRow)}<span class="text-muted whitespace-nowrap">{exclusionKindLabels[x.kind]}</span>{/snippet}
	{#snippet exScopeCell(x: ExclusionRow)}{#if x.client_name}{x.client_name}{:else}<span class="text-muted">Every client</span>{/if}{/snippet}
	{#snippet exByCell(x: ExclusionRow)}<span class="text-muted text-xs whitespace-nowrap">{x.created_by_name ?? 'System'} · <span title={datetime(x.created_at)}>{ago(x.created_at)}</span></span>{/snippet}
	{#snippet exDelCell(x: ExclusionRow)}{#if canManage}<IconButton icon={Trash2} size="sm" label="Remove exclusion {x.value}" onclick={() => removeExclusion(x)} />{/if}{/snippet}
	<DataTable
		id="security-exclusions"
		caption="Exclusions"
		rows={shownExclusions}
		key={(x) => x.id}
		loading={exclusions.loading}
		scroll={false}
		columns={[
			{ id: 'value', label: 'Excluded', cell: exValueCell, hideable: false },
			{ id: 'kind', label: 'Kind', cell: exKindCell },
			{ id: 'scope', label: 'Applies to', cell: exScopeCell, from: 'sm' },
			{ id: 'by', label: 'Added', cell: exByCell, from: 'md' },
			{ id: 'del', label: '', cell: exDelCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<ExclusionRow>[]}
	>
		{#snippet toolbar()}
			<div class="min-w-0">
				<h2 id="ex-h" class="text-sm font-semibold">Exclusions</h2>
				<p class="text-muted text-xs">Files, hashes, processes and rules our sensor ignores. Narrow ones are safer: an excluded folder is a place malware can hide.</p>
			</div>
		{/snippet}
		{#snippet empty()}<EmptyState compact title="No exclusions" description="Marking a detection a false positive can add one for its file or rule." />{/snippet}
	</DataTable>
	{#if canManage}
		<form class="card mt-3 grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-[minmax(10rem,14rem)_minmax(8rem,10rem)_minmax(0,1fr)_minmax(0,1fr)_auto] lg:items-start" onsubmit={addExclusion} aria-label="Add an exclusion">
			<Field label="Applies to" id="ex-client">
				<Select id="ex-client" class="w-full" bind:value={exClient} options={[{ value: '', label: 'Every client' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
			</Field>
			<Field label="Kind" id="ex-kind">
				<Select id="ex-kind" class="w-full" bind:value={exKind} options={kinds.map((k) => ({ value: k, label: exclusionKindLabels[k] }))} />
			</Field>
			<Field label="Value" id="ex-value" required hint={exclusionKindHints[exKind]} error={exError}>
				<Input id="ex-value" class="font-mono" spellcheck={false} bind:value={exValue} invalid={!!exError} />
			</Field>
			<Field label="Why" id="ex-comment" hint="Shown to everyone who sees it">
				<Input id="ex-comment" bind:value={exComment} placeholder="Backup software writes here" />
			</Field>
			<div class="lg:pt-5"><Button type="submit" icon={Plus} loading={adding}>Add</Button></div>
		</form>
	{/if}
</section>

<!-- Canary clients -->
<section class="card" aria-labelledby="canary-h">
	<header class="border-border border-b px-4 py-2.5">
		<h2 id="canary-h" class="text-sm font-semibold">Canary clients</h2>
		<p class="text-muted text-xs">New detection content runs on these clients’ agents first, and reaches everyone else after the soak time if nothing goes wrong. Pick a few that are low-risk and well-watched, like your own office.</p>
	</header>
	{#if clients.list.length}
		<ul class="divide-border divide-y">
			{#each clients.list as c (c.id)}
				<li class="flex items-center justify-between gap-3 px-4 py-2.5">
					<span class="min-w-0 truncate text-sm">{c.name}</span>
					<Switch label="{c.name} is a canary client" checked={!!c.security_canary} disabled={!canManage || saving === c.id} onchange={(on) => setCanary(c.id, on)} />
				</li>
			{/each}
		</ul>
	{:else}
		<EmptyState compact title="No clients yet" />
	{/if}
</section>

{#if editing}
	<SensorPolicyEditor
		policy={editing.policy}
		template={policies.data?.find((p) => !p.client_id)}
		taken={(policies.data ?? []).filter((p) => p.client_id).map((p) => `${p.client_id}:${p.site_id ?? ''}`)}
		onclose={() => (editing = null)}
		onsaved={() => policies.reload()}
	/>
{/if}
