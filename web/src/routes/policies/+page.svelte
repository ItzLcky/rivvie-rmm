<script lang="ts">
	import { goto } from '$app/navigation';
	import { FolderPlus, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { num, plural } from '#lib/format.js';
	import { setHref, treeOrder } from '#lib/policy/policy.js';
	import type { Category, SetRow } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import AssignmentGrid from '#lib/components/policy/AssignmentGrid.svelte';
	import CategoryDialog from '#lib/components/policy/CategoryDialog.svelte';
	import SetDialog from '#lib/components/policy/SetDialog.svelte';
	import SetTree from '#lib/components/policy/SetTree.svelte';

	const tab = $derived(param('tab', 'sets'));
	const scoped = $derived(currentClient());
	$effect(() => {
		loadClients();
	});

	const sets = resource(() => api.get<SetRow[]>(`/policy-sets${qs({ client_id: clientId() })}`));
	const categories = resource(() => api.get<Category[]>('/device-categories'));
	let newSet = $state(false);
	let editing = $state<Category | 'new' | null>(null);

	async function removeCategory(c: Category) {
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message: `${c.devices ? `Its ${plural(c.devices, 'device')} go back to their built-in category. ` : ''}Its assignments are deleted, and enrollment tokens naming it no longer do.`,
			confirmLabel: 'Delete category',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/device-categories/${c.id}`), `${c.name} deleted.`))) categories.reload();
	}
</script>

<svelte:head><title>Policies</title></svelte:head>

<PageHeader
	title="Policies"
	description={scoped
		? `The sets ${scoped.name}'s devices can use: MSP-wide ones and ${scoped.name}'s own.`
		: 'Every device uses one policy set: its pin, else the set assigned to its site or client for its category, else the category’s default. Sets inherit from the set above them.'}
>
	{#snippet actions()}
		{#if tab === 'sets' && can('technician')}<Button variant="primary" icon={FolderPlus} onclick={() => (newSet = true)}>New set</Button>{/if}
		{#if tab === 'categories' && can('admin')}<Button variant="primary" icon={Plus} onclick={() => (editing = 'new')}>New category</Button>{/if}
	{/snippet}
</PageHeader>

<Tabs
	label="Policy sections"
	class="mb-4"
	value={tab}
	onchange={(v) => setParams({ tab: v === 'sets' ? null : v }, { push: true })}
	items={[
		{ value: 'sets', label: 'Policy sets', count: sets.data ? num(sets.data.length) : undefined },
		{ value: 'categories', label: 'Device categories', count: categories.data ? num(categories.data.length) : undefined },
		{ value: 'assignments', label: 'Assignments' }
	]}
/>

{#if tab === 'sets'}
	<section class="card" aria-label="Policy sets">
		<Async res={sets} compact>
			{#snippet children(rows)}
				<SetTree rows={treeOrder(rows ?? [])} categories={categories.data ?? []} />
			{/snippet}
		</Async>
	</section>
	<p class="text-muted mt-3 max-w-3xl text-xs">
		Patching, security, remote access and agent settings live once, in All devices; every set below can change single fields of them. Alert policies and scheduled scripts can be added to any set and reach every set below it.
	</p>
{:else if tab === 'categories'}
	{#snippet nameCell(c: Category)}
		<span class="font-medium">{c.name}</span>
		{#if c.description}<div class="text-muted max-w-md truncate text-xs">{c.description}</div>{/if}
	{/snippet}
	{#snippet kindCell(c: Category)}{#if c.builtin}<Badge>Built-in</Badge>{:else}<span class="text-muted">Custom</span>{/if}{/snippet}
	{#snippet setCell(c: Category)}<a class="link" href={setHref(c.default_set_id)}>{c.default_set_name}</a>{/snippet}
	{#snippet devCell(c: Category)}<a class="hover:text-accent tabular" href="/agents?category={c.id}" aria-label="{plural(c.devices, 'device')} in {c.name}">{num(c.devices)}</a>{/snippet}
	{#snippet actCell(c: Category)}
		{#if can('admin')}
			<div class="flex justify-end gap-1">
				<IconButton icon={Pencil} size="sm" label="Edit {c.name}" onclick={() => (editing = c)} />
				{#if !c.builtin}<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {c.name}" onclick={() => removeCategory(c)} />{/if}
			</div>
		{/if}
	{/snippet}
	<DataTable
		id="device-categories"
		caption="Device categories"
		rows={categories.data ?? []}
		key={(c) => c.id}
		loading={categories.loading}
		scroll={false}
		columns={[
			{ id: 'name', label: 'Category', cell: nameCell, hideable: false },
			{ id: 'kind', label: 'Kind', cell: kindCell, from: 'md' },
			{ id: 'set', label: 'Default policy set', cell: setCell },
			{ id: 'devices', label: 'Devices', cell: devCell, align: 'right' },
			{ id: 'actions', label: 'Actions', cell: actCell, align: 'right', hideable: false, class: 'w-24' }
		] satisfies Column<Category>[]}
	>
		{#snippet toolbar()}
			<p class="text-muted text-xs">New devices land in the built-in category for their OS and platform, and follow it while nobody moves them. Move devices from the Agents list; an enrollment token can name a category too.</p>
		{/snippet}
		{#snippet empty()}<EmptyState compact title="No categories" />{/snippet}
	</DataTable>
{:else if tab === 'assignments'}
	<section class="card" aria-labelledby="assign-h">
		<header class="panel-head flex-wrap">
			<div class="min-w-0">
				<h2 id="assign-h" class="panel-title">Assignments{scoped ? ` for ${scoped.name}` : ''}</h2>
				<p class="text-muted text-xs">Pick the set each device category uses, for the whole client or one site. A site's choice wins over the client's; empty cells say what applies instead.</p>
			</div>
			{#if !scoped}
				<Select
					aria-label="Client"
					class="w-full sm:w-56"
					value={clientId()}
					onchange={(e) => goto(`/policies?tab=assignments&client=${e.currentTarget.value}`, { replace: true })}
					options={[{ value: '', label: 'Choose a client…', disabled: true }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]}
				/>
			{/if}
		</header>
		{#if clientId()}
			{#key clientId()}<AssignmentGrid clientId={clientId()} />{/key}
		{:else}
			<EmptyState compact title="Choose a client" description="Assignments belong to one client; pick it above or with the client switcher." />
		{/if}
	</section>
{/if}

{#if newSet}<SetDialog mode="new" client={clientId() || null} onclose={() => (newSet = false)} ondone={(r) => goto(setHref(r.id))} />{/if}
{#if editing}<CategoryDialog category={editing === 'new' ? null : editing} onclose={() => (editing = null)} onsaved={() => categories.reload()} />{/if}
