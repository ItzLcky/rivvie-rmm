<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { ROOT_SET, treeOrder } from '#lib/policy/policy.js';
	import type { SetRow } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/**
	 * Creates a set below another, edits a set's name, description and place in the tree, or
	 * duplicates one (a sibling, optionally as one client's own).
	 */
	let {
		mode,
		set,
		parent,
		client,
		onclose,
		ondone
	}: {
		mode: 'new' | 'edit' | 'duplicate';
		/** The set being edited or duplicated. */
		set?: Pick<SetRow, 'id' | 'name' | 'description' | 'parent_id' | 'client_id' | 'client_name' | 'builtin'>;
		/** New: the parent to start from. */
		parent?: Pick<SetRow, 'id' | 'name' | 'client_id' | 'client_name'>;
		/** New: start as this client's own. */
		client?: string | null;
		onclose: () => void;
		ondone: (s: SetRow) => void;
	} = $props();

	$effect(() => {
		untrack(() => loadClients());
	});
	const sets = resource(() => api.get<SetRow[]>('/policy-sets'));

	// svelte-ignore state_referenced_locally
	const s = set;
	// svelte-ignore state_referenced_locally
	let name = $state(mode === 'duplicate' ? `Copy of ${s?.name}` : (s?.name ?? ''));
	let description = $state(untrack(() => (mode === 'edit' ? (s?.description ?? '') : '')));
	let parentId = $state(untrack(() => (mode === 'new' ? (parent?.id ?? ROOT_SET) : (s?.parent_id ?? ROOT_SET))));
	// The owner: null is MSP-wide. A child of a client's set always belongs to that client.
	let owner = $state<string | null>(untrack(() => (mode === 'edit' ? (s?.client_id ?? null) : (parent?.client_id ?? s?.client_id ?? client ?? null))));
	let busy = $state(false);

	const parentRow = $derived(sets.data?.find((x) => x.id === parentId));
	const parentOwner = $derived(mode === 'new' ? (parentRow?.client_id ?? parent?.client_id ?? null) : null);
	$effect(() => {
		if (parentOwner) untrack(() => (owner = parentOwner));
		else if (mode === 'new' && !can('admin') && !owner && clients.list.length) untrack(() => (owner = clients.list[0].id));
	});
	/** Sets it may go below: not itself or anything under it; a client's set only below MSP-wide sets or its own client's. */
	const parents = $derived.by(() => {
		const rows = treeOrder(sets.data ?? []);
		const under = new Set<string>();
		if (mode === 'edit' && s) {
			under.add(s.id);
			for (const r of rows) if (r.parent_id && under.has(r.parent_id)) under.add(r.id);
		}
		const own = mode === 'edit' ? s?.client_id : owner;
		return rows.filter((r) => !under.has(r.id) && r.depth < 8 && (!r.client_id || r.client_id === own));
	});
	const title = $derived(mode === 'new' ? 'New policy set' : mode === 'edit' ? `Edit ${s?.name}` : `Duplicate ${s?.name}`);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			let r: SetRow;
			if (mode === 'new') r = await api.post<SetRow>('/policy-sets', { name: name.trim(), description, parent_id: parentId, client_id: owner });
			else if (mode === 'edit')
				r = await api.put<SetRow>(`/policy-sets/${s!.id}`, { name: name.trim(), description, ...(s!.builtin || parentId === s!.parent_id ? {} : { parent_id: parentId }) });
			else r = await api.post<SetRow>(`/policy-sets/${s!.id}/duplicate`, { name: name.trim(), ...(owner && !s!.client_id ? { client_id: owner } : {}) });
			toast.success(mode === 'new' ? `${r.name} created. Nothing changes until it's assigned or pinned.` : mode === 'edit' ? 'Saved.' : `${r.name} created next to ${s!.name}.`);
			ondone(r);
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	const indent = (d: number) => ' '.repeat(Math.max(0, d));
</script>

<Modal
	{title}
	{onclose}
	size="md"
	description={mode === 'new'
		? 'It inherits every policy of the set above it. Override fields or add policies in it, then assign it to clients or sites.'
		: mode === 'duplicate'
			? 'A copy next to it with its own policies and overrides, not the sets below it.'
			: undefined}
>
	<form id="set-form" class="space-y-4" onsubmit={submit}>
		<Field label="Name" id="set-name" required>
			<!-- svelte-ignore a11y_autofocus -->
			<Input id="set-name" bind:value={name} required maxlength={200} autofocus autocomplete="off" placeholder="e.g. Kiosks, SQL servers" />
		</Field>
		{#if mode !== 'duplicate'}
			<Field label="Description" id="set-desc">
				<Textarea id="set-desc" rows={2} bind:value={description} maxlength={2000} placeholder="What it's for, and what it changes" />
			</Field>
		{/if}
		{#if mode !== 'duplicate' && !s?.builtin}
			<Field label="Below" id="set-parent" hint={mode === 'edit' ? 'Moving takes the sets below it along. Overrides of policies that no longer reach it are dropped.' : 'It inherits every policy of this set.'}>
				<Select id="set-parent" class="w-full" bind:value={parentId} options={parents.map((r) => ({ value: r.id, label: `${indent(r.depth)}${r.name}${r.client_name ? ` (${r.client_name})` : ''}` }))} />
			</Field>
		{/if}
		{#if mode === 'new' || (mode === 'duplicate' && !s?.client_id)}
			<Field label="Belongs to" id="set-owner" hint={parentOwner ? 'Sets below a client’s set belong to that client.' : 'A client’s own set can only be assigned to that client’s devices; technicians with access to it can change it.'}>
				<Select
					id="set-owner"
					class="w-full"
					bind:value={owner}
					disabled={!!parentOwner}
					options={[...(can('admin') ? [{ value: null, label: 'MSP-wide (every client)' }] : []), ...clients.list.map((c) => ({ value: c.id, label: c.name }))]}
				/>
			</Field>
		{/if}
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="set-form" loading={busy} disabled={!name.trim()}>{mode === 'new' ? 'Create set' : mode === 'edit' ? 'Save' : 'Duplicate'}</Button>
	{/snippet}
</Modal>
