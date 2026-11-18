<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { treeOrder } from '#lib/policy/policy.js';
	import type { Category, SetRow } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Creates a device category, or edits one (a built-in one: only its default set). */
	let { category, onclose, onsaved }: { category: Category | null; onclose: () => void; onsaved: () => void } = $props();

	// svelte-ignore state_referenced_locally
	const c = category;
	let name = $state(c?.name ?? '');
	let description = $state(c?.description ?? '');
	let setId = $state(untrack(() => c?.default_set_id ?? ''));
	let busy = $state(false);
	const sets = resource(() => api.get<SetRow[]>('/policy-sets'));
	const options = $derived(treeOrder((sets.data ?? []).filter((s) => !s.client_id)).map((s) => ({ value: s.id, label: `${' '.repeat(s.depth)}${s.name}` })));

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const body = c?.builtin ? { default_set_id: setId } : { name: name.trim(), description, default_set_id: setId };
			if (c) await api.put(`/device-categories/${c.id}`, body);
			else await api.post('/device-categories', body);
			toast.success(c ? 'Saved. Its devices use the new default unless they’re assigned another set.' : `${name.trim()} created. Move devices into it from the Agents list.`);
			onsaved();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal
	title={c ? `Edit ${c.name}` : 'New device category'}
	{onclose}
	size="md"
	description={c?.builtin ? 'A built-in category: devices land here by operating system and platform. Its name can’t change.' : 'A folder of devices you fill by hand (or with an enrollment token), such as kiosks or SQL servers.'}
>
	<form id="cat-form" class="space-y-4" onsubmit={save}>
		<Field label="Name" id="cat-name" required>
			<!-- svelte-ignore a11y_autofocus -->
			<Input id="cat-name" bind:value={name} required maxlength={200} disabled={c?.builtin} autofocus={!c?.builtin} placeholder="e.g. Kiosks" />
		</Field>
		{#if !c?.builtin}
			<Field label="Description" id="cat-desc"><Textarea id="cat-desc" rows={2} bind:value={description} maxlength={2000} /></Field>
		{/if}
		<Field label="Default policy set" id="cat-set" required hint="Devices in it use this set unless their client or site is assigned another for this category, or they're pinned. Only MSP-wide sets.">
			<Select id="cat-set" class="w-full" bind:value={setId} options={[{ value: '', label: 'Choose a set…', disabled: true }, ...options]} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="cat-form" loading={busy} disabled={!setId || !name.trim()}>{c ? 'Save' : 'Create category'}</Button>
	{/snippet}
</Modal>
