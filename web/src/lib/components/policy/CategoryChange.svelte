<script lang="ts">
	import { api } from '#lib/api.js';
	import { plural } from '#lib/format.js';
	import type { Category } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** Moves devices to a device category, or back to automatic placement. */
	let { agentIds, current = '', onclose, ondone }: { agentIds: string[]; current?: string; onclose: () => void; ondone: () => void } = $props();

	const categories = resource(() => api.get<Category[]>('/device-categories'));
	// svelte-ignore state_referenced_locally
	let value = $state(current);
	let busy = $state(false);
	const what = $derived(agentIds.length === 1 ? 'this device' : plural(agentIds.length, 'device'));

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const r = await api.post<{ changed: number; moved: number }>('/agents/category', { agent_ids: agentIds, category_id: value || null });
			toast.success(`${value ? `Moved ${plural(r.changed, 'device')}` : `${plural(r.changed, 'device')} placed automatically again`}; ${r.moved ? `${plural(r.moved, 'device')} now use${r.moved === 1 ? 's' : ''} another policy set` : 'none changed policy set'}.`);
			ondone();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Change category" {onclose} size="sm" description="The category decides which policy set {what} use{agentIds.length === 1 ? 's' : ''}, unless a site, client or pin says otherwise.">
	<form id="cat-change" onsubmit={save}>
		<Field label="Category" id="cc-cat" hint={value ? 'Moved by hand: it stays there whatever the device reports.' : 'The built-in category for its OS and platform, updated when the device reports them.'}>
			<Select id="cc-cat" class="w-full" bind:value options={[{ value: '', label: 'Automatic (by OS and platform)' }, ...(categories.data ?? []).map((c) => ({ value: c.id, label: c.name }))]} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="cat-change" loading={busy}>Move</Button>
	{/snippet}
</Modal>
