<script lang="ts">
	import { api } from '#lib/api.js';
	import { plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Tag } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import TagChip from './TagChip.svelte';

	/** Add or remove tags on the selected agents; tags left alone stay as they are. */
	let { agentIds, onclose, ondone }: { agentIds: string[]; onclose: () => void; ondone: () => void } = $props();

	const tags = resource(() => api.get<Tag[]>('/tags'));
	let action = $state<Record<string, 'keep' | 'add' | 'remove'>>({});
	const add = $derived(Object.keys(action).filter((k) => action[k] === 'add'));
	const remove = $derived(Object.keys(action).filter((k) => action[k] === 'remove'));
	let saving = $state(false);

	async function save() {
		saving = true;
		const ok = await attempt(async () => {
			await api.post('/agents/tags', { agent_ids: agentIds, add, remove });
		}, `Tags changed on ${plural(agentIds.length, 'agent')}.`);
		saving = false;
		if (ok) {
			ondone();
			onclose();
		}
	}
</script>

<Modal title="Change tags" description={plural(agentIds.length, 'selected agent')} {onclose} size="sm">
	<Async res={tags} compact>
		{#snippet children(all)}
			{#if all.length}
				<ul class="space-y-2" aria-label="Tags">
					{#each all as t (t.id)}
						<li class="flex items-center justify-between gap-3">
							<TagChip name={t.name} color={t.color} />
							<Select
								class="w-32"
								aria-label="What to do with {t.name}"
								value={action[t.id] ?? 'keep'}
								onchange={(e) => (action[t.id] = e.currentTarget.value as 'keep' | 'add' | 'remove')}
								options={[{ value: 'keep', label: 'Leave' }, { value: 'add', label: 'Add' }, { value: 'remove', label: 'Remove' }]}
							/>
						</li>
					{/each}
				</ul>
			{:else}
				<p class="text-muted text-sm">There are no tags yet. Open an agent and add one first.</p>
			{/if}
		{/snippet}
	</Async>
	{#snippet footer()}
		<Button variant="ghost" onclick={onclose}>Cancel</Button>
		<Button variant="primary" loading={saving} disabled={!add.length && !remove.length} onclick={save}>Apply</Button>
	{/snippet}
</Modal>
