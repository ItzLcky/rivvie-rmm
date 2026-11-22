<script lang="ts">
	import { Plus } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Tag, TagRef } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import TagChip from './TagChip.svelte';

	/** Choose the tags of one agent, or make a new one on the spot. */
	let { agentId, hostname, current, onclose, ondone }: { agentId: string; hostname: string; current: TagRef[]; onclose: () => void; ondone: () => void } = $props();

	const tags = resource(() => api.get<Tag[]>('/tags'));
	// svelte-ignore state_referenced_locally
	let chosen = $state(new Set(current.map((t) => t.id)));
	let name = $state('');
	let saving = $state(false);

	function toggle(id: string, on: boolean) {
		const s = new Set(chosen);
		if (on) s.add(id);
		else s.delete(id);
		chosen = s;
	}
	async function create() {
		const n = name.trim();
		if (!n) return;
		const made = await attempt(async () => {
			const t = await api.post<Tag>('/tags', { name: n });
			await tags.reload();
			toggle(t.id, true);
		});
		if (made) name = '';
	}
	async function save() {
		saving = true;
		const ok = await attempt(() => api.put(`/agents/${agentId}/tags`, { tag_ids: [...chosen] }), 'Tags saved.');
		saving = false;
		if (ok) {
			ondone();
			onclose();
		}
	}
</script>

<Modal title="Tags" description={hostname} {onclose} size="sm">
	<Async res={tags} compact>
		{#snippet children(all)}
			{#if all.length}
				<ul class="mb-4 max-h-64 space-y-1.5 overflow-y-auto" aria-label="Tags">
					{#each all as t (t.id)}
						<li>
							<Checkbox checked={chosen.has(t.id)} onchange={(c) => toggle(t.id, c)}><TagChip name={t.name} color={t.color} /><span class="text-muted ml-2 text-xs">{t.agents} agent{t.agents === 1 ? '' : 's'}</span></Checkbox>
						</li>
					{/each}
				</ul>
			{:else}
				<p class="text-muted mb-4 text-sm">There are no tags yet. Make the first one below.</p>
			{/if}
		{/snippet}
	</Async>
	<form
		class="flex gap-2"
		onsubmit={(e) => {
			e.preventDefault();
			create();
		}}
	>
		<Input class="min-w-0 flex-1" placeholder="New tag…" aria-label="New tag name" maxlength={40} bind:value={name} />
		<Button type="submit" icon={Plus} disabled={!name.trim()}>Add</Button>
	</form>
	{#snippet footer()}
		<Button variant="ghost" onclick={onclose}>Cancel</Button>
		<Button variant="primary" loading={saving} onclick={save}>Save</Button>
	{/snippet}
</Modal>
