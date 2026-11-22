<script lang="ts">
	import { Pencil, Pin, PinOff, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { AgentNote } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Notes on an agent: authored and timestamped, one of them pinned to the agent's header. Always shown as plain text. */
	let { agentId, onchange }: { agentId: string; onchange?: () => void } = $props();

	const notes = resource(() => api.get<AgentNote[]>(`/agents/${agentId}/notes`), { keep: false });
	let body = $state('');
	let pin = $state(false);
	let adding = $state(false);
	let editing = $state<{ id: string; body: string } | null>(null);

	async function add() {
		adding = true;
		const ok = await attempt(() => api.post(`/agents/${agentId}/notes`, { body, pinned: pin }), 'Note added.');
		adding = false;
		if (ok) {
			body = '';
			pin = false;
			await notes.reload();
			onchange?.();
		}
	}
	async function save() {
		const e = editing!;
		if (await attempt(() => api.put(`/agents/${agentId}/notes/${e.id}`, { body: e.body }), 'Note saved.')) {
			editing = null;
			await notes.reload();
			onchange?.();
		}
	}
	async function setPinned(n: AgentNote, pinned: boolean) {
		if (await attempt(() => api.put(`/agents/${agentId}/notes/${n.id}`, { pinned }))) {
			await notes.reload();
			onchange?.();
		}
	}
	async function remove(n: AgentNote) {
		const ok = await confirmAction({ title: 'Delete this note?', message: n.body.length > 140 ? `${n.body.slice(0, 140)}…` : n.body, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/agents/${agentId}/notes/${n.id}`), 'Note deleted.'))) {
			await notes.reload();
			onchange?.();
		}
	}
</script>

<div class="space-y-4">
	{#if can('technician')}
		<form
			class="card space-y-3 p-4"
			onsubmit={(e) => {
				e.preventDefault();
				add();
			}}
		>
			<label class="label" for="new-note">Add a note</label>
			<Textarea id="new-note" rows={3} maxlength={10000} placeholder="Gate code, who to call, what was tried…" bind:value={body} />
			<div class="flex flex-wrap items-center justify-between gap-2">
				<label class="text-muted inline-flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={pin} /> Pin to the agent's header</label>
				<Button variant="primary" type="submit" icon={Plus} loading={adding} disabled={!body.trim()}>Add note</Button>
			</div>
		</form>
	{/if}
	<Async res={notes}>
		{#snippet children(all)}
			{#if all.length}
				<ul class="space-y-3" aria-label="Notes">
					{#each all as n (n.id)}
						<li class="card p-4">
							<div class="mb-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
								<span class="font-medium">{n.author_name}</span>
								<time class="text-muted" datetime={n.created_at} title={datetime(n.created_at)}>{ago(n.created_at)}</time>
								{#if n.updated_at !== n.created_at}<span class="text-muted" title={datetime(n.updated_at)}>(edited)</span>{/if}
								{#if n.pinned}<Badge tone="accent" icon={Pin}>Pinned</Badge>{/if}
								<span class="ml-auto flex items-center">
									{#if can('technician')}<IconButton size="sm" icon={n.pinned ? PinOff : Pin} label={n.pinned ? 'Unpin' : 'Pin to the header'} onclick={() => setPinned(n, !n.pinned)} />{/if}
									{#if n.can_edit}
										<IconButton size="sm" icon={Pencil} label="Edit note" onclick={() => (editing = { id: n.id, body: n.body })} />
										<IconButton size="sm" icon={Trash2} label="Delete note" onclick={() => remove(n)} />
									{/if}
								</span>
							</div>
							{#if editing?.id === n.id}
								<form
									class="space-y-2"
									onsubmit={(e) => {
										e.preventDefault();
										save();
									}}
								>
									<Textarea rows={4} maxlength={10000} aria-label="Note text" bind:value={editing.body} />
									<div class="flex justify-end gap-2">
										<Button variant="ghost" type="button" onclick={() => (editing = null)}>Cancel</Button>
										<Button variant="primary" type="submit" disabled={!editing.body.trim()}>Save</Button>
									</div>
								</form>
							{:else}
								<p class="text-sm break-words whitespace-pre-wrap">{n.body}</p>
							{/if}
						</li>
					{/each}
				</ul>
			{:else}
				<div class="card"><EmptyState compact title="No notes yet" description="Write down what the next person should know about this machine." /></div>
			{/if}
		{/snippet}
	</Async>
</div>
