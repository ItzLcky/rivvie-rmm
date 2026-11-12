<script lang="ts">
	import { MessageSquareText, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { categories, categoryOf, priorities } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { CannedResponse, Priority, StatusCategory } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	const list = resource(() => api.get<CannedResponse[]>('/canned-responses'));
	type Draft = { id: string | null; name: string; body: string; kind: 'reply' | 'note'; status_category: string; priority: string; assign: string; shared: boolean };
	let draft = $state<Draft | null>(null);
	let saving = $state(false);
	const variables = ['contact.first_name', 'contact.name', 'contact.email', 'client.name', 'ticket.number', 'ticket.subject', 'technician.name', 'technician.first_name', 'company.name'];

	function edit(c?: CannedResponse) {
		draft = c
			? { id: c.id, name: c.name, body: c.body, kind: c.kind, status_category: c.status_category ?? '', priority: c.priority ? String(c.priority) : '', assign: c.assign ?? '', shared: !c.owner_id }
			: { id: null, name: '', body: 'Hi {{contact.first_name}},\n\n\n\n{{technician.name}}', kind: 'reply', status_category: '', priority: '', assign: '', shared: true };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const d = draft!;
		const body = {
			name: d.name, body: d.body, kind: d.kind, shared: d.shared,
			status_category: (d.status_category || null) as StatusCategory | null,
			priority: d.priority ? (Number(d.priority) as Priority) : null,
			assign: d.assign || null
		};
		saving = true;
		const ok = await attempt(() => (d.id ? api.put(`/canned-responses/${d.id}`, body) : api.post('/canned-responses', body)), `${d.name} saved.`);
		saving = false;
		if (ok) {
			draft = null;
			list.reload();
		}
	}
	async function remove(c: CannedResponse) {
		if (await confirmAction({ title: `Delete ${c.name}?`, confirmLabel: 'Delete', danger: true })) {
			if (await attempt(() => api.del(`/canned-responses/${c.id}`), `${c.name} deleted.`)) list.reload();
		}
	}
</script>

<section class="card" aria-labelledby="canned-h">
	<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="canned-h" class="font-semibold">Canned responses and macros</h2>
			<p class="text-muted text-xs">Inserted from a ticket's reply box. A macro also sets the status, priority or assignee when the reply goes out.</p>
		</div>
		<Button variant="primary" icon={Plus} onclick={() => edit()}>Add response</Button>
	</header>
	<Async res={list} compact>
		{#snippet children(rows)}
			{#if rows.length}
				<ul class="divide-border divide-y">
					{#each rows as c (c.id)}
						<li class="flex items-center gap-3 px-5 py-3 text-sm">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-1.5 font-medium">
									{c.name}
									{#if c.kind === 'note'}<Badge tone="warning">Note</Badge>{/if}
									{#if !c.owner_id}<Badge>Shared</Badge>{:else}<Badge tone="info">Yours</Badge>{/if}
									{#if c.status_category}<Badge tone={categoryOf(c.status_category).tone}>→ {categoryOf(c.status_category).label}</Badge>{/if}
									{#if c.priority}<Badge>P{c.priority}</Badge>{/if}
									{#if c.assign}<Badge>{c.assign === 'me' ? 'Assign to me' : 'Unassign'}</Badge>{/if}
								</div>
								<div class="text-muted truncate text-xs">{c.body.replace(/\s+/g, ' ')}</div>
							</div>
							<IconButton icon={Pencil} size="sm" label="Edit {c.name}" onclick={() => edit(c)} />
							<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {c.name}" onclick={() => remove(c)} />
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState compact icon={MessageSquareText} title="No canned responses" description="Save the replies you type every day." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if draft}
	<Modal title={draft.id ? `Edit ${draft.name}` : 'Add canned response'} onclose={() => (draft = null)} size="lg">
		<form id="canned-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
				<Field label="Name" id="cr-name" required><Input id="cr-name" bind:value={draft.name} required maxlength={100} placeholder="Need more information" /></Field>
				<Segmented label="Kind" value={draft.kind} onchange={(v) => (draft!.kind = v)} options={[{ value: 'reply', label: 'Reply' }, { value: 'note', label: 'Internal note' }]} />
			</div>
			<Field label="Text" id="cr-body" hint="Variables: {variables.map((v) => `{{${v}}}`).join(' ')}">
				<Textarea id="cr-body" rows={8} bind:value={draft.body} />
			</Field>
			<div class="grid gap-3 sm:grid-cols-3">
				<Field label="Then set status" id="cr-status">
					<Select id="cr-status" class="w-full" bind:value={draft.status_category} options={[{ value: '', label: 'Keep status' }, ...categories.map((c) => ({ value: c.value, label: c.label }))]} />
				</Field>
				<Field label="Set priority" id="cr-prio">
					<Select id="cr-prio" class="w-full" bind:value={draft.priority} options={[{ value: '', label: 'Keep priority' }, ...priorities.map((p) => ({ value: String(p.value), label: p.label }))]} />
				</Field>
				<Field label="Assignee" id="cr-assign">
					<Select id="cr-assign" class="w-full" bind:value={draft.assign} options={[{ value: '', label: 'Keep assignee' }, { value: 'me', label: 'Assign to me' }, { value: 'none', label: 'Unassign' }]} />
				</Field>
			</div>
			<Segmented label="Who sees it" value={draft.shared ? 'shared' : 'mine'} onchange={(v) => (draft!.shared = v === 'shared')} options={[{ value: 'shared', label: 'Everyone' }, { value: 'mine', label: 'Only me' }]} />
		</form>
		{#snippet footer()}
			<Button onclick={() => (draft = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="canned-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
