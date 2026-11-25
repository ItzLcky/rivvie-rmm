<script lang="ts">
	import { ListChecks, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { checklistActions, type ChecklistAction, type TicketTemplate } from '#lib/identity.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { priorities } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { TicketMeta } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Ticket templates: onboarding, offboarding and other repeatable work, with a checklist. */
	let { meta }: { meta: TicketMeta | null } = $props();

	const list = resource(() => api.get<TicketTemplate[]>('/ticket-templates'));
	type Draft = { id: string | null; name: string; client_id: string; board_id: string; type_id: string; priority: string; subject: string; body: string; checklist: { text: string; action: ChecklistAction | '' }[] };
	let draft = $state<Draft | null>(null);
	let saving = $state(false);
	$effect(() => {
		loadClients();
	});

	function edit(t?: TicketTemplate) {
		draft = t
			? { id: t.id, name: t.name, client_id: t.client_id ?? '', board_id: t.board_id ?? '', type_id: t.type_id ?? '', priority: String(t.priority), subject: t.subject, body: t.body, checklist: t.checklist.map((c) => ({ text: c.text, action: c.action ?? '' })) }
			: { id: null, name: '', client_id: '', board_id: '', type_id: '', priority: '3', subject: '', body: '', checklist: [{ text: '', action: '' }] };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const d = draft!;
		const body = {
			name: d.name, client_id: d.client_id || null, board_id: d.board_id || null, type_id: d.type_id || null, priority: Number(d.priority), subject: d.subject, body: d.body,
			checklist: d.checklist.filter((c) => c.text.trim()).map((c) => ({ text: c.text, action: c.action || null }))
		};
		saving = true;
		const ok = await attempt(() => (d.id ? api.put(`/ticket-templates/${d.id}`, body) : api.post('/ticket-templates', body)), `${d.name} saved.`);
		saving = false;
		if (ok) {
			draft = null;
			list.reload();
		}
	}
	async function remove(t: TicketTemplate) {
		if (await confirmAction({ title: `Delete ${t.name}?`, message: 'Tickets already opened from it keep their checklists.', confirmLabel: 'Delete', danger: true })) {
			if (await attempt(() => api.del(`/ticket-templates/${t.id}`), `${t.name} deleted.`)) list.reload();
		}
	}
</script>

<section class="card" aria-labelledby="tpl-h">
	<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="tpl-h" class="font-semibold">Ticket templates</h2>
			<p class="text-muted text-xs">Opened from a directory user (Users tab of a client). Checklist items can disable the account, reset its password, remove it from groups or sign it out.</p>
		</div>
		<Button variant="primary" icon={Plus} onclick={() => edit()}>Add template</Button>
	</header>
	<Async res={list} compact>
		{#snippet children(rows)}
			{#if rows.length}
				<ul class="divide-border divide-y">
					{#each rows as t (t.id)}
						<li class="flex items-center gap-3 px-5 py-3 text-sm">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-1.5 font-medium">
									{t.name}
									{#if t.client_name}<Badge tone="info">{t.client_name} only</Badge>{/if}
									<Badge>{t.checklist.length} items</Badge>
									{#if t.checklist.some((c) => c.action)}<Badge tone="accent">{t.checklist.filter((c) => c.action).length} actions</Badge>{/if}
								</div>
								<div class="text-muted truncate text-xs">{t.subject || t.name}</div>
							</div>
							<IconButton icon={Pencil} size="sm" label="Edit {t.name}" onclick={() => edit(t)} />
							<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {t.name}" onclick={() => remove(t)} />
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState compact icon={ListChecks} title="No ticket templates" description="Add a new starter or leaver checklist." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if draft}
	<Modal title={draft.id ? `Edit ${draft.name}` : 'Add a ticket template'} onclose={() => (draft = null)} size="lg">
		<form id="tpl-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="tpl-name" required><Input id="tpl-name" bind:value={draft.name} required maxlength={100} placeholder="Leaver" /></Field>
				<Field label="For" id="tpl-client"><Select id="tpl-client" class="w-full" bind:value={draft.client_id} options={[{ value: '', label: 'Every client' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} /></Field>
			</div>
			<Field label="Subject" id="tpl-subject" hint="{'{name}'} becomes the directory user’s or contact’s name."><Input id="tpl-subject" bind:value={draft.subject} maxlength={300} placeholder="Leaver: {'{name}'}" /></Field>
			<Field label="Description" id="tpl-body" hint="The ticket’s first entry, as an internal note."><Textarea id="tpl-body" rows={3} bind:value={draft.body} /></Field>
			<div class="grid gap-3 sm:grid-cols-3">
				<Field label="Board" id="tpl-board"><Select id="tpl-board" class="w-full" bind:value={draft.board_id} options={[{ value: '', label: 'The first board' }, ...(meta?.boards ?? []).map((b) => ({ value: b.id, label: b.name }))]} /></Field>
				<Field label="Type" id="tpl-type"><Select id="tpl-type" class="w-full" bind:value={draft.type_id} options={[{ value: '', label: 'No type' }, ...(meta?.types ?? []).map((t) => ({ value: t.id, label: t.name }))]} /></Field>
				<Field label="Priority" id="tpl-prio"><Select id="tpl-prio" class="w-full" bind:value={draft.priority} options={priorities.map((p) => ({ value: String(p.value), label: p.label }))} /></Field>
			</div>
			<fieldset class="space-y-2">
				<legend class="mb-1 text-sm font-medium">Checklist</legend>
				{#each draft.checklist as item, i (i)}
					<div class="grid gap-1.5 sm:grid-cols-[1fr_16rem_auto]">
						<Input aria-label="Item {i + 1}" bind:value={item.text} maxlength={500} placeholder="What to do" />
						<Select aria-label="Action for item {i + 1}" class="w-full" bind:value={item.action} options={[{ value: '', label: 'Tick off by hand' }, ...checklistActions]} />
						<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove item {i + 1}" onclick={() => draft!.checklist.splice(i, 1)} />
					</div>
				{/each}
				<Button size="sm" variant="ghost" icon={Plus} onclick={() => draft!.checklist.push({ text: '', action: '' })}>Add item</Button>
			</fieldset>
		</form>
		{#snippet footer()}
			<Button onclick={() => (draft = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="tpl-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
