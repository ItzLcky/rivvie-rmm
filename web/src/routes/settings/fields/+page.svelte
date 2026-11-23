<script lang="ts">
	import { Pencil, Plus, ScrollText, Tag as TagIcon, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import type { CustomField, FieldEntity, FieldKind, Tag, TagColor } from '#lib/types.js';
	import { tagColors } from '#lib/components/tags/colors.js';
	import TagChip from '#lib/components/tags/TagChip.svelte';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	const tags = resource(() => api.get<Tag[]>('/tags'));
	const fields = resource(() => api.get<CustomField[]>('/custom-fields'));
	$effect(() => {
		loadClients();
	});
	let busy = $state(false);

	// --- tags -------------------------------------------------------------------------------------
	let tag = $state<{ id: string | null; name: string; color: TagColor } | null>(null);
	async function saveTag(e: SubmitEvent) {
		e.preventDefault();
		const t = tag!;
		busy = true;
		const ok = await attempt(() => (t.id ? api.put(`/tags/${t.id}`, { name: t.name, color: t.color }) : api.post('/tags', { name: t.name, color: t.color })), `${t.name} saved.`);
		busy = false;
		if (ok) {
			tag = null;
			tags.reload();
		}
	}
	async function removeTag(t: Tag) {
		const ok = await confirmAction({ title: `Delete the tag ${t.name}?`, message: t.agents ? `It is taken off ${plural(t.agents, 'agent')}.` : undefined, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/tags/${t.id}`), `${t.name} deleted.`))) tags.reload();
	}

	// --- custom fields ----------------------------------------------------------------------------------
	const entities: { value: FieldEntity; label: string }[] = [
		{ value: 'agent', label: 'Agents' },
		{ value: 'client', label: 'Clients' },
		{ value: 'site', label: 'Sites' }
	];
	const kinds: { value: FieldKind; label: string }[] = [
		{ value: 'text', label: 'Text' },
		{ value: 'number', label: 'Number' },
		{ value: 'bool', label: 'Yes / no' },
		{ value: 'date', label: 'Date' },
		{ value: 'select', label: 'Choice from a list' }
	];
	const kindLabel = (k: FieldKind) => kinds.find((x) => x.value === k)?.label ?? k;
	type Draft = { id: string | null; entity: FieldEntity; name: string; label: string; description: string; kind: FieldKind; options: string; client_id: string; script_writable: boolean };
	let draft = $state<Draft | null>(null);
	function edit(f?: CustomField, entity: FieldEntity = 'agent') {
		draft = f
			? { id: f.id, entity: f.entity, name: f.name, label: f.label, description: f.description, kind: f.kind, options: f.options.join('\n'), client_id: f.client_id ?? '', script_writable: f.script_writable }
			: { id: null, entity, name: '', label: '', description: '', kind: 'text', options: '', client_id: '', script_writable: false };
	}
	/** A name for scripts and the API from what's typed as the label, until the name is touched. */
	let nameTouched = $state(false);
	$effect(() => {
		if (draft && !draft.id && !nameTouched) draft.name = draft.label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^[^a-z]+|_+$/g, '').slice(0, 40);
	});
	async function saveField(e: SubmitEvent) {
		e.preventDefault();
		const d = draft!;
		const options = d.options.split('\n').map((o) => o.trim()).filter(Boolean);
		busy = true;
		const ok = await attempt(
			() =>
				d.id
					? api.put(`/custom-fields/${d.id}`, { label: d.label, description: d.description, script_writable: d.script_writable, ...(d.kind === 'select' ? { options } : {}) })
					: api.post('/custom-fields', { entity: d.entity, name: d.name, label: d.label, description: d.description, kind: d.kind, options, client_id: d.client_id || null, script_writable: d.script_writable }),
			`${d.label} saved.`
		);
		busy = false;
		if (ok) {
			draft = null;
			nameTouched = false;
			fields.reload();
		}
	}
	async function removeField(f: CustomField) {
		const ok = await confirmAction({
			title: `Delete the field ${f.label}?`,
			message: f.in_use ? `Its values on ${plural(f.in_use, f.entity)} are deleted with it. Scripts and integrations that set it will be refused.` : undefined,
			confirmLabel: 'Delete',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/custom-fields/${f.id}`), `${f.label} deleted.`))) fields.reload();
	}
</script>

<div class="max-w-4xl space-y-5">
	<section class="card" aria-labelledby="tags-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="tags-h" class="font-semibold">Tags</h2>
				<p class="text-muted text-xs">Labels for agents, shared by the whole team: "VIP", "Domain controller", "Pilot ring". Technicians add tags to agents; renaming and deleting them is for admins.</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => (tag = { id: null, name: '', color: 'slate' })}>Add tag</Button>
		</header>
		<Async res={tags} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as t (t.id)}
							<li class="flex items-center gap-3 px-5 py-2.5 text-sm">
								<span class="min-w-0 flex-1"><TagChip name={t.name} color={t.color} /></span>
								<a class="text-muted hover:text-fg text-xs" href="/agents?tag={t.id}">{plural(t.agents, 'agent')}</a>
								<IconButton icon={Pencil} size="sm" label="Edit {t.name}" onclick={() => (tag = { id: t.id, name: t.name, color: t.color })} />
								<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {t.name}" onclick={() => removeTag(t)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={TagIcon} title="No tags yet" description="Add one here, or from an agent's page." />
				{/if}
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-labelledby="fields-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="fields-h" class="font-semibold">Custom fields</h2>
				<p class="text-muted text-xs">
					Things you track that we don't collect: a warranty date, an account tier, the rack a server sits in. A field can apply to one client only.
					A script can fill an agent field by printing <code class="font-mono">RMM-FIELD name=value</code> when you mark it script-writable.
				</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => edit()}>Add field</Button>
		</header>
		<Async res={fields} compact>
			{#snippet children(list)}
				{#each entities as e (e.value)}
					{@const these = list.filter((f) => f.entity === e.value)}
					<h3 class="text-muted bg-sunken/50 border-border border-b px-5 py-1.5 text-xs font-medium">{e.label}</h3>
					{#if these.length}
						<ul class="divide-border divide-y">
							{#each these as f (f.id)}
								<li class="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
									<div class="min-w-0 flex-1">
										<div class="flex flex-wrap items-center gap-1.5 font-medium">
											{f.label}
											<span class="text-muted font-mono text-xs font-normal">{f.name}</span>
											<Badge>{kindLabel(f.kind)}</Badge>
											{#if f.script_writable}<Badge tone="info" icon={ScrollText} title="Scripts can set it with RMM-FIELD {f.name}=…">script-writable</Badge>{/if}
											{#if f.client_name}<Badge tone="accent">{f.client_name} only</Badge>{/if}
										</div>
										<div class="text-muted truncate text-xs">
											{#if f.kind === 'select'}{f.options.join(' · ')} · {/if}{plural(f.in_use, 'value')}{#if f.description} · {f.description}{/if}
										</div>
									</div>
									<IconButton icon={Pencil} size="sm" label="Edit {f.label}" onclick={() => edit(f)} />
									<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {f.label}" onclick={() => removeField(f)} />
								</li>
							{/each}
						</ul>
					{:else}
						<p class="text-muted px-5 py-3 text-sm">No fields for {e.label.toLowerCase()}. <button class="link cursor-pointer" onclick={() => edit(undefined, e.value)}>Add one</button></p>
					{/if}
				{/each}
			{/snippet}
		</Async>
	</section>
</div>

{#if tag}
	<Modal title={tag.id ? 'Edit tag' : 'New tag'} onclose={() => (tag = null)} size="sm">
		<form id="tag-form" class="space-y-4" onsubmit={saveTag}>
			<Field label="Name" id="tag-name"><Input id="tag-name" bind:value={tag.name} maxlength={40} required /></Field>
			<fieldset>
				<legend class="label">Colour</legend>
				<div class="flex flex-wrap gap-2">
					{#each tagColors as c (c)}
						<label class="cursor-pointer rounded-full has-[:checked]:ring-accent has-[:checked]:ring-2 has-[:checked]:ring-offset-2 has-[:checked]:ring-offset-raised">
							<input type="radio" class="sr-only" name="tag-color" value={c} bind:group={tag.color} />
							<TagChip name={c} color={c} />
						</label>
					{/each}
				</div>
			</fieldset>
		</form>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (tag = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="tag-form" loading={busy} disabled={!tag?.name.trim()}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if draft}
	<Modal title={draft.id ? `Edit ${draft.label}` : 'New custom field'} onclose={() => ((draft = null), (nameTouched = false))} size="md">
		<form id="field-form" class="space-y-4" onsubmit={saveField}>
			{#if !draft.id}
				<div class="grid gap-4 sm:grid-cols-2">
					<Field label="Applies to" id="f-entity">
						<Select id="f-entity" bind:value={draft.entity} options={entities} onchange={() => { if (draft!.entity === 'client') draft!.client_id = ''; if (draft!.entity !== 'agent') draft!.script_writable = false; }} />
					</Field>
					<Field label="Type" id="f-kind"><Select id="f-kind" bind:value={draft.kind} options={kinds} /></Field>
				</div>
			{/if}
			<Field label="Label" id="f-label" hint="What people read."><Input id="f-label" bind:value={draft.label} maxlength={80} required /></Field>
			{#if !draft.id}
				<Field label="Name" id="f-name" hint="What scripts and the API use: lowercase letters, digits and underscores. It can't change later.">
					<Input id="f-name" class="font-mono" bind:value={draft.name} maxlength={40} pattern="[a-z][a-z0-9_]*" required oninput={() => (nameTouched = true)} />
				</Field>
			{/if}
			{#if draft.kind === 'select'}
				<Field label="Choices" id="f-options" hint="One per line."><Textarea id="f-options" rows={4} bind:value={draft.options} /></Field>
			{/if}
			<Field label="Description" id="f-desc" hint="Shown next to the field."><Input id="f-desc" bind:value={draft.description} maxlength={500} /></Field>
			{#if !draft.id && draft.entity !== 'client'}
				<Field label="Only for one client" id="f-client">
					<Select id="f-client" bind:value={draft.client_id} options={[{ value: '', label: 'All clients' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
			{/if}
			{#if draft.entity === 'agent'}
				<div>
					<Switch bind:checked={draft.script_writable}>Scripts can set it</Switch>
					<p class="hint mt-1">A script run on an agent prints <code class="font-mono">RMM-FIELD {draft.name || 'name'}=value</code> and, when the job succeeds, the agent's field takes the value. Text a script copies from elsewhere (a log, a web page) could print one too, so leave it off for fields where that matters.</p>
				</div>
			{/if}
		</form>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => ((draft = null), (nameTouched = false))}>Cancel</Button>
			<Button variant="primary" type="submit" form="field-form" loading={busy} disabled={!draft?.label.trim() || (!draft?.id && !draft?.name)}>Save</Button>
		{/snippet}
	</Modal>
{/if}
