<script lang="ts">
	import { Pencil, ScrollText } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { FieldEntity, FieldValue } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** The custom fields of one agent, client or site, with their values; technicians edit them. */
	let { entity, id, title = 'Custom fields' }: { entity: FieldEntity; id: string; title?: string } = $props();

	const fields = resource(() => api.get<FieldValue[]>(`/${entity === 'agent' ? 'agents' : entity === 'client' ? 'clients' : 'sites'}/${id}/fields`), { keep: false });
	let editing = $state(false);
	let draft = $state<Record<string, string>>({});
	let saving = $state(false);

	const text = (v: FieldValue['value']) => (v === null ? '' : typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v));
	function edit(all: FieldValue[]) {
		draft = Object.fromEntries(all.map((f) => [f.name, f.kind === 'bool' ? (f.value === null ? '' : f.value ? 'yes' : 'no') : text(f.value)]));
		editing = true;
	}
	async function save(all: FieldValue[]) {
		// Only what changed: a script may have set the others meanwhile.
		const values: Record<string, string | null> = {};
		for (const f of all) {
			const d = draft[f.name].trim();
			if (d !== text(f.value)) values[f.name] = d === '' ? null : d;
		}
		if (!Object.keys(values).length) {
			editing = false;
			return;
		}
		saving = true;
		const ok = await attempt(async () => fields.set(await api.put<FieldValue[]>(`/${entity === 'agent' ? 'agents' : entity === 'client' ? 'clients' : 'sites'}/${id}/fields`, { values })), 'Fields saved.');
		saving = false;
		if (ok) editing = false;
	}
	const kinds = { text: 'text', number: 'number', date: 'date' } as const;
</script>

<Async res={fields} compact>
	{#snippet children(all)}
		{#if all.length}
			<section class="card p-4" aria-label={title}>
				<div class="mb-3 flex items-center justify-between gap-2">
					<h2 class="panel-title">{title}</h2>
					{#if can('technician') && !editing}<Button size="sm" icon={Pencil} onclick={() => edit(all)}>Edit</Button>{/if}
				</div>
				{#if editing}
					<form
						class="space-y-3"
						onsubmit={(e) => {
							e.preventDefault();
							save(all);
						}}
					>
						{#each all as f (f.field_id)}
							<div>
								<label class="label" for="field-{f.field_id}">{f.label}</label>
								{#if f.kind === 'select'}
									<Select id="field-{f.field_id}" bind:value={draft[f.name]} options={[{ value: '', label: '–' }, ...f.options.map((o) => ({ value: o, label: o }))]} />
								{:else if f.kind === 'bool'}
									<Select id="field-{f.field_id}" bind:value={draft[f.name]} options={[{ value: '', label: '–' }, { value: 'yes', label: 'Yes' }, { value: 'no', label: 'No' }]} />
								{:else}
									<Input id="field-{f.field_id}" type={kinds[f.kind as 'text' | 'number' | 'date']} step={f.kind === 'number' ? 'any' : undefined} bind:value={draft[f.name]} maxlength={2000} />
								{/if}
								{#if f.description}<p class="hint">{f.description}</p>{/if}
							</div>
						{/each}
						<div class="flex justify-end gap-2">
							<Button variant="ghost" type="button" onclick={() => (editing = false)}>Cancel</Button>
							<Button variant="primary" type="submit" loading={saving}>Save</Button>
						</div>
					</form>
				{:else}
					<dl class="dl">
						{#each all as f (f.field_id)}
							<dt title={f.description || undefined}>{f.label}</dt>
							<dd>
								{#if f.value === null}<span class="text-muted">–</span>{:else if f.kind === 'date'}{f.value}{:else}<span class="break-words whitespace-pre-line">{text(f.value)}</span>{/if}
								{#if f.source === 'script'}<Badge class="ml-1" icon={ScrollText} title="Set by a script {f.updated_at ? datetime(f.updated_at) : ''}">script</Badge>{/if}
								{#if f.updated_at}<span class="text-muted block text-xs">{ago(f.updated_at)}{f.updated_by_name ? ` by ${f.updated_by_name}` : ''}</span>{/if}
							</dd>
						{/each}
					</dl>
				{/if}
			</section>
		{/if}
	{/snippet}
</Async>
