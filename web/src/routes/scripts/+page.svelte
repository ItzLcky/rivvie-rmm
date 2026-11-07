<script lang="ts">
	import { api } from '#lib/api.js';
	import { datetime, interpreters } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import type { Interpreter, Script } from '#lib/types.js';
	import Modal from '#lib/components/Modal.svelte';

	type Draft = { id?: string; name: string; description: string; interpreter: Interpreter; body: string; timeout_secs: number };
	let scripts = $state<Script[]>([]);
	let draft = $state<Draft | null>(null);
	let error = $state('');

	const load = () => api.get<Script[]>('/scripts').then((s) => (scripts = s));
	$effect(() => {
		load();
	});

	const blank = (): Draft => ({ name: '', description: '', interpreter: 'powershell', body: '', timeout_secs: 300 });

	async function save() {
		if (!draft) return;
		error = '';
		try {
			const { id, ...body } = draft;
			if (id) await api.put(`/scripts/${id}`, body);
			else await api.post('/scripts', body);
			draft = null;
			await load();
		} catch (e) {
			error = (e as Error).message;
		}
	}
	async function remove(s: Script) {
		if (!confirm(`Delete script "${s.name}"?`)) return;
		await api.del(`/scripts/${s.id}`);
		await load();
	}
</script>

<div class="mb-4 flex items-center justify-between">
	<h1 class="text-xl font-semibold">Script library</h1>
	{#if can('technician')}<button class="btn-primary" onclick={() => (draft = blank())}>New script</button>{/if}
</div>

<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Name</th><th>Interpreter</th><th>Timeout</th><th>Updated</th><th></th></tr></thead>
		<tbody>
			{#each scripts as s (s.id)}
				<tr>
					<td><div class="font-medium">{s.name}</div><div class="text-xs text-slate-500">{s.description}</div></td>
					<td>{interpreters.find((i) => i.value === s.interpreter)?.label ?? s.interpreter}</td>
					<td class="tabular-nums">{s.timeout_secs}s</td>
					<td class="text-xs text-slate-400">{datetime(s.updated_at)}</td>
					<td class="text-right">
						{#if can('technician')}
							<button class="btn-ghost py-1 text-xs" onclick={() => (draft = { ...s })}>Edit</button>
							<button class="btn-danger ml-1 py-1 text-xs" onclick={() => remove(s)}>Delete</button>
						{/if}
					</td>
				</tr>
			{:else}
				<tr><td colspan="5" class="py-8 text-center text-slate-500">No saved scripts. Run them from the Agents page once created.</td></tr>
			{/each}
		</tbody>
	</table>
</div>

{#if draft}
	<Modal title={draft.id ? 'Edit script' : 'New script'} onclose={() => (draft = null)} wide>
		<div class="space-y-3">
			<div class="grid grid-cols-3 gap-3">
				<div class="col-span-2"><label class="label" for="n">Name</label><input id="n" class="input" bind:value={draft.name} /></div>
				<div>
					<label class="label" for="i">Interpreter</label>
					<select id="i" class="input" bind:value={draft.interpreter}>
						{#each interpreters as i (i.value)}<option value={i.value}>{i.label}</option>{/each}
					</select>
				</div>
			</div>
			<div class="grid grid-cols-3 gap-3">
				<div class="col-span-2"><label class="label" for="d">Description</label><input id="d" class="input" bind:value={draft.description} /></div>
				<div><label class="label" for="t">Timeout (s)</label><input id="t" class="input" type="number" min="1" bind:value={draft.timeout_secs} /></div>
			</div>
			<div><label class="label" for="b">Body</label><textarea id="b" class="input h-72 font-mono text-xs" spellcheck="false" bind:value={draft.body}></textarea></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button class="btn-ghost" onclick={() => (draft = null)}>Cancel</button><button class="btn-primary" onclick={save}>Save</button></div>
		</div>
	</Modal>
{/if}
