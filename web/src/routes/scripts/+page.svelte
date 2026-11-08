<script lang="ts">
	import { api } from '#lib/api.js';
	import { datetime, interpreters } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import type { Client, Interpreter, Script } from '#lib/types.js';
	import Modal from '#lib/components/Modal.svelte';

	type Draft = { id?: string; name: string; description: string; interpreter: Interpreter; body: string; timeout_secs: number; client_id: string | null };
	let scripts = $state<Script[]>([]);
	let clients = $state<Client[]>([]);
	let draft = $state<Draft | null>(null);
	let error = $state('');

	const load = () => api.get<Script[]>('/scripts').then((s) => (scripts = s));
	$effect(() => {
		load();
		api.get<Client[]>('/clients').then((c) => (clients = c));
	});

	// MSP-wide scripts run on every client, so only admins change them.
	const canEdit = (clientId: string | null) => (clientId === null ? can('admin') : can('technician'));
	const blank = (): Draft => ({
		name: '', description: '', interpreter: 'powershell', body: '', timeout_secs: 300,
		client_id: can('admin') ? null : (clients[0]?.id ?? null)
	});
	const edit = (s: Script): Draft => ({
		id: s.id, name: s.name, description: s.description, interpreter: s.interpreter, body: s.body, timeout_secs: s.timeout_secs, client_id: s.client_id
	});

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
	{#if can('admin') || (can('technician') && clients.length)}<button class="btn-primary" onclick={() => (draft = blank())}>New script</button>{/if}
</div>

<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Name</th><th>Scope</th><th>Interpreter</th><th>Timeout</th><th>Updated</th><th></th></tr></thead>
		<tbody>
			{#each scripts as s (s.id)}
				<tr>
					<td><div class="font-medium">{s.name}</div><div class="text-xs text-slate-500">{s.description}</div></td>
					<td class="text-xs">{#if s.client_name}{s.client_name}{:else}<span class="text-slate-400">All clients</span>{/if}</td>
					<td>{interpreters.find((i) => i.value === s.interpreter)?.label ?? s.interpreter}</td>
					<td class="tabular-nums">{s.timeout_secs}s</td>
					<td class="text-xs text-slate-400">{datetime(s.updated_at)}</td>
					<td class="text-right">
						{#if canEdit(s.client_id)}
							<button class="btn-ghost py-1 text-xs" onclick={() => (draft = edit(s))}>Edit</button>
							<button class="btn-danger ml-1 py-1 text-xs" onclick={() => remove(s)}>Delete</button>
						{/if}
					</td>
				</tr>
			{:else}
				<tr><td colspan="6" class="py-8 text-center text-slate-500">No saved scripts. Run them from the Agents page once created.</td></tr>
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
			<div>
				<label class="label" for="sc">Scope</label>
				<select id="sc" class="input" bind:value={draft.client_id}>
					{#if can('admin')}<option value={null}>All clients (MSP-wide)</option>{/if}
					{#each clients as c (c.id)}<option value={c.id}>{c.name} only</option>{/each}
				</select>
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
