<script lang="ts">
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import type { Client, Site } from '#lib/types.js';
	import Modal from '#lib/components/Modal.svelte';

	interface Token { id: string; label: string; max_uses: number | null; uses: number; expires_at: string | null; created_at: string }
	interface NewToken { token: string; expires_at: string | null; install: { linux: string; windows: string } }

	let clients = $state<Client[]>([]);
	let newClient = $state('');
	let error = $state('');
	let tokenSite = $state<{ client: Client; site: Site } | null>(null);
	let tokens = $state<Token[]>([]);
	let created = $state<NewToken | null>(null);
	let label = $state('');
	let maxUses = $state<number | null>(null);
	let expiresHours = $state(168);

	const load = () => api.get<Client[]>('/clients').then((c) => (clients = c));
	$effect(() => {
		load();
	});

	async function act(fn: () => Promise<unknown>) {
		error = '';
		try {
			await fn();
			await load();
		} catch (e) {
			error = (e as Error).message;
		}
	}

	const addClient = (e: SubmitEvent) => {
		e.preventDefault();
		act(async () => {
			await api.post('/clients', { name: newClient });
			newClient = '';
		});
	};
	const addSite = (c: Client) => {
		const name = prompt(`New site name for ${c.name}`);
		if (name) act(() => api.post(`/clients/${c.id}/sites`, { name }));
	};
	const delClient = (c: Client) => confirm(`Delete ${c.name} and ALL its sites and agents?`) && act(() => api.del(`/clients/${c.id}`));
	const delSite = (s: Site) => confirm(`Delete site ${s.name} and its ${s.agent_count} agents?`) && act(() => api.del(`/sites/${s.id}`));

	async function openTokens(client: Client, site: Site) {
		tokenSite = { client, site };
		created = null;
		tokens = await api.get<Token[]>(`/sites/${site.id}/enrollment-tokens`);
	}
	async function createToken() {
		if (!tokenSite) return;
		created = await api.post<NewToken>(`/sites/${tokenSite.site.id}/enrollment-tokens`, {
			label,
			max_uses: maxUses || null,
			expires_in_hours: expiresHours
		});
		tokens = await api.get<Token[]>(`/sites/${tokenSite.site.id}/enrollment-tokens`);
	}
	async function revoke(t: Token) {
		await api.del(`/enrollment-tokens/${t.id}`);
		tokens = tokens.filter((x) => x.id !== t.id);
	}
</script>

<h1 class="mb-4 text-xl font-semibold">Clients & Sites</h1>

{#if can('admin')}
	<form class="mb-4 flex max-w-md gap-2" onsubmit={addClient}>
		<input class="input" placeholder="New client name" bind:value={newClient} required />
		<button class="btn-primary shrink-0">Add client</button>
	</form>
{/if}
{#if error}<p class="mb-3 text-sm text-red-400">{error}</p>{/if}

<div class="space-y-4">
	{#each clients as c (c.id)}
		<div class="card">
			<div class="flex items-center justify-between border-b border-slate-800 px-4 py-3">
				<a class="font-semibold hover:text-sky-400" href="/agents?client_id={c.id}">{c.name}</a>
				{#if can('admin')}
					<div class="flex gap-2"><button class="btn-ghost py-1 text-xs" onclick={() => addSite(c)}>Add site</button><button class="btn-danger py-1 text-xs" onclick={() => delClient(c)}>Delete</button></div>
				{/if}
			</div>
			<table class="table">
				<tbody>
					{#each c.sites as s (s.id)}
						<tr>
							<td>{s.name}</td>
							<td class="text-slate-400">{s.online_count} / {s.agent_count} online</td>
							<td class="text-right">
								{#if can('technician')}<button class="btn-ghost py-1 text-xs" onclick={() => openTokens(c, s)}>Enroll agents</button>{/if}
								{#if can('admin')}<button class="btn-danger ml-1 py-1 text-xs" onclick={() => delSite(s)}>Delete</button>{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="text-slate-500">No clients yet. Add one to start enrolling agents.</p>
	{/each}
</div>

{#if tokenSite}
	<Modal title="Enroll agents into {tokenSite.client.name} / {tokenSite.site.name}" onclose={() => (tokenSite = null)} wide>
		{#if created}
			<div class="mb-4 rounded-md border border-emerald-900 bg-emerald-950/30 p-3 text-sm">
				<p class="mb-2 text-emerald-300">Token created. Copy it now, it won't be shown again.</p>
				<div class="label">Linux (as root)</div>
				<pre class="mb-2 overflow-x-auto rounded bg-slate-950 p-2 font-mono text-xs select-all">{created.install.linux}</pre>
				<div class="label">Windows (elevated PowerShell)</div>
				<pre class="overflow-x-auto rounded bg-slate-950 p-2 font-mono text-xs select-all">{created.install.windows}</pre>
			</div>
		{/if}
		<div class="mb-4 grid grid-cols-3 gap-2">
			<div><label class="label" for="tl">Label</label><input id="tl" class="input" bind:value={label} placeholder="e.g. Office rollout" /></div>
			<div><label class="label" for="tm">Max uses</label><input id="tm" class="input" type="number" min="1" bind:value={maxUses} placeholder="Unlimited" /></div>
			<div>
				<label class="label" for="te">Expires</label>
				<select id="te" class="input" bind:value={expiresHours}>
					<option value={1}>1 hour</option><option value={24}>1 day</option><option value={168}>7 days</option><option value={720}>30 days</option><option value={0}>Never</option>
				</select>
			</div>
		</div>
		<button class="btn-primary mb-4" onclick={createToken}>Create enrollment token</button>
		<table class="table">
			<thead><tr><th>Label</th><th>Uses</th><th>Expires</th><th></th></tr></thead>
			<tbody>
				{#each tokens as t (t.id)}
					<tr>
						<td>{t.label || '–'}</td><td class="tabular-nums">{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ''}</td>
						<td class="text-xs text-slate-400">{t.expires_at ? datetime(t.expires_at) : 'never'}</td>
						<td class="text-right"><button class="btn-danger py-0.5 text-xs" onclick={() => revoke(t)}>Revoke</button></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</Modal>
{/if}
