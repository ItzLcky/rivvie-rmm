<script lang="ts">
	import { api } from '#lib/api.js';
	import { ago } from '#lib/format.js';
	import { session } from '#lib/session.svelte.js';
	import Modal from '#lib/components/Modal.svelte';

	interface UserRow { id: string; email: string; name: string; role: string; disabled: boolean; last_login_at: string | null }
	let users = $state<UserRow[]>([]);
	let adding = $state(false);
	let form = $state({ email: '', name: '', password: '', role: 'technician' });
	let error = $state('');

	const load = () => api.get<UserRow[]>('/users').then((u) => (users = u));
	$effect(() => {
		load();
	});

	async function add() {
		error = '';
		try {
			await api.post('/users', form);
			adding = false;
			form = { email: '', name: '', password: '', role: 'technician' };
			await load();
		} catch (e) {
			error = (e as Error).message;
		}
	}
	async function disable(u: UserRow) {
		if (!confirm(`Disable ${u.email}? Their sessions will be revoked.`)) return;
		await api.del(`/users/${u.id}`);
		await load();
	}
</script>

<div class="mb-4 flex items-center justify-between">
	<h1 class="text-xl font-semibold">Users</h1>
	<button class="btn-primary" onclick={() => (adding = true)}>Add user</button>
</div>
<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Last login</th><th></th></tr></thead>
		<tbody>
			{#each users as u (u.id)}
				<tr class={u.disabled ? 'opacity-50' : ''}>
					<td>{u.name}</td><td>{u.email}</td><td class="capitalize">{u.role}</td><td class="text-xs text-slate-400">{ago(u.last_login_at)}</td>
					<td class="text-right">
						{#if u.disabled}<span class="text-xs text-slate-500">disabled</span>{:else if u.id !== session.user?.id}<button class="btn-danger py-1 text-xs" onclick={() => disable(u)}>Disable</button>{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

{#if adding}
	<Modal title="Add user" onclose={() => (adding = false)}>
		<div class="space-y-3">
			<div><label class="label" for="ue">Email</label><input id="ue" class="input" type="email" bind:value={form.email} /></div>
			<div><label class="label" for="un">Name</label><input id="un" class="input" bind:value={form.name} /></div>
			<div><label class="label" for="up">Password (min 12 chars)</label><input id="up" class="input" type="password" autocomplete="new-password" bind:value={form.password} /></div>
			<div>
				<label class="label" for="ur">Role</label>
				<select id="ur" class="input" bind:value={form.role}>
					<option value="admin">Admin: everything, including users and clients</option>
					<option value="technician">Technician: scripts, terminal, enrollment</option>
					<option value="readonly">Read-only: view only</option>
				</select>
			</div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button class="btn-ghost" onclick={() => (adding = false)}>Cancel</button><button class="btn-primary" onclick={add}>Create</button></div>
		</div>
	</Modal>
{/if}
