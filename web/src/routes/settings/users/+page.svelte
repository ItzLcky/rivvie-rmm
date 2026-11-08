<script lang="ts">
	import { api } from '#lib/api.js';
	import { ago } from '#lib/format.js';
	import { session } from '#lib/session.svelte.js';
	import Modal from '#lib/components/Modal.svelte';
	import Sessions from '#lib/components/Sessions.svelte';

	interface UserRow { id: string; email: string; name: string; role: string; disabled: boolean; totp_enabled: boolean; last_login_at: string | null }
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
	async function enable(u: UserRow) {
		await api.post(`/users/${u.id}/enable`);
		await load();
	}

	let resetting = $state<UserRow | null>(null);
	let resetPw = $state('');
	let resetError = $state('');
	async function reset() {
		resetError = '';
		try {
			await api.post(`/users/${resetting!.id}/password`, { password: resetPw });
			resetting = null;
			resetPw = '';
		} catch (e) {
			resetError = (e as Error).message;
		}
	}

	let viewing = $state<UserRow | null>(null);

	let resetting2fa = $state<UserRow | null>(null);
	let reset2faError = $state('');
	async function reset2fa() {
		reset2faError = '';
		try {
			await api.del(`/users/${resetting2fa!.id}/totp`);
			resetting2fa = null;
			await load();
		} catch (e) {
			reset2faError = (e as Error).message;
		}
	}
</script>

<div class="mb-4 flex items-center justify-between">
	<p class="text-sm text-slate-400">People who can sign in to this console.</p>
	<button class="btn-primary" onclick={() => (adding = true)}>Add user</button>
</div>
<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Name</th><th>Email</th><th>Role</th><th>2FA</th><th>Last login</th><th></th></tr></thead>
		<tbody>
			{#each users as u (u.id)}
				<tr>
					<td class={u.disabled ? 'opacity-50' : ''}>{u.name}</td><td class={u.disabled ? 'opacity-50' : ''}>{u.email}</td><td class="capitalize {u.disabled ? 'opacity-50' : ''}">{u.role}</td><td class="text-xs {u.disabled ? 'opacity-50' : ''}">{#if u.totp_enabled}<span class="text-emerald-400">On</span>{:else if u.role === 'admin'}<span class="text-amber-300">Not set up</span>{:else}<span class="text-slate-500">Off</span>{/if}</td><td class="text-xs text-slate-400 {u.disabled ? 'opacity-50' : ''}">{ago(u.last_login_at)}</td>
					<td class="text-right">
						<div class="flex justify-end gap-1.5">
							{#if u.id === session.user?.id}
								<a class="btn-ghost py-1 text-xs" href="/account">Account</a>
							{:else if u.disabled}
								<span class="self-center text-xs text-slate-500">disabled</span>
								<button class="btn-ghost py-1 text-xs" onclick={() => enable(u)}>Enable</button>
							{:else}
								<button class="btn-ghost py-1 text-xs" onclick={() => (viewing = u)}>Sessions</button>
								<button class="btn-ghost py-1 text-xs" onclick={() => { resetting = u; resetPw = ''; resetError = ''; }}>Reset password</button>
								{#if u.totp_enabled}<button class="btn-ghost py-1 text-xs" onclick={() => { resetting2fa = u; reset2faError = ''; }}>Reset 2FA</button>{/if}
								<button class="btn-danger py-1 text-xs" onclick={() => disable(u)}>Disable</button>
							{/if}
						</div>
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

{#if resetting}
	<Modal title="Reset password for {resetting.email}" onclose={() => (resetting = null)}>
		<form class="space-y-3" onsubmit={(e) => { e.preventDefault(); reset(); }}>
			<p class="text-sm text-slate-400">Sets a new password and signs them out of every session. Share it with them over a separate channel.</p>
			<div><label class="label" for="rp">New password (min 12 chars)</label><input id="rp" class="input" type="password" autocomplete="new-password" bind:value={resetPw} /></div>
			{#if resetError}<p class="text-sm text-red-400">{resetError}</p>{/if}
			<div class="flex justify-end gap-2"><button type="button" class="btn-ghost" onclick={() => (resetting = null)}>Cancel</button><button class="btn-primary">Reset password</button></div>
		</form>
	</Modal>
{/if}

{#if viewing}
	<Modal title="Sessions for {viewing.email}" onclose={() => (viewing = null)}>
		<Sessions base="/users/{viewing.id}/sessions" revokeAllLabel="Revoke all" />
	</Modal>
{/if}

{#if resetting2fa}
	<Modal title="Reset 2FA for {resetting2fa.email}" onclose={() => (resetting2fa = null)}>
		<div class="space-y-3">
			<p class="text-sm text-slate-400">Removes their authenticator and recovery codes and signs them out everywhere. Do this when they've lost their phone, after confirming it's really them. If 2FA is required for them, they set it up again at their next sign-in.</p>
			{#if reset2faError}<p class="text-sm text-red-400">{reset2faError}</p>{/if}
			<div class="flex justify-end gap-2"><button class="btn-ghost" onclick={() => (resetting2fa = null)}>Cancel</button><button class="btn-danger" onclick={reset2fa}>Reset 2FA</button></div>
		</div>
	</Modal>
{/if}
