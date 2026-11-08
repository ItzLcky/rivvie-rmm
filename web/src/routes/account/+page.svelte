<script lang="ts">
	import { api } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import Sessions from '#lib/components/Sessions.svelte';
	import TwoFactor from '#lib/components/TwoFactor.svelte';

	let form = $state({ current: '', next: '', confirm: '' });
	let error = $state('');
	let done = $state('');
	let busy = $state(false);
	// Bumped after a password change so the session list reloads (others were revoked).
	let gen = $state(0);

	async function change(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		done = '';
		if (form.next !== form.confirm) {
			error = 'New passwords do not match';
			return;
		}
		busy = true;
		try {
			const r = await api.post<{ sessions_revoked: number }>('/auth/password', { current_password: form.current, new_password: form.next });
			form = { current: '', next: '', confirm: '' };
			done = r.sessions_revoked ? `Password changed. Signed out ${r.sessions_revoked} other session${r.sessions_revoked === 1 ? '' : 's'}.` : 'Password changed.';
			gen++;
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<h1 class="mb-4 text-xl font-semibold">Account</h1>
<div class="grid max-w-5xl gap-6 lg:grid-cols-2">
	<section class="card p-4 {session.user?.mfa_setup_required ? 'lg:col-span-2 lg:max-w-xl' : ''}">
		<h2 class="mb-1 font-semibold">Two-factor authentication</h2>
		<p class="mb-3 text-xs text-slate-500">A code from an authenticator app on your phone, asked for at every sign-in.</p>
		<TwoFactor onchange={() => gen++} />
	</section>
	{#if !session.user?.mfa_setup_required}
	<section class="card p-4">
		<h2 class="mb-1 font-semibold">Change password</h2>
		<p class="mb-3 text-xs text-slate-500">{session.user?.email} · your other sessions will be signed out</p>
		<form class="space-y-3" onsubmit={change}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<div><label class="label" for="pc">Current password</label><input id="pc" class="input" type="password" autocomplete="current-password" required bind:value={form.current} /></div>
			<div><label class="label" for="pn">New password (min 12 chars)</label><input id="pn" class="input" type="password" autocomplete="new-password" required minlength="12" bind:value={form.next} /></div>
			<div><label class="label" for="pr">Repeat new password</label><input id="pr" class="input" type="password" autocomplete="new-password" required bind:value={form.confirm} /></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			{#if done}<p class="text-sm text-emerald-400">{done}</p>{/if}
			<div class="flex justify-end"><button class="btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Change password'}</button></div>
		</form>
	</section>
	<section class="card p-4">
		<h2 class="mb-1 font-semibold">Sessions</h2>
		<p class="mb-3 text-xs text-slate-500">Browsers and API clients signed in as you. Sessions end after a period of inactivity or 7 days.</p>
		{#key gen}<Sessions base="/auth/sessions" />{/key}
	</section>
	{/if}
</div>
