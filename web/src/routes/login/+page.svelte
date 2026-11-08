<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, ApiError } from '#lib/api.js';
	import { brand, session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import favicon from '#lib/assets/favicon.svg';

	let email = $state('');
	let password = $state('');
	let code = $state('');
	// Set once the password is accepted for an account with 2FA.
	let needCode = $state(false);
	let error = $state('');
	let busy = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			const res = await api.post<{ user: User }>('/auth/login', { email, password, code: needCode ? code : undefined });
			session.user = res.user;
			session.loaded = true;
			const next = page.url.searchParams.get('next');
			await goto(res.user.mfa_setup_required ? '/account' : next && next.startsWith('/') && !next.startsWith('//') ? next : '/');
		} catch (e) {
			if (e instanceof ApiError && e.data?.mfa_required) {
				error = needCode ? 'Invalid or already used code' : '';
				needCode = true;
				code = '';
			} else {
				error = 'Invalid email or password';
				needCode = false;
			}
		} finally {
			busy = false;
		}
	}

	function back() {
		needCode = false;
		code = '';
		error = '';
	}
</script>

<div class="flex min-h-screen items-center justify-center p-4">
	<form class="card w-full max-w-sm space-y-4 p-6" onsubmit={submit}>
		<div class="flex items-center gap-2 text-lg font-semibold"><img src={favicon} alt="" class="size-7" /> Sign in to {brand()}</div>
		{#if !needCode}
			<div>
				<label class="label" for="email">Email</label>
				<input id="email" class="input" type="email" autocomplete="username" required bind:value={email} />
			</div>
			<div>
				<label class="label" for="pw">Password</label>
				<input id="pw" class="input" type="password" autocomplete="current-password" required bind:value={password} />
			</div>
		{:else}
			<div>
				<label class="label" for="code">Two-factor code</label>
				<!-- svelte-ignore a11y_autofocus -->
				<input id="code" class="input font-mono tracking-widest" autocomplete="one-time-code" required autofocus maxlength="20" bind:value={code} />
				<p class="mt-1 text-xs text-slate-500">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
			</div>
		{/if}
		{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
		<button class="btn-primary w-full justify-center" disabled={busy}>{busy ? 'Signing in…' : needCode ? 'Verify' : 'Sign in'}</button>
		{#if needCode}
			<button type="button" class="w-full text-center text-xs text-slate-400 hover:text-slate-200" onclick={back}>Use a different account</button>
		{/if}
	</form>
</div>
