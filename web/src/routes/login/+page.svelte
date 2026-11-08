<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, ApiError } from '#lib/api.js';
	import { brand, session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import favicon from '#lib/assets/favicon.svg';
	import { loadPrefs } from '#lib/prefs.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';

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
			loadPrefs(res.user.preferences);
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

<div class="bg-surface flex min-h-dvh flex-col items-center justify-center p-4">
	<div class="w-full max-w-sm">
		<div class="mb-6 flex flex-col items-center gap-3 text-center">
			<img src={favicon} alt="" class="size-10" />
			<h1 class="text-xl font-semibold tracking-tight">Sign in to {brand()}</h1>
		</div>
		<form class="card space-y-4 p-6" onsubmit={submit}>
			{#if !needCode}
				<Field label="Email" id="email"><Input id="email" type="email" autocomplete="username" required bind:value={email} /></Field>
				<Field label="Password" id="pw"><Input id="pw" type="password" autocomplete="current-password" required bind:value={password} /></Field>
			{:else}
				<Field label="Two-factor code" id="code" hint="The 6-digit code from your authenticator app, or one of your recovery codes.">
					<!-- svelte-ignore a11y_autofocus -->
					<Input id="code" class="font-mono tracking-widest" autocomplete="one-time-code" required autofocus maxlength={20} bind:value={code} />
				</Field>
			{/if}
			{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
			<Button variant="primary" type="submit" class="w-full" loading={busy}>{needCode ? 'Verify' : 'Sign in'}</Button>
			{#if needCode}
				<button type="button" class="text-muted hover:text-fg w-full text-center text-xs" onclick={back}>Use a different account</button>
			{/if}
		</form>
	</div>
</div>
