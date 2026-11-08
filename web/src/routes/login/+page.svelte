<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { brand, session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import favicon from '#lib/assets/favicon.svg';

	let email = $state('');
	let password = $state('');
	let error = $state('');
	let busy = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			const res = await api.post<{ user: User }>('/auth/login', { email, password });
			session.user = res.user;
			session.loaded = true;
			const next = page.url.searchParams.get('next');
			await goto(next && next.startsWith('/') && !next.startsWith('//') ? next : '/');
		} catch {
			error = 'Invalid email or password';
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center p-4">
	<form class="card w-full max-w-sm space-y-4 p-6" onsubmit={submit}>
		<div class="flex items-center gap-2 text-lg font-semibold"><img src={favicon} alt="" class="size-7" /> Sign in to {brand()}</div>
		<div>
			<label class="label" for="email">Email</label>
			<input id="email" class="input" type="email" autocomplete="username" required bind:value={email} />
		</div>
		<div>
			<label class="label" for="pw">Password</label>
			<input id="pw" class="input" type="password" autocomplete="current-password" required bind:value={password} />
		</div>
		{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
		<button class="btn-primary w-full justify-center" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
	</form>
</div>
