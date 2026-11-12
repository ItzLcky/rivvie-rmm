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
	import { Activity, LifeBuoy, PackageCheck } from '@lucide/svelte';

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

<div class="bg-raised grid min-h-dvh lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
	<!-- Brand panel: navy like the navigation rail. Hidden on small screens, where the form is all there is. -->
	<aside class="brand-panel bg-nav text-nav-fg relative hidden flex-col justify-between overflow-hidden p-10 lg:flex xl:p-14">
		<div class="relative flex items-center gap-3">
			<img src={favicon} alt="" class="size-8" />
			<span class="text-[0.9375rem] font-semibold tracking-tight text-white">{brand()}</span>
		</div>
		<div class="relative max-w-md">
			<h2 class="text-3xl leading-tight font-semibold tracking-tight text-white xl:text-4xl">Monitor, patch and support every client device from one console.</h2>
			<ul class="text-nav-muted mt-8 space-y-3 text-sm">
				<li class="flex items-center gap-3"><Activity class="text-nav-indicator size-4 shrink-0" />Live health, alerts and remote sessions</li>
				<li class="flex items-center gap-3"><PackageCheck class="text-nav-indicator size-4 shrink-0" />Patch policies with maintenance windows</li>
				<li class="flex items-center gap-3"><LifeBuoy class="text-nav-indicator size-4 shrink-0" />Tickets linked to the machines they are about</li>
			</ul>
		</div>
		<p class="text-nav-label relative text-xs">Authorized technicians only. Sign-ins are recorded in the audit log.</p>
	</aside>

	<main class="flex flex-col items-center justify-center px-4 py-10 sm:px-8">
		<div class="w-full max-w-sm">
			<div class="mb-8">
				<img src={favicon} alt="" class="mb-6 size-9 lg:hidden" />
				<h1 class="text-2xl font-semibold tracking-tight">{needCode ? 'Two-factor verification' : 'Sign in'}</h1>
				<p class="text-muted mt-1.5 text-sm">{needCode ? 'Enter the code from your authenticator app.' : `Use your ${brand()} account.`}</p>
			</div>
			<form class="space-y-5" onsubmit={submit}>
				{#if !needCode}
					<Field label="Email" id="email"><Input id="email" type="email" autocomplete="username" required bind:value={email} class="h-10" /></Field>
					<Field label="Password" id="pw"><Input id="pw" type="password" autocomplete="current-password" required bind:value={password} class="h-10" /></Field>
				{:else}
					<Field label="Two-factor code" id="code" hint="The 6-digit code from your authenticator app, or one of your recovery codes.">
						<!-- svelte-ignore a11y_autofocus -->
						<Input id="code" class="h-10 font-mono tracking-widest" autocomplete="one-time-code" required autofocus maxlength={20} bind:value={code} />
					</Field>
				{/if}
				{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
				<Button variant="primary" type="submit" class="h-10 w-full" loading={busy}>{needCode ? 'Verify' : 'Sign in'}</Button>
				{#if needCode}
					<button type="button" class="text-muted hover:text-fg w-full text-center text-sm" onclick={back}>Use a different account</button>
				{/if}
			</form>
		</div>
	</main>
</div>

<style>
	/* A soft light source in the top corner, in the accent's hue: depth without decoration. */
	.brand-panel::before {
		content: '';
		position: absolute;
		inset: 0;
		background:
			radial-gradient(60% 50% at 100% 0%, rgb(91 154 255 / 0.22), transparent 70%),
			radial-gradient(50% 40% at 0% 100%, rgb(91 154 255 / 0.08), transparent 70%);
		pointer-events: none;
	}
</style>
