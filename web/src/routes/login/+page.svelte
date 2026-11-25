<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, ApiError } from '#lib/api.js';
	import { brand, company, session } from '#lib/session.svelte.js';
	import SourceLink from '#lib/components/branding/SourceLink.svelte';
	import type { User } from '#lib/types.js';
	import favicon from '#lib/assets/favicon.svg';
	import { loadPrefs } from '#lib/prefs.svelte.js';
	import { cancelled, passkeysSupported, usePasskey } from '#lib/webauthn.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import { Activity, Building2, KeyRound, LifeBuoy, PackageCheck } from '@lucide/svelte';

	interface Methods { totp: boolean; passkey: boolean }
	interface SsoProvider { id: string; name: string; preset: string }

	let email = $state('');
	let password = $state('');
	let code = $state('');
	// Set once the password is accepted for an account with a second factor.
	let second = $state<Methods | null>(null);
	let error = $state(page.url.searchParams.has('sso_error') ? ssoMessage(page.url.searchParams.get('sso_error')!) : '');
	let busy = $state(false);
	let providers = $state<SsoProvider[]>([]);
	let ssoRequired = $state(false);
	// With SSO required, the password form is for break-glass accounts and stays tucked away.
	let showPassword = $state(false);

	function ssoMessage(code: string): string {
		const messages: Record<string, string> = {
			not_allowed: 'This account isn’t allowed to sign in with that provider. Ask an admin to check your access.',
			no_account: 'There’s no account for that email address. Ask an admin to add you.',
			provider_denied: 'The sign-in was cancelled or refused at the identity provider.',
			provider_error: 'The identity provider isn’t answering. Try again, or use a password if you have one.',
			expired: 'That sign-in expired. Start again.',
			too_many: 'Too many attempts. Wait a minute and try again.'
		};
		return messages[code] ?? 'Single sign-on failed. Try again, or ask an admin to check the audit log.';
	}

	$effect(() => {
		fetch('/api/auth/sso/providers')
			.then((r) => (r.ok ? r.json() : null))
			.then((d: { providers: SsoProvider[]; sso_required: boolean } | null) => {
				if (!d) return;
				providers = d.providers;
				ssoRequired = d.sso_required && d.providers.length > 0;
			})
			.catch(() => {});
	});

	const next = $derived.by(() => {
		const n = page.url.searchParams.get('next');
		return n && n.startsWith('/') && !n.startsWith('//') ? n : '/';
	});
	const ssoHref = (p: SsoProvider) => `/api/auth/sso/${p.id}/start${next === '/' ? '' : `?next=${encodeURIComponent(next)}`}`;

	async function signedIn(res: { user: User }) {
		session.user = res.user;
		session.loaded = true;
		loadPrefs(res.user.preferences);
		await goto(res.user.mfa_setup_required ? '/account' : next);
	}

	/** Sends the credentials with whichever second factor the person has given. */
	async function login(extra: Record<string, unknown> = {}) {
		busy = true;
		error = '';
		try {
			await signedIn(await api.post<{ user: User }>('/auth/login', { email, password, ...extra }));
		} catch (e) {
			if (e instanceof ApiError && e.data?.mfa_required) {
				const m = (e.data.methods as Methods | undefined) ?? { totp: true, passkey: false };
				error = second ? (extra.passkey ? 'That passkey wasn’t accepted' : 'Invalid or already used code') : '';
				second = m;
				code = '';
			} else if (e instanceof ApiError && e.status === 403) {
				error = e.message;
				second = null;
			} else if (e instanceof ApiError && e.status === 429) {
				error = e.message;
			} else {
				error = ssoRequired ? 'Invalid email or password. With single sign-on required, only break-glass accounts can use a password.' : 'Invalid email or password';
				second = null;
			}
		} finally {
			busy = false;
		}
	}

	function submit(e: SubmitEvent) {
		e.preventDefault();
		return login(second ? { code } : {});
	}

	async function withPasskey() {
		busy = true;
		error = '';
		try {
			const ch = await api.post<{ ceremony_id: string; options: Parameters<typeof usePasskey>[0] }>('/auth/login/passkey', { email, password });
			const credential = await usePasskey(ch.options);
			busy = false;
			await login({ passkey: { ceremony_id: ch.ceremony_id, credential } });
		} catch (e) {
			error = cancelled(e) ? 'The passkey prompt was closed or timed out.' : (e as Error).message;
			busy = false;
		}
	}

	function back() {
		second = null;
		code = '';
		error = '';
	}
</script>

<div class="bg-raised grid min-h-dvh lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
	<!-- Brand panel: navy like the navigation rail. Hidden on small screens, where the form is all there is. -->
	<aside class="bg-nav text-nav-fg relative hidden flex-col justify-between overflow-hidden p-10 lg:flex xl:p-14">
		<div class="relative flex items-center gap-3">
			{#if company.branding?.logo_dark || company.branding?.logo_light}
				<img src={company.branding.logo_dark ?? company.branding.logo_light} alt={brand()} class="h-10 max-w-[16rem] object-contain object-left" />
			{:else}
				<img src={company.branding?.icon ?? favicon} alt="" class="size-8" />
				<span class="text-[0.9375rem] font-semibold tracking-tight text-white">{brand()}</span>
			{/if}
		</div>
		<div class="relative max-w-md">
			<h2 class="text-3xl leading-tight font-medium tracking-tight text-white xl:text-4xl">Monitor, patch and support every client device from one console.</h2>
			<ul class="text-nav-muted mt-8 space-y-3 text-sm">
				<li class="flex items-center gap-3"><Activity class="text-nav-indicator size-4 shrink-0" />Live health, alerts and remote sessions</li>
				<li class="flex items-center gap-3"><PackageCheck class="text-nav-indicator size-4 shrink-0" />Patch policies with maintenance windows</li>
				<li class="flex items-center gap-3"><LifeBuoy class="text-nav-indicator size-4 shrink-0" />Tickets linked to the machines they are about</li>
			</ul>
		</div>
		<p class="text-nav-label relative text-xs">Authorized technicians only. Sign-ins are recorded in the audit log. · <SourceLink href={company.branding?.source_url} /></p>
	</aside>

	<main class="flex flex-col items-center justify-center px-4 py-10 sm:px-8">
		<div class="w-full max-w-sm">
			<div class="mb-8">
				<img src={company.branding?.icon ?? favicon} alt="" class="mb-6 size-9 lg:hidden" />
				<h1 class="text-2xl font-medium">{second ? 'Two-factor verification' : 'Sign in'}</h1>
				<p class="text-muted mt-1.5 text-sm">
					{#if !second}Use your {brand()} account.
					{:else if second.passkey && second.totp}Use a passkey, or enter the code from your authenticator app.
					{:else if second.passkey}Use a passkey, or enter one of your recovery codes.
					{:else}Enter the code from your authenticator app.{/if}
				</p>
			</div>
			{#if !second && providers.length > 0}
				<div class="space-y-2.5" role="group" aria-label="Single sign-on">
					{#each providers as p (p.id)}
						<Button href={ssoHref(p)} variant={ssoRequired ? 'primary' : 'secondary'} class="h-10 w-full" icon={Building2}>Sign in with {p.name}</Button>
					{/each}
				</div>
				{#if error && !showPassword && ssoRequired}<p class="bg-danger-soft text-danger mt-4 rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
				{#if ssoRequired && !showPassword}
					<button type="button" class="text-muted hover:text-fg mt-6 w-full text-center text-sm" onclick={() => (showPassword = true)}>Use a password (break-glass accounts)</button>
				{:else}
					<div class="text-muted my-5 flex items-center gap-3 text-xs"><span class="bg-border h-px flex-1"></span>or<span class="bg-border h-px flex-1"></span></div>
				{/if}
			{/if}
			{#if second || !ssoRequired || showPassword}
				<form class="space-y-5" onsubmit={submit}>
					{#if !second}
						<Field label="Email" id="email"><Input id="email" type="email" autocomplete="username" required bind:value={email} class="h-10" /></Field>
						<Field label="Password" id="pw"><Input id="pw" type="password" autocomplete="current-password" required bind:value={password} class="h-10" /></Field>
					{:else}
						{#if second.passkey && passkeysSupported()}
							<Button variant="primary" icon={KeyRound} class="h-10 w-full" loading={busy} onclick={withPasskey}>Use a passkey</Button>
						{/if}
						<Field label={second.totp ? 'Two-factor code' : 'Recovery code'} id="code" hint={second.totp ? 'The 6-digit code from your authenticator app, or one of your recovery codes.' : 'One of the recovery codes you saved when you added your passkey.'}>
							<!-- svelte-ignore a11y_autofocus -->
							<Input id="code" class="h-10 font-mono tracking-widest" autocomplete="one-time-code" required autofocus={!second.passkey} maxlength={20} bind:value={code} />
						</Field>
					{/if}
					{#if error && !(ssoRequired && !showPassword && !second)}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
					<Button variant={second?.passkey ? 'secondary' : 'primary'} type="submit" class="h-10 w-full" loading={busy && !second?.passkey}>{second ? 'Verify' : 'Sign in'}</Button>
					{#if second}
						<button type="button" class="text-muted hover:text-fg w-full text-center text-sm" onclick={back}>Use a different account</button>
					{/if}
				</form>
			{/if}
			<p class="text-muted mt-10 text-center text-xs lg:hidden"><SourceLink href={company.branding?.source_url} /></p>
		</div>
	</main>
</div>
