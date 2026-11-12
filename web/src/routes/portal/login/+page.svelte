<script lang="ts">
	import { goto, replaceState } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { KeyRound, MailCheck } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { portal, PortalError, safeNext } from '#lib/portal/api.js';
	import { clearMe, loadMe } from '#lib/portal/me.svelte.js';
	import type { PortalInfo } from '#lib/portal/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';

	type Mode = 'link' | 'sent' | 'password' | 'code' | 'verifying';

	let info = $state<PortalInfo | null>(null);
	let mode = $state<Mode>('link');
	// Where the two-factor code goes: the sign-in link or the password sign-in.
	let codeFor = $state<'link' | 'password'>('password');
	let email = $state('');
	let password = $state('');
	let code = $state('');
	let token = $state('');
	let error = $state('');
	let busy = $state(false);

	const company = $derived(info?.company_name || '');

	onMount(() => {
		fetch('/api/portal/info', { credentials: 'same-origin' })
			.then((r) => (r.ok ? r.json() : null))
			.then((d) => (info = d))
			.catch(() => {});
		const t = page.url.searchParams.get('token');
		if (t) {
			token = t;
			// Take the token out of the address bar (and history) straight away.
			const u = new URL(page.url.href);
			u.searchParams.delete('token');
			replaceState(u, {});
			verify();
		}
	});

	async function done() {
		clearMe();
		await loadMe(true);
		await goto(safeNext(page.url.searchParams.get('next')), { replace: true });
	}

	function needCode(e: unknown, target: 'link' | 'password'): boolean {
		if (!(e instanceof PortalError && e.data?.mfa_required)) return false;
		error = mode === 'code' ? 'That code didn’t work. Check your authenticator app and try again.' : '';
		codeFor = target;
		mode = 'code';
		code = '';
		return true;
	}

	async function verify() {
		const retry = mode === 'code';
		if (!retry) mode = 'verifying';
		busy = true;
		error = '';
		try {
			await portal.post('/auth/verify', { token, code: retry ? code.trim() : undefined });
			await done();
		} catch (e) {
			if (!needCode(e, 'link')) {
				mode = 'link';
				error = e instanceof Error ? e.message : 'This sign-in link didn’t work.';
				error = error.charAt(0).toUpperCase() + error.slice(1);
			}
		} finally {
			busy = false;
		}
	}

	async function sendLink(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			await portal.post('/auth/link', { email: email.trim() });
			mode = 'sent';
		} catch (e) {
			const m = e instanceof Error ? e.message : String(e);
			error = m.charAt(0).toUpperCase() + m.slice(1);
		} finally {
			busy = false;
		}
	}

	async function signIn(e?: SubmitEvent) {
		e?.preventDefault();
		busy = true;
		const retry = mode === 'code';
		error = '';
		try {
			await portal.post('/auth/login', { email: email.trim(), password, code: retry ? code.trim() : undefined });
			await done();
		} catch (e) {
			if (!needCode(e, 'password')) {
				mode = 'password';
				error = e instanceof PortalError && e.status === 429 ? e.message : 'Wrong email or password.';
			}
		} finally {
			busy = false;
		}
	}

	function submitCode(e: SubmitEvent) {
		e.preventDefault();
		if (codeFor === 'link') verify();
		else signIn();
	}

	function show(m: Mode) {
		mode = m;
		error = '';
		code = '';
	}

	const heading = $derived(
		{
			link: 'Sign in',
			sent: 'Check your email',
			password: 'Sign in with a password',
			code: 'Two-factor verification',
			verifying: 'Signing you in'
		}[mode]
	);
</script>

<div class="bg-surface flex min-h-dvh flex-col items-center justify-center px-4 py-10">
	<main class="w-full max-w-md">
		<div class="mb-6 flex items-center gap-2.5">
			<img src={favicon} alt="" class="size-8" />
			<span class="text-[0.9375rem] font-semibold tracking-tight">{company ? `${company} support` : 'Support portal'}</span>
		</div>
		<div class="card p-6 sm:p-8">
			<h1 class="text-2xl font-semibold tracking-tight">{heading}</h1>

			{#if mode === 'verifying'}
				<p class="text-muted mt-4 flex items-center gap-2 text-sm" role="status"><Spinner />Checking your sign-in link…</p>
			{:else if mode === 'sent'}
				<div class="mt-4 space-y-4" role="status">
					<div class="bg-accent-soft text-accent flex size-11 items-center justify-center rounded-lg"><MailCheck class="size-5" aria-hidden="true" /></div>
					<p class="text-sm">
						If <strong class="font-medium break-all">{email.trim()}</strong> has access to the portal, we've sent it a sign-in link. Open the email on this device and select the link.
					</p>
					<p class="text-muted text-sm">It can take a minute to arrive. Check your junk folder if you don't see it.</p>
					<Button variant="ghost" class="-ml-3" onclick={() => show('link')}>Use a different email</Button>
				</div>
			{:else if mode === 'code'}
				<p class="text-muted mt-1.5 text-sm">Enter the 6-digit code from your authenticator app.</p>
				<form class="mt-6 space-y-5" onsubmit={submitCode}>
					<Field label="Two-factor code" id="code">
						<!-- svelte-ignore a11y_autofocus -->
						<Input
							id="code"
							class="h-10 font-mono tracking-widest"
							inputmode="numeric"
							autocomplete="one-time-code"
							pattern="[0-9 ]*"
							required
							autofocus
							maxlength={8}
							bind:value={code}
						/>
					</Field>
					{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
					<Button variant="primary" type="submit" class="h-10 w-full" loading={busy}>Verify</Button>
					<button type="button" class="text-muted hover:text-fg w-full text-center text-sm" onclick={() => show(codeFor === 'link' ? 'link' : 'password')}>Cancel</button>
				</form>
			{:else if mode === 'password'}
				<p class="text-muted mt-1.5 text-sm">Use the password you set on your account page.</p>
				<form class="mt-6 space-y-5" onsubmit={signIn}>
					<Field label="Email" id="pw-email"><Input id="pw-email" type="email" autocomplete="username" required bind:value={email} class="h-10" /></Field>
					<Field label="Password" id="pw"><Input id="pw" type="password" autocomplete="current-password" required bind:value={password} class="h-10" /></Field>
					{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
					<Button variant="primary" type="submit" class="h-10 w-full" loading={busy}>Sign in</Button>
				</form>
				<div class="border-border mt-6 border-t pt-4">
					<Button variant="ghost" class="-ml-3" icon={MailCheck} onclick={() => show('link')}>Email me a sign-in link instead</Button>
				</div>
			{:else}
				<p class="text-muted mt-1.5 text-sm">{info?.welcome || 'Enter your email and we’ll send you a link to sign in. No password needed.'}</p>
				<form class="mt-6 space-y-5" onsubmit={sendLink}>
					<Field label="Email" id="email"><Input id="email" type="email" autocomplete="email" required bind:value={email} class="h-10" /></Field>
					{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
					<Button variant="primary" type="submit" class="h-10 w-full" loading={busy}>Send me a sign-in link</Button>
				</form>
				<div class="border-border mt-6 border-t pt-4">
					<Button variant="ghost" class="-ml-3" icon={KeyRound} onclick={() => show('password')}>Sign in with a password</Button>
				</div>
			{/if}
		</div>
	</main>
</div>
