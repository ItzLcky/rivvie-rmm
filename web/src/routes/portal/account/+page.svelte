<script lang="ts">
	import { ShieldCheck, ShieldOff } from '@lucide/svelte';
	import { portal } from '#lib/portal/api.js';
	import { loadMe, me } from '#lib/portal/me.svelte.js';
	import type { TotpSetup } from '#lib/portal/types.js';
	import { toast } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';

	const m = $derived(me.data!);

	const cap = (e: unknown) => {
		const s = e instanceof Error ? e.message : String(e);
		return s.charAt(0).toUpperCase() + s.slice(1);
	};

	// Password
	let current = $state('');
	let password = $state('');
	let confirm = $state('');
	let pwBusy = $state(false);
	let pwError = $state('');

	async function savePassword(e: SubmitEvent) {
		e.preventDefault();
		pwError = '';
		if (password.length < 12) {
			pwError = 'Use at least 12 characters.';
			return;
		}
		if (password !== confirm) {
			pwError = 'The two passwords don’t match.';
			return;
		}
		pwBusy = true;
		try {
			await portal.post('/account/password', { current_password: m.has_password ? current : undefined, password });
			toast.success(m.has_password ? 'Password changed. Other sessions were signed out.' : 'Password set. You can now sign in with it.');
			current = password = confirm = '';
			await loadMe(true);
		} catch (e) {
			pwError = cap(e);
		} finally {
			pwBusy = false;
		}
	}

	// Two-factor
	let setup = $state<TotpSetup | null>(null);
	let code = $state('');
	let tfBusy = $state(false);
	let tfError = $state('');

	async function startSetup() {
		tfBusy = true;
		tfError = '';
		try {
			setup = await portal.post<TotpSetup>('/account/totp/setup');
			code = '';
		} catch (e) {
			toast.error(cap(e));
		} finally {
			tfBusy = false;
		}
	}

	async function enable(e: SubmitEvent) {
		e.preventDefault();
		tfBusy = true;
		tfError = '';
		try {
			await portal.post('/account/totp/enable', { code: code.trim() });
			toast.success('Two-factor authentication is on');
			setup = null;
			code = '';
			await loadMe(true);
		} catch (e) {
			tfError = cap(e);
		} finally {
			tfBusy = false;
		}
	}

	async function disable(e: SubmitEvent) {
		e.preventDefault();
		tfBusy = true;
		tfError = '';
		try {
			await portal.post('/account/totp/disable', { code: code.trim() });
			toast.success('Two-factor authentication is off');
			code = '';
			await loadMe(true);
		} catch (e) {
			tfError = cap(e);
		} finally {
			tfBusy = false;
		}
	}
</script>

<div class="mx-auto max-w-2xl space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">Account</h1>
		<p class="text-muted mt-1 text-sm">How you sign in to the support portal.</p>
	</div>

	<section class="card" aria-labelledby="profile-h">
		<div class="panel-head"><h2 id="profile-h" class="panel-title">Your details</h2></div>
		<dl class="dl p-4">
			<dt>Name</dt>
			<dd>{m.contact.name || '–'}</dd>
			<dt>Email</dt>
			<dd class="break-all">{m.contact.email}</dd>
			<dt>Organisation</dt>
			<dd>{m.contact.client_name}{#if m.contact.is_primary} <Badge tone="accent">Primary contact</Badge>{/if}</dd>
		</dl>
		<p class="text-muted border-border border-t px-4 py-3 text-xs">To change these details, ask the support team.</p>
	</section>

	<section class="card" aria-labelledby="pw-h">
		<div class="panel-head"><h2 id="pw-h" class="panel-title">Password</h2></div>
		<form class="space-y-4 p-4" onsubmit={savePassword}>
			<p class="text-muted text-sm">
				{#if m.has_password}You can sign in with your email and this password, or with an emailed link.{:else}You sign in with emailed links. Set a password if you'd rather type one in.{/if}
			</p>
			<!-- Lets password managers pair the new password with the account. -->
			<input type="email" class="sr-only" autocomplete="username" value={m.contact.email} tabindex="-1" aria-hidden="true" readonly />
			{#if m.has_password}
				<Field label="Current password" id="cur-pw">
					<Input id="cur-pw" type="password" autocomplete="current-password" required bind:value={current} />
				</Field>
			{/if}
			<Field label={m.has_password ? 'New password' : 'Password'} id="new-pw" hint="At least 12 characters.">
				<Input id="new-pw" type="password" autocomplete="new-password" required minlength={12} bind:value={password} />
			</Field>
			<Field label="Confirm password" id="confirm-pw">
				<Input id="confirm-pw" type="password" autocomplete="new-password" required bind:value={confirm} />
			</Field>
			{#if pwError}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{pwError}</p>{/if}
			<div class="flex justify-end">
				<Button variant="primary" type="submit" loading={pwBusy}>{m.has_password ? 'Change password' : 'Set password'}</Button>
			</div>
		</form>
	</section>

	<section class="card" aria-labelledby="tf-h">
		<div class="panel-head">
			<h2 id="tf-h" class="panel-title">Two-factor authentication</h2>
			{#if m.totp_enabled}<Badge tone="success" icon={ShieldCheck}>On</Badge>{:else}<Badge>Off</Badge>{/if}
		</div>
		<div class="space-y-4 p-4">
			{#if m.totp_enabled}
				<p class="text-sm">Signing in asks for a code from your authenticator app as well as your link or password.</p>
				<form class="space-y-4" onsubmit={disable}>
					<Field label="Code from your app" id="off-code" hint="Enter a current code to turn two-factor authentication off.">
						<Input id="off-code" class="font-mono tracking-widest sm:max-w-48" inputmode="numeric" autocomplete="one-time-code" required maxlength={8} bind:value={code} />
					</Field>
					{#if tfError}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{tfError}</p>{/if}
					<div class="flex justify-end"><Button variant="danger" type="submit" icon={ShieldOff} loading={tfBusy}>Turn off</Button></div>
				</form>
			{:else if setup}
				<ol class="list-decimal space-y-4 pl-5 text-sm">
					<li>
						Scan this QR code with an authenticator app (such as Microsoft Authenticator or Google Authenticator).
						<div class="mt-3 w-44 rounded-md border border-[#d0d5dd] bg-white p-2 [&_svg]:h-auto [&_svg]:w-full" role="img" aria-label="QR code for your authenticator app">
							<!-- The server renders this SVG; nothing user-supplied goes into it. -->
							{@html setup.qr_svg}
						</div>
						<details class="mt-3">
							<summary class="text-accent cursor-pointer">Can't scan it? Enter the key instead</summary>
							<p class="mt-2"><code class="bg-sunken border-border rounded border px-1.5 py-0.5 font-mono text-xs break-all">{setup.secret}</code></p>
						</details>
					</li>
					<li>
						<form class="space-y-4" onsubmit={enable}>
							<Field label="Enter the 6-digit code the app shows" id="on-code">
								<!-- svelte-ignore a11y_autofocus -->
								<Input id="on-code" class="font-mono tracking-widest sm:max-w-48" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength={8} bind:value={code} />
							</Field>
							{#if tfError}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{tfError}</p>{/if}
							<div class="flex flex-wrap justify-end gap-2">
								<Button variant="ghost" onclick={() => ((setup = null), (tfError = ''))}>Cancel</Button>
								<Button variant="primary" type="submit" loading={tfBusy}>Turn on</Button>
							</div>
						</form>
					</li>
				</ol>
			{:else}
				<p class="text-sm">Add a second step to signing in: a code from an app on your phone. It keeps your account safe even if someone gets into your email.</p>
				<div class="flex justify-end"><Button variant="primary" icon={ShieldCheck} loading={tfBusy} onclick={startSetup}>Set up two-factor authentication</Button></div>
			{/if}
		</div>
	</section>
</div>
