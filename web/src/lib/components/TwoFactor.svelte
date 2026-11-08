<script lang="ts">
	import { api } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	interface Status { enabled: boolean; required: boolean; recovery_codes_left: number }
	interface Setup { secret: string; uri: string; qr_svg: string }

	let { onchange }: { onchange?: () => void } = $props();

	let status = $state<Status | null>(null);
	// idle → password (to start setup) → scan → codes (shown once)
	let step = $state<'idle' | 'password' | 'scan' | 'codes' | 'disable' | 'regen'>('idle');
	let setup = $state<Setup | null>(null);
	let codes = $state<string[]>([]);
	let password = $state('');
	let code = $state('');
	let error = $state('');
	let notice = $state('');
	let busy = $state(false);
	let copied = $state(false);

	const load = () => api.get<Status>('/auth/totp').then((s) => (status = s));
	$effect(() => {
		load();
	});

	async function refreshUser() {
		session.user = await api.get<User>('/auth/me');
		await load();
		onchange?.();
	}

	function go(s: typeof step) {
		step = s;
		password = '';
		code = '';
		error = '';
		notice = '';
	}

	async function run(fn: () => Promise<void>) {
		busy = true;
		error = '';
		try {
			await fn();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}

	const start = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			setup = await api.post<Setup>('/auth/totp/setup', { password });
			go('scan');
		});
	};

	const confirm = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			const r = await api.post<{ recovery_codes: string[]; sessions_revoked: number }>('/auth/totp/enable', { code });
			codes = r.recovery_codes;
			setup = null;
			go('codes');
			if (r.sessions_revoked) notice = `Signed out ${r.sessions_revoked} other session${r.sessions_revoked === 1 ? '' : 's'}.`;
			// Don't refresh session.user yet: lifting the setup requirement mid-flow would
			// navigate away before the recovery codes are saved. Done does it.
		});
	};

	const turnOff = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			await api.post('/auth/totp/disable', { password, code });
			go('idle');
			await refreshUser();
		});
	};

	const regen = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			codes = (await api.post<{ recovery_codes: string[] }>('/auth/totp/recovery-codes', { code })).recovery_codes;
			go('codes');
		});
	};

	async function done() {
		codes = [];
		go('idle');
		await refreshUser();
	}

	async function copy() {
		try {
			await navigator.clipboard.writeText(codes.join('\n'));
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			/* clipboard blocked: the codes are on screen to copy by hand */
		}
	}
</script>

{#if !status}
	<Skeleton lines={2} />
{:else}
	{#if session.user?.mfa_setup_required && step !== 'codes'}
		<p class="border-warning/40 bg-warning-soft text-warning mb-4 rounded-md border px-3 py-2 text-sm" role="status">
			Your account needs two-factor authentication. Set it up to continue using the dashboard.
		</p>
	{/if}

	{#if step === 'codes'}
		<p class="mb-3 text-sm">Save these recovery codes somewhere safe. Each one signs you in once if you lose your phone. They won't be shown again.</p>
		<div class="code-block mb-3 grid grid-cols-2 gap-1 text-sm">
			{#each codes as c (c)}<span>{c}</span>{/each}
		</div>
		{#if notice}<p class="text-muted mb-3 text-xs">{notice}</p>{/if}
		<div class="flex justify-end gap-2">
			<Button onclick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
			<Button variant="primary" onclick={done}>I've saved them</Button>
		</div>
	{:else if step === 'password'}
		<form class="space-y-3" onsubmit={start}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<Field label="Confirm your password" id="tp" {error}><Input id="tp" type="password" autocomplete="current-password" required bind:value={password} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>Continue</Button></div>
		</form>
	{:else if step === 'scan' && setup}
		<form class="space-y-4" onsubmit={confirm}>
			<p class="text-sm">Scan this with an authenticator app (1Password, Bitwarden, Google Authenticator, Authy…), then enter the code it shows.</p>
			<div class="flex flex-wrap items-start gap-4">
				<!-- Server-rendered SVG from our own API. -->
				<div class="border-border size-44 shrink-0 overflow-hidden rounded-md border bg-white p-1 [&>svg]:size-full">{@html setup.qr_svg}</div>
				<div class="text-muted min-w-0 flex-1 space-y-1 text-xs">
					<div>Can't scan? Enter this key:</div>
					<code class="code-block block text-sm break-all select-all">{setup.secret.match(/.{1,4}/g)?.join(' ')}</code>
				</div>
			</div>
			<Field label="6-digit code" id="tc" {error}>
				<Input id="tc" class="max-w-40 font-mono tracking-widest" inputmode="numeric" autocomplete="one-time-code" maxlength={6} required bind:value={code} invalid={!!error} />
			</Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>Turn on</Button></div>
		</form>
	{:else if step === 'disable'}
		<form class="space-y-3" onsubmit={turnOff}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			{#if status.required}<p class="text-warning text-sm">Two-factor is required for your account, so you'll have to set it up again straight away (e.g. on a new phone).</p>{/if}
			<Field label="Password" id="dp"><Input id="dp" type="password" autocomplete="current-password" required bind:value={password} /></Field>
			<Field label="Code from your app, or a recovery code" id="dc" {error}><Input id="dc" class="font-mono" autocomplete="one-time-code" required bind:value={code} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="danger" type="submit" loading={busy}>Turn off</Button></div>
		</form>
	{:else if step === 'regen'}
		<form class="space-y-3" onsubmit={regen}>
			<p class="text-muted text-sm">Your current recovery codes stop working.</p>
			<Field label="Code from your app" id="rc" {error}><Input id="rc" class="max-w-40 font-mono tracking-widest" autocomplete="one-time-code" required bind:value={code} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>New codes</Button></div>
		</form>
	{:else if status.enabled}
		<p class="mb-3 flex items-center gap-2 text-sm">
			<Badge tone="success">On</Badge>
			<span class="text-muted">{status.recovery_codes_left} recovery code{status.recovery_codes_left === 1 ? '' : 's'} left</span>
		</p>
		{#if status.recovery_codes_left <= 3}<p class="text-warning mb-3 text-xs">Running low on recovery codes: generate new ones.</p>{/if}
		<div class="flex flex-wrap justify-end gap-2">
			<Button onclick={() => go('regen')}>New recovery codes</Button>
			<Button variant="danger-ghost" onclick={() => go('disable')}>Turn off</Button>
		</div>
	{:else}
		<p class="text-muted mb-3 text-sm">{status.required ? 'Required for your account.' : 'Off.'} Sign-in will ask for a code from your phone as well as your password.</p>
		<div class="flex justify-end"><Button variant="primary" onclick={() => go('password')}>Set up</Button></div>
	{/if}
{/if}
