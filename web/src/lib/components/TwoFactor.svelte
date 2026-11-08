<script lang="ts">
	import { api } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';

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

{#if status}
	{#if session.user?.mfa_setup_required && step !== 'codes'}
		<p class="mb-3 rounded-md border border-amber-800 bg-amber-950/40 px-3 py-2 text-sm text-amber-200">
			Your account needs two-factor authentication. Set it up to continue using the dashboard.
		</p>
	{/if}

	{#if step === 'codes'}
		<p class="mb-2 text-sm text-slate-300">Save these recovery codes somewhere safe. Each one signs you in once if you lose your phone. They won't be shown again.</p>
		<div class="mb-3 grid grid-cols-2 gap-1 rounded-md bg-slate-950 p-3 font-mono text-sm">
			{#each codes as c (c)}<span>{c}</span>{/each}
		</div>
		{#if notice}<p class="mb-2 text-xs text-slate-400">{notice}</p>{/if}
		<div class="flex justify-end gap-2">
			<button class="btn-ghost" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
			<button class="btn-primary" onclick={done}>I've saved them</button>
		</div>
	{:else if step === 'password'}
		<form class="space-y-3" onsubmit={start}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<div><label class="label" for="tp">Confirm your password</label><input id="tp" class="input" type="password" autocomplete="current-password" required bind:value={password} /></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button type="button" class="btn-ghost" onclick={() => go('idle')}>Cancel</button><button class="btn-primary" disabled={busy}>Continue</button></div>
		</form>
	{:else if step === 'scan' && setup}
		<form class="space-y-3" onsubmit={confirm}>
			<p class="text-sm text-slate-300">Scan this with an authenticator app (1Password, Bitwarden, Google Authenticator, Authy…), then enter the code it shows.</p>
			<div class="flex flex-wrap items-start gap-4">
				<!-- Server-rendered SVG from our own API. -->
				<div class="size-44 shrink-0 overflow-hidden rounded-md bg-white p-1 [&>svg]:size-full">{@html setup.qr_svg}</div>
				<div class="min-w-0 flex-1 space-y-1 text-xs text-slate-400">
					<div>Can't scan? Enter this key:</div>
					<code class="block rounded bg-slate-950 p-2 font-mono text-sm break-all text-slate-200 select-all">{setup.secret.match(/.{1,4}/g)?.join(' ')}</code>
				</div>
			</div>
			<div><label class="label" for="tc">6-digit code</label><input id="tc" class="input max-w-40 font-mono tracking-widest" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required bind:value={code} /></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button type="button" class="btn-ghost" onclick={() => go('idle')}>Cancel</button><button class="btn-primary" disabled={busy}>Turn on</button></div>
		</form>
	{:else if step === 'disable'}
		<form class="space-y-3" onsubmit={turnOff}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			{#if status.required}<p class="text-sm text-amber-300">Two-factor is required for your account, so you'll have to set it up again straight away (e.g. on a new phone).</p>{/if}
			<div><label class="label" for="dp">Password</label><input id="dp" class="input" type="password" autocomplete="current-password" required bind:value={password} /></div>
			<div><label class="label" for="dc">Code from your app, or a recovery code</label><input id="dc" class="input font-mono" autocomplete="one-time-code" required bind:value={code} /></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button type="button" class="btn-ghost" onclick={() => go('idle')}>Cancel</button><button class="btn-danger" disabled={busy}>Turn off</button></div>
		</form>
	{:else if step === 'regen'}
		<form class="space-y-3" onsubmit={regen}>
			<p class="text-sm text-slate-400">Your current recovery codes stop working.</p>
			<div><label class="label" for="rc">Code from your app</label><input id="rc" class="input max-w-40 font-mono tracking-widest" autocomplete="one-time-code" required bind:value={code} /></div>
			{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
			<div class="flex justify-end gap-2"><button type="button" class="btn-ghost" onclick={() => go('idle')}>Cancel</button><button class="btn-primary" disabled={busy}>New codes</button></div>
		</form>
	{:else if status.enabled}
		<p class="mb-3 text-sm"><span class="text-emerald-400">On.</span> <span class="text-slate-400">{status.recovery_codes_left} recovery code{status.recovery_codes_left === 1 ? '' : 's'} left.</span></p>
		{#if status.recovery_codes_left <= 3}<p class="mb-3 text-xs text-amber-300">Running low on recovery codes: generate new ones.</p>{/if}
		<div class="flex justify-end gap-2">
			<button class="btn-ghost" onclick={() => go('regen')}>New recovery codes</button>
			<button class="btn-danger" onclick={() => go('disable')}>Turn off</button>
		</div>
	{:else}
		<p class="mb-3 text-sm text-slate-400">{status.required ? 'Required for your account.' : 'Off.'} Sign-in will ask for a code from your phone as well as your password.</p>
		<div class="flex justify-end"><button class="btn-primary" onclick={() => go('password')}>Set up</button></div>
	{/if}
{/if}
