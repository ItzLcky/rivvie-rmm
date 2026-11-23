<script lang="ts">
	import { KeyRound, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago } from '#lib/format.js';
	import { session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import { cancelled, createPasskey, passkeysSupported } from '#lib/webauthn.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	interface Passkey { id: string; name: string; created_at: string; last_used_at: string | null }
	interface Listing { available: boolean; passkeys: Passkey[]; recovery_codes_left: number; sso_only: boolean }

	let { onchange }: { onchange?: () => void } = $props();

	let data = $state<Listing | null>(null);
	// idle → add (password, name) → codes (shown once, when this was the first second factor)
	let step = $state<'idle' | 'add' | 'codes' | 'remove' | 'rename' | 'regen'>('idle');
	let target = $state<Passkey | null>(null);
	let password = $state('');
	let name = $state('');
	let codes = $state<string[]>([]);
	let error = $state('');
	let notice = $state('');
	let busy = $state(false);
	let copied = $state(false);
	const supported = passkeysSupported();

	const load = () => api.get<Listing>('/auth/passkeys').then((d) => (data = d));
	$effect(() => {
		load();
	});

	function go(s: typeof step, p: Passkey | null = null) {
		step = s;
		target = p;
		password = '';
		name = p?.name ?? '';
		error = '';
		notice = '';
	}

	async function run(fn: () => Promise<void>) {
		busy = true;
		error = '';
		try {
			await fn();
		} catch (e) {
			// The person closing the browser's prompt isn't an error worth shouting about.
			error = cancelled(e) ? 'The passkey prompt was closed or timed out. Try again.' : (e as Error).message;
		} finally {
			busy = false;
		}
	}

	async function refreshUser() {
		session.user = await api.get<User>('/auth/me');
		await load();
		onchange?.();
	}

	const add = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			const start = await api.post<{ ceremony_id: string; options: Parameters<typeof createPasskey>[0] }>('/auth/passkeys/register/start', { password });
			const credential = await createPasskey(start.options);
			const r = await api.post<{ recovery_codes: string[] | null; sessions_revoked: number }>('/auth/passkeys/register/finish', {
				ceremony_id: start.ceremony_id,
				name: name.trim() || 'Passkey',
				credential
			});
			if (r.recovery_codes) {
				codes = r.recovery_codes;
				go('codes');
				if (r.sessions_revoked) notice = `Signed out ${r.sessions_revoked} other session${r.sessions_revoked === 1 ? '' : 's'}.`;
				// The setup requirement is lifted when "I've saved them" refreshes the user, so the page
				// doesn't navigate away before the codes are saved.
				await load();
			} else {
				go('idle');
				await refreshUser();
			}
		});
	};

	const rename = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			await api.patch(`/auth/passkeys/${target!.id}`, { name });
			go('idle');
			await load();
		});
	};

	const remove = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			await api.post(`/auth/passkeys/${target!.id}/remove`, { password });
			go('idle');
			await refreshUser();
		});
	};

	const regen = (e: SubmitEvent) => {
		e.preventDefault();
		return run(async () => {
			codes = (await api.post<{ recovery_codes: string[] }>('/auth/passkeys/recovery-codes', { password })).recovery_codes;
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
			/* clipboard blocked: the codes are on screen */
		}
	}
</script>

{#if !data}
	<Skeleton lines={2} />
{:else if data.sso_only}
	<p class="text-muted text-sm">This account signs in with single sign-on, so your identity provider handles the second factor.</p>
{:else if !data.available}
	<p class="text-muted text-sm">Passkeys need the console to be reached at a host name. Ask an admin to set <code class="font-mono text-xs">RMM_PUBLIC_URL</code> to one (an IP address won't do).</p>
{:else}
	{#if step === 'codes'}
		<p class="mb-3 text-sm">Save these recovery codes somewhere safe. Each one signs you in once if you lose your passkey. They won't be shown again.</p>
		<div class="code-block mb-3 grid grid-cols-2 gap-1 text-sm">
			{#each codes as c (c)}<span>{c}</span>{/each}
		</div>
		{#if notice}<p class="text-muted mb-3 text-xs">{notice}</p>{/if}
		<div class="flex justify-end gap-2">
			<Button onclick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
			<Button variant="primary" onclick={done}>I've saved them</Button>
		</div>
	{:else if step === 'add'}
		<form class="space-y-3" onsubmit={add}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<Field label="Name" id="pkn" hint="So you can tell your keys apart, e.g. “YubiKey” or “Work laptop”."><Input id="pkn" maxlength={60} placeholder="Passkey" bind:value={name} /></Field>
			<Field label="Confirm your password" id="pkp" {error}><Input id="pkp" type="password" autocomplete="current-password" required bind:value={password} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>Continue</Button></div>
		</form>
	{:else if step === 'rename' && target}
		<form class="space-y-3" onsubmit={rename}>
			<Field label="Name" id="pkr" {error}><Input id="pkr" required maxlength={60} bind:value={name} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>Save</Button></div>
		</form>
	{:else if step === 'remove' && target}
		<form class="space-y-3" onsubmit={remove}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<p class="text-sm">Remove <strong>{target.name}</strong>? It can't be used to sign in any more.</p>
			<Field label="Password" id="pkx" {error}><Input id="pkx" type="password" autocomplete="current-password" required bind:value={password} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="danger" type="submit" loading={busy}>Remove</Button></div>
		</form>
	{:else if step === 'regen'}
		<form class="space-y-3" onsubmit={regen}>
			<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
			<p class="text-muted text-sm">Your current recovery codes stop working.</p>
			<Field label="Password" id="pkg" {error}><Input id="pkg" type="password" autocomplete="current-password" required bind:value={password} invalid={!!error} /></Field>
			<div class="flex justify-end gap-2"><Button onclick={() => go('idle')}>Cancel</Button><Button variant="primary" type="submit" loading={busy}>New codes</Button></div>
		</form>
	{:else}
		{#if data.passkeys.length === 0}
			<p class="text-muted mb-3 text-sm">None yet. A passkey is a security key, or your phone or computer's fingerprint or screen lock, used to sign in after your password.</p>
		{:else}
			<ul class="divide-border border-border mb-3 divide-y rounded-md border" aria-label="Your passkeys">
				{#each data.passkeys as p (p.id)}
					<li class="flex items-center gap-3 px-3 py-2">
						<KeyRound class="text-muted size-4 shrink-0" />
						<div class="min-w-0 flex-1">
							<div class="truncate text-sm font-medium">{p.name}</div>
							<div class="text-muted text-xs">Added {ago(p.created_at)} · {p.last_used_at ? `used ${ago(p.last_used_at)}` : 'never used'}</div>
						</div>
						<IconButton icon={Pencil} label="Rename {p.name}" size="sm" onclick={() => go('rename', p)} />
						<IconButton icon={Trash2} label="Remove {p.name}" size="sm" onclick={() => go('remove', p)} />
					</li>
				{/each}
			</ul>
			<p class="mb-3 flex items-center gap-2 text-sm">
				<Badge tone="success">On</Badge>
				{#if !session.user?.totp_enabled}<span class="text-muted">{data.recovery_codes_left} recovery code{data.recovery_codes_left === 1 ? '' : 's'} left</span>{/if}
			</p>
		{/if}
		{#if !supported}<p class="text-warning mb-3 text-xs">This browser can't create passkeys (they need a secure connection).</p>{/if}
		<div class="flex flex-wrap justify-end gap-2">
			{#if data.passkeys.length > 0 && !session.user?.totp_enabled}<Button onclick={() => go('regen')}>New recovery codes</Button>{/if}
			<Button variant="primary" icon={Plus} disabled={!supported || data.passkeys.length >= 10} onclick={() => go('add')}>Add a passkey</Button>
		</div>
	{/if}
{/if}
