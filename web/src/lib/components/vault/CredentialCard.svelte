<script lang="ts">
	import { onDestroy } from 'svelte';
	import { Check, Copy, ExternalLink, Eye, EyeOff, KeyRound, RefreshCw, StickyNote, Timer } from '@lucide/svelte';
	import { cx } from '#lib/format.js';
	import { webUrl } from '#lib/docs/markdown.js';
	import type { TotpCode, VaultItem } from '#lib/docs/types.js';
	import { REVEAL_MS, reveal, secretError, totpCode } from '#lib/docs/vault.js';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';

	/**
	 * A credential: name, username, password (masked; reveal and copy), TOTP (a code on
	 * request, with a countdown) and URL. Used by the `credential` block, the popover of a
	 * credential link and the Passwords tab.
	 *
	 * Secrets live only in this component's state: a revealed password hides itself after 30
	 * seconds, codes aren't refreshed on their own (each one is an audit entry), and both are
	 * dropped when the card goes away.
	 */
	let { item, label = '', flat = false }: { item: VaultItem; /** The slot's label from the page, shown above the name when it differs. */ label?: string; /** No border of its own (inside a drawer or popover). */ flat?: boolean } = $props();

	let now = $state(Date.now());
	let tick: ReturnType<typeof setInterval> | undefined;
	function ticking(on: boolean) {
		if (on && !tick) tick = setInterval(() => (now = Date.now()), 1000);
		if (!on && tick) {
			clearInterval(tick);
			tick = undefined;
		}
	}

	// --- password -------------------------------------------------------------------------------
	let password = $state<{ value: string; until: number } | null>(null);
	let pwBusy = $state(false);
	let pwError = $state('');
	let copied = $state<'password' | 'code' | null>(null);
	async function showPassword() {
		pwBusy = true;
		pwError = '';
		try {
			password = { value: await reveal(item.id, 'password'), until: Date.now() + REVEAL_MS };
			now = Date.now();
		} catch (e) {
			pwError = secretError(e);
		} finally {
			pwBusy = false;
		}
	}
	async function copyPassword() {
		pwError = '';
		try {
			const v = password?.value ?? (await reveal(item.id, 'password'));
			await navigator.clipboard.writeText(v);
			flash('password');
		} catch (e) {
			pwError = e instanceof DOMException ? 'The browser blocked the clipboard. Reveal the password and copy it by hand.' : secretError(e);
		}
	}
	function flash(what: 'password' | 'code') {
		copied = what;
		setTimeout(() => copied === what && (copied = null), 1500);
	}
	const pwLeft = $derived(password ? Math.max(0, Math.ceil((password.until - now) / 1000)) : 0);
	$effect(() => {
		if (password && pwLeft === 0) password = null;
	});

	// --- TOTP -----------------------------------------------------------------------------------
	let code = $state<(TotpCode & { until: number }) | null>(null);
	let codeBusy = $state(false);
	let codeError = $state('');
	async function showCode() {
		codeBusy = true;
		codeError = '';
		try {
			const c = await totpCode(item.id);
			code = { ...c, until: Date.now() + c.remaining * 1000 };
			now = Date.now();
		} catch (e) {
			codeError = secretError(e);
		} finally {
			codeBusy = false;
		}
	}
	const codeLeft = $derived(code ? Math.max(0, Math.ceil((code.until - now) / 1000)) : 0);
	const grouped = (c: string) => (c.length >= 6 ? `${c.slice(0, Math.ceil(c.length / 2))} ${c.slice(Math.ceil(c.length / 2))}` : c);

	// --- notes ----------------------------------------------------------------------------------
	let notes = $state<string | null>(null);
	let notesBusy = $state(false);
	let notesError = $state('');
	async function showNotes() {
		notesBusy = true;
		notesError = '';
		try {
			notes = await reveal(item.id, 'notes');
		} catch (e) {
			notesError = secretError(e);
		} finally {
			notesBusy = false;
		}
	}

	$effect(() => ticking(!!password || (!!code && codeLeft > 0)));
	// A different credential in the same place: forget what was revealed for the old one.
	$effect(() => {
		void item.id;
		return () => {
			password = null;
			code = null;
			notes = null;
		};
	});
	onDestroy(() => ticking(false));

	const link = $derived(webUrl(item.url));
	const uid = $props.id();
</script>

<section class={cx('cred', !flat && 'cred-card')} aria-labelledby="{uid}-name">
	<header class="flex items-start gap-3">
		<span class="bg-accent-soft text-accent flex size-8 shrink-0 items-center justify-center rounded-md"><KeyRound class="size-4" aria-hidden="true" /></span>
		<div class="min-w-0 flex-1">
			{#if label && label.toLowerCase() !== item.name.toLowerCase()}<p class="text-muted text-xs">{label}</p>{/if}
			<h4 id="{uid}-name" class="font-sans text-sm font-semibold tracking-normal break-words">{item.name}</h4>
			{#if item.url}
				{#if link}
					<a class="link text-xs break-all" href={link} target="_blank" rel="noopener noreferrer">{item.url}<ExternalLink class="ml-0.5 inline size-3 align-[-1px]" aria-hidden="true" /><span class="sr-only"> (opens in a new tab)</span></a>
				{:else}
					<p class="text-muted font-mono text-xs break-all">{item.url}</p>
				{/if}
			{/if}
		</div>
	</header>

	<dl class="cred-rows">
		<div class="cred-row">
			<dt>Username</dt>
			<dd>
				{#if item.username}
					<span class="cred-value font-mono">{item.username}</span>
					<CopyButton text={item.username} label="Copy username" />
				{:else}
					<span class="text-subtle">None</span>
				{/if}
			</dd>
		</div>
		<div class="cred-row">
			<dt>Password</dt>
			<dd>
				{#if !item.has_password}
					<span class="text-subtle">None</span>
				{:else}
					<span class="cred-value font-mono" aria-live="polite">
						{#if password}{password.value}{:else}<span aria-hidden="true">••••••••••••</span><span class="sr-only">Hidden</span>{/if}
					</span>
					{#if password}
						<span class="text-muted tabular shrink-0 text-xs" title="Hides itself after 30 seconds">{pwLeft} s</span>
						<IconButton icon={EyeOff} size="sm" label="Hide password" onclick={() => (password = null)} />
					{:else}
						<IconButton icon={Eye} size="sm" label="Reveal password" onclick={showPassword} disabled={pwBusy} />
					{/if}
					<IconButton icon={copied === 'password' ? Check : Copy} size="sm" label={copied === 'password' ? 'Copied' : 'Copy password'} onclick={copyPassword} />
				{/if}
			</dd>
		</div>
		{#if pwError}<p class="cred-error" role="alert">{pwError}</p>{/if}
		{#if item.has_totp}
			<div class="cred-row">
				<dt>One-time code</dt>
				<dd>
					{#if code}
						<span class={cx('cred-value font-mono text-base font-semibold tracking-wider tabular', codeLeft === 0 && 'text-subtle line-through')} aria-live="polite">{grouped(code.code)}</span>
						{#if codeLeft > 0}
							<span class="text-muted flex shrink-0 items-center gap-1 text-xs tabular" title="Seconds until this code expires"><Timer class="size-3.5" aria-hidden="true" />{codeLeft} s</span>
							<IconButton icon={copied === 'code' ? Check : Copy} size="sm" label={copied === 'code' ? 'Copied' : 'Copy code'} onclick={() => navigator.clipboard.writeText(code!.code).then(() => flash('code'), () => {})} />
						{:else}
							<span class="text-muted shrink-0 text-xs">Expired</span>
							<Button size="xs" icon={RefreshCw} loading={codeBusy} onclick={showCode}>New code</Button>
						{/if}
					{:else}
						<Button size="xs" icon={Timer} loading={codeBusy} onclick={showCode}>Show code</Button>
					{/if}
				</dd>
			</div>
			{#if codeError}<p class="cred-error" role="alert">{codeError}</p>{/if}
		{/if}
		{#if item.has_notes}
			<div class="cred-row cred-row-notes">
				<dt>Notes</dt>
				<dd>
					{#if notes !== null}
						<div class="w-full">
							<pre class="bg-sunken border-border max-h-60 overflow-auto rounded-md border px-2.5 py-2 font-sans text-xs leading-relaxed whitespace-pre-wrap">{notes}</pre>
							<button type="button" class="link mt-1 text-xs" onclick={() => (notes = null)}>Hide notes</button>
						</div>
					{:else}
						<Button size="xs" icon={StickyNote} loading={notesBusy} onclick={showNotes}>Show notes</Button>
					{/if}
				</dd>
			</div>
			{#if notesError}<p class="cred-error" role="alert">{notesError}</p>{/if}
		{/if}
	</dl>
</section>

<style>
	.cred-card {
		border: 1px solid var(--border);
		border-radius: 10px;
		background: var(--raised);
		padding: 0.875rem 1rem;
	}
	.cred-rows {
		margin-top: 0.75rem;
		display: grid;
		grid-template-columns: minmax(5.5rem, max-content) minmax(0, 1fr);
		column-gap: 1rem;
		font-size: 0.8125rem;
	}
	.cred-row {
		display: contents;
	}
	.cred-row > dt,
	.cred-row > dd {
		border-top: 1px solid var(--border);
		padding: 0.3rem 0;
		min-height: 2.25rem;
		display: flex;
		align-items: center;
	}
	.cred-row > dt {
		color: var(--muted);
	}
	.cred-row > dd {
		gap: 0.25rem;
		min-width: 0;
	}
	.cred-row-notes > dt,
	.cred-row-notes > dd {
		align-items: flex-start;
		padding-top: 0.5rem;
	}
	.cred-value {
		min-width: 0;
		flex: 1;
		overflow-wrap: anywhere;
	}
	.cred-error {
		grid-column: 1 / -1;
		color: var(--danger);
		font-size: 0.75rem;
		padding-bottom: 0.35rem;
	}
</style>
