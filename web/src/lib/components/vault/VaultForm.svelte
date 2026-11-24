<script lang="ts">
	import { Eye, EyeOff, Undo2, WandSparkles } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import type { VaultDetail, VaultItem } from '#lib/docs/types.js';
	import { reveal, secretError } from '#lib/docs/vault.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import PasswordGenerator from './PasswordGenerator.svelte';

	/**
	 * The fields of a credential, for a new one or `item`. The caller supplies the dialog and its
	 * buttons (submit with `form={formId}`). Existing secrets aren't loaded: leave a field empty
	 * to keep it, or remove it; notes are revealed only if you choose to edit them.
	 */
	let {
		clientId,
		item = null,
		initialName = '',
		formId,
		busy = $bindable(false),
		onsaved
	}: { clientId: string; item?: VaultItem | null; initialName?: string; formId: string; busy?: boolean; onsaved: (d: VaultDetail) => void } = $props();

	// svelte-ignore state_referenced_locally
	const it = item;
	// svelte-ignore state_referenced_locally
	let f = $state({ name: it?.name ?? initialName, username: it?.username ?? '', url: it?.url ?? '', password: '', totp: '', notes: '' });
	let clear = $state({ password: false, totp: false, notes: false });
	let showPw = $state(false);
	let generating = $state(false);
	let error = $state('');
	/** The notes as revealed for editing; null until then (they're left alone). */
	let notesWas = $state<string | null>(null);
	let notesBusy = $state(false);
	async function editNotes() {
		notesBusy = true;
		try {
			notesWas = await reveal(it!.id, 'notes');
			f.notes = notesWas;
		} catch (e) {
			error = secretError(e);
		} finally {
			notesBusy = false;
		}
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		busy = true;
		try {
			let saved: VaultDetail;
			const base = { name: f.name.trim(), username: f.username.trim(), url: f.url.trim() };
			if (!it) {
				saved = await api.post<VaultDetail>(`/clients/${clientId}/vault`, {
					...base,
					...(f.password ? { password: f.password } : {}),
					...(f.totp.trim() ? { totp: f.totp.trim() } : {}),
					...(f.notes.trim() ? { notes: f.notes } : {})
				});
			} else {
				const body: Record<string, unknown> = { ...base };
				if (clear.password) body.password = null;
				else if (f.password) body.password = f.password;
				if (clear.totp) body.totp = null;
				else if (f.totp.trim()) body.totp = f.totp.trim();
				if (clear.notes) body.notes = null;
				else if (!it.has_notes && f.notes.trim()) body.notes = f.notes;
				else if (notesWas !== null && f.notes !== notesWas) body.notes = f.notes.trim() ? f.notes : null;
				saved = await api.put<VaultDetail>(`/vault/${it.id}`, body);
			}
			f.password = '';
			onsaved(saved);
		} catch (err) {
			error = secretError(err);
		} finally {
			busy = false;
		}
	}
	const uid = $props.id();
</script>

<form id={formId} class="space-y-4" onsubmit={submit} autocomplete="off">
	{#if error}<p class="border-danger/40 bg-danger-soft text-danger rounded-md border px-3 py-2 text-sm" role="alert">{error}</p>{/if}
	<Field label="Name" id="{uid}-name" required>
		<!-- svelte-ignore a11y_autofocus -->
		<Input id="{uid}-name" bind:value={f.name} required maxlength={200} placeholder="Firewall admin" autofocus />
	</Field>
	<div class="grid gap-4 sm:grid-cols-2">
		<Field label="Username" id="{uid}-user">
			<Input id="{uid}-user" bind:value={f.username} maxlength={200} autocomplete="off" spellcheck="false" disabled={!!it?.managed_kind} />
		</Field>
		<Field label="URL or host" id="{uid}-url" hint="Web addresses open as links; host names and rdp:// are shown as text.">
			<Input id="{uid}-url" bind:value={f.url} maxlength={2000} placeholder="https://10.0.0.1:4443" spellcheck="false" />
		</Field>
	</div>

	{#if it?.managed_kind}
		<p class="border-border bg-sunken text-muted rounded-md border px-3 py-2 text-sm">The server keeps this password up to date: it and the username can’t be edited here.</p>
	{:else}
	<Field label="Password" id="{uid}-pw" hint={it?.has_password && !clear.password ? 'Leave empty to keep the current password. A changed password goes into the history.' : undefined}>
		{#if clear.password}
			<div class="border-border-strong bg-sunken flex h-9 items-center justify-between rounded-md border border-dashed px-3 text-sm">
				<span class="text-muted">The password will be removed</span>
				<Button size="xs" variant="ghost" icon={Undo2} onclick={() => (clear.password = false)}>Undo</Button>
			</div>
		{:else}
			<div class="flex gap-2">
				<div class="relative min-w-0 flex-1">
					<Input
						id="{uid}-pw"
						type={showPw ? 'text' : 'password'}
						bind:value={f.password}
						maxlength={1000}
						autocomplete="new-password"
						spellcheck="false"
						class="pr-9 font-mono"
						placeholder={it?.has_password ? 'Unchanged' : ''}
					/>
					<div class="absolute inset-y-0 right-1 flex items-center">
						<IconButton icon={showPw ? EyeOff : Eye} size="sm" label={showPw ? 'Hide password' : 'Show password'} onclick={() => (showPw = !showPw)} />
					</div>
				</div>
				<Button icon={WandSparkles} aria-expanded={generating} onclick={() => (generating = !generating)}>Generate</Button>
			</div>
			{#if it?.has_password}<button type="button" class="link mt-1 text-xs" onclick={() => ((clear.password = true), (f.password = ''))}>Remove the password</button>{/if}
		{/if}
	</Field>
	{/if}
	{#if generating && !clear.password}
		<PasswordGenerator
			onclose={() => (generating = false)}
			onuse={(p) => {
				f.password = p;
				showPw = true;
				generating = false;
			}}
		/>
	{/if}

	<Field
		label="TOTP secret"
		id="{uid}-totp"
		hint={it?.has_totp && !clear.totp ? 'A secret is set. Paste a new one to replace it, or leave empty to keep it.' : 'The base32 secret or the otpauth:// link from the QR code. Codes are worked out on the server; the secret never comes back to the browser.'}
	>
		{#if clear.totp}
			<div class="border-border-strong bg-sunken flex h-9 items-center justify-between rounded-md border border-dashed px-3 text-sm">
				<span class="text-muted">The TOTP secret will be removed</span>
				<Button size="xs" variant="ghost" icon={Undo2} onclick={() => (clear.totp = false)}>Undo</Button>
			</div>
		{:else}
			<Input id="{uid}-totp" bind:value={f.totp} maxlength={2000} spellcheck="false" autocomplete="off" class="font-mono" placeholder={it?.has_totp ? 'Unchanged' : 'JBSWY3DPEHPK3PXP or otpauth://totp/…'} />
			{#if it?.has_totp}<button type="button" class="link mt-1 text-xs" onclick={() => ((clear.totp = true), (f.totp = ''))}>Remove the TOTP secret</button>{/if}
		{/if}
	</Field>

	<Field label="Notes" id="{uid}-notes" hint="Encrypted like the password: recovery codes, security questions, licence keys.">
		{#if clear.notes}
			<div class="border-border-strong bg-sunken flex h-9 items-center justify-between rounded-md border border-dashed px-3 text-sm">
				<span class="text-muted">The notes will be removed</span>
				<Button size="xs" variant="ghost" icon={Undo2} onclick={() => (clear.notes = false)}>Undo</Button>
			</div>
		{:else if it?.has_notes && notesWas === null}
			<div class="border-border-strong flex min-h-9 flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-1.5 text-sm">
				<span class="text-muted">Notes are set and stay as they are.</span>
				<span class="flex gap-1">
					<Button size="xs" loading={notesBusy} onclick={editNotes}>Reveal and edit</Button>
					<Button size="xs" variant="danger-ghost" onclick={() => (clear.notes = true)}>Remove</Button>
				</span>
			</div>
		{:else}
			<Textarea id="{uid}-notes" rows={4} bind:value={f.notes} maxlength={20000} spellcheck="false" />
		{/if}
	</Field>
	{#if busy}<span class="sr-only" role="status">Saving…</span>{/if}
</form>
