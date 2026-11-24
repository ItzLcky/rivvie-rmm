<script lang="ts">
	import { Eye, KeyRound, Vault } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import type { ActionOutcome, DirUser } from '#lib/identity.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/**
	 * Reset a directory password. The password goes to exactly one place: shown here once
	 * (and stored nowhere), or saved in the client's vault.
	 */
	let { user, onclose, ondone, initial = null }: { user: DirUser; onclose: () => void; ondone: () => void; initial?: ActionOutcome | null } = $props();

	let choose = $state<'generate' | 'type'>('generate');
	let password = $state('');
	let mustChange = $state(true);
	let delivery = $state<'show' | 'vault'>('vault');
	let saving = $state(false);
	// svelte-ignore state_referenced_locally
	let outcome = $state<ActionOutcome | null>(initial);
	const who = $derived(user.display_name || user.username);

	async function reset(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			outcome = await api.post<ActionOutcome>(`/identity/users/${user.id}/reset-password`, {
				password: choose === 'type' ? password : null,
				must_change: mustChange,
				delivery
			});
			password = '';
			if (outcome.delivered === 'vault') toast.success(`${who}’s password was reset and saved in the vault.`);
			ondone();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Modal title="Reset {who}’s password" description="{user.source_name} · {user.upn || user.username}" {onclose}>
	{#if outcome?.delivered === 'shown' && outcome.password}
		<div class="space-y-3">
			<p class="text-sm">The password was reset. Give it to {who} now: it isn’t stored anywhere and won’t be shown again.</p>
			<div class="border-border bg-sunken flex items-center gap-2 rounded-md border px-3 py-2">
				<code class="min-w-0 flex-1 font-mono text-base break-all" data-testid="shown-password">{outcome.password}</code>
				<CopyButton text={outcome.password} label="Copy password" />
			</div>
			{#if mustChange}<p class="hint">They’ll be asked to choose a new one when they sign in.</p>{/if}
		</div>
	{:else if outcome?.delivered === 'vault'}
		<p class="text-sm">The password was reset and saved in the client’s vault. Reveal it from the Passwords tab when you need it.</p>
	{:else}
		<form id="reset-form" class="space-y-4" onsubmit={reset}>
			<Segmented label="New password" value={choose} onchange={(v) => (choose = v)} options={[{ value: 'generate', label: 'Generate one' }, { value: 'type', label: 'Type one' }]} />
			{#if choose === 'type'}
				<Field label="Password" id="rp-pw" required hint="8 to 256 characters; the directory’s own complexity rules apply too.">
					<Input id="rp-pw" type="password" autocomplete="new-password" required minlength={8} maxlength={256} bind:value={password} />
				</Field>
			{:else}
				<p class="hint">16 random characters: letters, digits and a symbol, nothing easily misread.</p>
			{/if}
			<Switch bind:checked={mustChange}>Ask for a new password at the next sign-in</Switch>
			<div class="space-y-1.5" role="radiogroup" aria-labelledby="rp-then">
				<p id="rp-then" class="mb-1 text-sm font-medium">Then</p>
				{#each [{ v: 'vault', icon: Vault, label: 'Save it in the vault', hint: 'A managed credential for this account; reveal it later from the Passwords tab.' }, { v: 'show', icon: Eye, label: 'Show it to me once', hint: 'Shown here and stored nowhere, not even in the audit log.' }] as o (o.v)}
					{@const on = delivery === o.v}
					<button type="button" role="radio" aria-checked={on} class="flex w-full items-start gap-2 rounded-md border px-3 py-2 text-left text-sm {on ? 'border-accent bg-accent-soft' : 'border-border hover:bg-hover'}" onclick={() => (delivery = o.v as 'vault' | 'show')}>
						<o.icon class="mt-0.5 size-4 shrink-0" />
						<span><span class="block font-medium">{o.label}</span><span class="text-muted block text-xs">{o.hint}</span></span>
					</button>
				{/each}
			</div>
		</form>
	{/if}
	{#snippet footer()}
		{#if outcome}
			<Button variant="primary" onclick={onclose}>Done</Button>
		{:else}
			<Button onclick={onclose}>Cancel</Button>
			<Button variant="primary" type="submit" form="reset-form" icon={KeyRound} loading={saving} disabled={choose === 'type' && password.length < 8}>Reset password</Button>
		{/if}
	{/snippet}
</Modal>
