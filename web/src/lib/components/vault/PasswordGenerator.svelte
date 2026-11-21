<script lang="ts">
	import { Dices } from '@lucide/svelte';
	import { GEN_DEFAULTS, generatePassword, type GenOptions } from '#lib/docs/vault.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';

	/** Makes a random password in the browser (crypto.getRandomValues) for the form to use. */
	let { onuse, onclose }: { onuse: (password: string) => void; onclose: () => void } = $props();

	let o = $state<GenOptions>({ ...GEN_DEFAULTS });
	let value = $state('');
	const regenerate = () => (value = generatePassword(o));
	$effect(() => {
		void [o.length, o.lower, o.upper, o.digits, o.symbols, o.unambiguous];
		regenerate();
	});
	const uid = $props.id();
</script>

<div class="border-border bg-sunken/60 space-y-3 rounded-md border p-3" role="group" aria-label="Password generator">
	<div class="flex items-center gap-2">
		<output class="border-border bg-raised min-w-0 flex-1 rounded-md border px-2.5 py-1.5 font-mono text-sm break-all" for="{uid}-len" aria-live="polite">{value || 'Pick at least one kind of character'}</output>
		<Button size="sm" icon={Dices} onclick={regenerate} aria-label="Generate another">Another</Button>
	</div>
	<div class="flex items-center gap-3">
		<label for="{uid}-len" class="text-muted shrink-0 text-xs">Length</label>
		<input id="{uid}-len" type="range" min="8" max="64" bind:value={o.length} class="accent-accent min-w-0 flex-1" />
		<span class="tabular w-6 text-right text-sm">{o.length}</span>
	</div>
	<div class="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3">
		<Checkbox bind:checked={o.lower}>a–z</Checkbox>
		<Checkbox bind:checked={o.upper}>A–Z</Checkbox>
		<Checkbox bind:checked={o.digits}>0–9</Checkbox>
		<Checkbox bind:checked={o.symbols}>Symbols</Checkbox>
		<Checkbox bind:checked={o.unambiguous}>No look-alikes</Checkbox>
	</div>
	<div class="flex justify-end gap-2">
		<Button size="sm" variant="ghost" onclick={onclose}>Close</Button>
		<Button size="sm" variant="primary" disabled={!value} onclick={() => onuse(value)}>Use this password</Button>
	</div>
</div>
