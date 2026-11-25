<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	type Draft = { enabled: boolean; account: string; create: boolean; rotate_days: number; length: number; rotate_after_reveal_hours: number };
	const fromConfig = (c: Config): Draft => ({
		enabled: !!c.enabled,
		account: typeof c.account === 'string' ? c.account : 'rmmadmin',
		create: c.create !== false,
		rotate_days: Number(c.rotate_days ?? 30),
		length: Number(c.length ?? 20),
		rotate_after_reveal_hours: Number(c.rotate_after_reveal_hours ?? 24)
	});
	const toConfig = (d: Draft): Config => ({ ...d, account: d.account.trim(), rotate_days: Number(d.rotate_days), length: Number(d.length), rotate_after_reveal_hours: Number(d.rotate_after_reveal_hours) });
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	const builtin = ['administrator', 'admin', 'root', 'guest', 'defaultaccount', 'wdagutilityaccount'];
	export function accountError(a: string): string | undefined {
		const t = a.trim();
		if (!/^[a-z][a-z0-9_-]{0,19}$/.test(t)) return 'Up to 20 lower-case letters, digits, - or _, starting with a letter.';
		if (builtin.includes(t)) return `${t} is a built-in account; pick a name of its own.`;
	}
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import Input from '#lib/ui/Input.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** One managed local admin account per device, its password rotated into the vault. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let d = $state(fromConfig(untrack(() => config)));
	const err = $derived(accountError(d.account));
	const valid = $derived(!err && d.rotate_days >= 1 && d.rotate_days <= 365 && d.length >= 14 && d.length <= 64 && d.rotate_after_reveal_hours >= 0 && d.rotate_after_reveal_hours <= 720);
	$effect(() => {
		const c = toConfig(d);
		const ok = valid;
		untrack(() => onchange(c, ok));
	});
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Local admin password policy</legend>
	<PField path="enabled" name="Rotation" hint="Turn it on in the sets that need it (Windows workstations, say). Windows and Linux; macOS and domain controllers report it as unsupported. Turning it off stops rotating and leaves the account and its password in place.">
		<Switch bind:checked={d.enabled} {disabled}>Rotate the local admin password</Switch>
	</PField>
	<div class="grid gap-3 sm:grid-cols-2">
		<PField path="account" label="Account" id="la-account" error={err} hint="Not the built-in Administrator: Windows LAPS may manage that one.">
			<Input id="la-account" class="font-mono" bind:value={d.account} {disabled} />
		</PField>
		<PField path="create" name="Create the account">
			<Switch bind:checked={d.create} {disabled}>Create it (as an administrator) where it doesn't exist</Switch>
		</PField>
		<PField path="rotate_days" label="Rotate every (days)" id="la-days">
			<Input id="la-days" type="number" min="1" max="365" class="max-w-40" bind:value={d.rotate_days} {disabled} />
		</PField>
		<PField path="length" label="Password length" id="la-len" hint="14-64; letters, digits and symbols.">
			<Input id="la-len" type="number" min="14" max="64" class="max-w-40" bind:value={d.length} {disabled} />
		</PField>
		<PField path="rotate_after_reveal_hours" label="Rotate after a reveal (hours)" id="la-reveal" hint="Someone saw it: change it this long after. 0: don't.">
			<Input id="la-reveal" type="number" min="0" max="720" class="max-w-40" bind:value={d.rotate_after_reveal_hours} {disabled} />
		</PField>
	</div>
	<p class="hint">The server makes each password and stores it in the client's vault before the device sets it, so a failed or lost rotation never locks anyone out: the previous password stays in the credential's history. Needs RMM_DATA_KEY on the server.</p>
</fieldset>
