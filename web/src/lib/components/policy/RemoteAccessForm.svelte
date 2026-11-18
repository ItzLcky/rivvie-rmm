<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	type Draft = { desktop: boolean; consent: boolean; shell: boolean; files: boolean };
	const fromConfig = (c: Config): Draft => ({ desktop: c.desktop_enabled !== false, consent: !!c.desktop_consent, shell: c.shell_enabled !== false, files: c.files_enabled !== false });
	const toConfig = (d: Draft): Config => ({ desktop_enabled: d.desktop, desktop_consent: d.consent, shell_enabled: d.shell, files_enabled: d.files });
	export const normalize = (c: Config) => toConfig(fromConfig(c));
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** Which remote tools technicians may open on a device. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let d = $state(fromConfig(untrack(() => config)));
	$effect(() => {
		const c = toConfig(d);
		untrack(() => onchange(c, true));
	});
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Remote access policy</legend>
	<PField path="desktop_enabled" name="Remote desktop" hint="Off: the Remote desktop tab refuses to connect and names this policy set.">
		<Switch bind:checked={d.desktop} {disabled}>Allow remote desktop</Switch>
	</PField>
	<PField path="desktop_consent" name="Ask first" hint="The person at the machine gets an Allow / Deny prompt, and the session is refused if nobody answers within 30 seconds. If nobody is signed in, the session starts without asking.">
		<Switch bind:checked={d.consent} disabled={disabled || !d.desktop}>Ask the user before a remote desktop session starts</Switch>
	</PField>
	<PField path="shell_enabled" name="Terminal">
		<Switch bind:checked={d.shell} {disabled}>Allow the terminal</Switch>
	</PField>
	<PField path="files_enabled" name="Files" hint="Browsing, downloading and uploading files. Listing and ending processes isn't covered.">
		<Switch bind:checked={d.files} {disabled}>Allow file access</Switch>
	</PField>
	<p class="hint">Scripts, patching and security actions aren't affected.</p>
</fieldset>
