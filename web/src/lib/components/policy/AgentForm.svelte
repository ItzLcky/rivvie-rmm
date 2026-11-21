<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	export const normalize = (c: Config): Config => ({ auto_update: !!c.auto_update });
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** The agent software itself: automatic updates. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let autoUpdate = $state(!!untrack(() => config).auto_update);
	$effect(() => {
		const c = { auto_update: autoUpdate };
		untrack(() => onchange(c, true));
	});
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Agent policy</legend>
	<PField path="auto_update" name="Automatic updates" hint="When a newer signed release is on the server for a device's platform, the device is offered it when it connects, or within a few minutes if it's already online. Each agent waits for running jobs, restarts, and rolls back by itself if the new version can't reconnect.">
		<Switch bind:checked={autoUpdate} {disabled}>Update agents automatically</Switch>
	</PField>
</fieldset>
