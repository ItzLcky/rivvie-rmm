<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	export const normalize = (c: Config): Config => ({ escrow_recovery_keys: c.escrow_recovery_keys !== false, add_recovery_protector: !!c.add_recovery_protector });
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** BitLocker recovery keys: escrowed into the client's vault, and added where missing. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let escrow = $state(untrack(() => config).escrow_recovery_keys !== false);
	let add = $state(!!untrack(() => config).add_recovery_protector);
	$effect(() => {
		const c = { escrow_recovery_keys: escrow, add_recovery_protector: add };
		untrack(() => onchange(c, true));
	});
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Disk encryption policy</legend>
	<PField path="escrow_recovery_keys" name="Escrow recovery keys" hint="Each BitLocker volume's recovery password is read from the device and kept in its client's Passwords tab, as a managed credential. Revealing it needs vault access and two-factor authentication. A new recovery password is picked up at the next report. Needs RMM_DATA_KEY on the server.">
		<Switch bind:checked={escrow} {disabled}>Keep BitLocker recovery passwords in the vault</Switch>
	</PField>
	<PField path="add_recovery_protector" name="Add a recovery password" hint="For an encrypted volume that has no recovery password (only a TPM, say). Group Policy may forbid numerical passwords; the device's card shows why it failed. It isn't retried for a day.">
		<Switch bind:checked={add} {disabled}>Add a recovery password where a BitLocker volume has none</Switch>
	</PField>
	<p class="hint">Encryption itself isn't turned on from here: it needs TPM readiness and a restart. FileVault and LUKS are reported, but their keys can't be escrowed. Alerts come from <em>Disk encryption</em> alert items.</p>
</fieldset>
