<script lang="ts">
	import { api } from '#lib/api.js';
	import { clients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { SecurityPolicyRow } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Edits a security policy, or creates one for a client or site (`policy` null). */
	let {
		policy,
		template,
		taken = [],
		onclose,
		onsaved
	}: {
		policy: SecurityPolicyRow | null;
		/** A new policy starts from these settings (the MSP-wide policy). */
		template?: SecurityPolicyRow;
		/** `client:site` scopes that already have a policy. */
		taken?: string[];
		onclose: () => void;
		onsaved: () => void;
	} = $props();

	// svelte-ignore state_referenced_locally
	const p = policy;
	// svelte-ignore state_referenced_locally
	const t = policy ?? template;
	let clientId = $state(p?.client_id ?? '');
	let siteId = $state(p?.site_id ?? '');
	let enabled = $state(t?.sensor_enabled ?? true);
	let prevention = $state(t?.prevention ?? false);
	let autoQuarantine = $state(t?.auto_quarantine ?? true);
	let canaries = $state(t?.canaries ?? false);
	let quick = $state(String(t?.quick_scan_hours ?? 24));
	let full = $state(String(t?.full_scan_days ?? 7));
	let telemetry = $state(String(t?.telemetry_mb ?? 256));
	let errors = $state<Record<string, string>>({});
	let busy = $state(false);

	const client = $derived(clients.list.find((c) => c.id === clientId));
	const scopeTaken = $derived(!p && !!clientId && taken.includes(`${clientId}:${siteId}`));
	const title = $derived(
		p ? (p.site_name ? `Security policy for ${p.client_name} › ${p.site_name}` : p.client_name ? `Security policy for ${p.client_name}` : 'MSP-wide security policy') : 'New security policy'
	);

	function int(v: string, min: number, max: number): number | null {
		const n = Number(v);
		return Number.isInteger(n) && n >= min && n <= max ? n : null;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const q = int(quick, 0, 720);
		const f = int(full, 0, 90);
		const t = int(telemetry, 16, 4096);
		errors = {
			...(q === null ? { quick: 'A whole number of hours, 0–720' } : {}),
			...(f === null ? { full: 'A whole number of days, 0–90' } : {}),
			...(t === null ? { telemetry: 'A whole number of MB, 16–4096' } : {})
		};
		if (q === null || f === null || t === null) return;
		busy = true;
		const body = {
			client_id: clientId || null,
			site_id: siteId || null,
			sensor_enabled: enabled,
			quick_scan_hours: q,
			full_scan_days: f,
			auto_quarantine: autoQuarantine,
			prevention,
			canaries,
			telemetry_mb: t
		};
		try {
			if (p) await api.put(`/security/policies/${p.id}`, body);
			else await api.post('/security/policies', body);
			toast.success('Security policy saved. Agents pick it up within a minute.');
			onsaved();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal {title} {onclose} size="md" description="The most specific policy applies to each agent, whole: a site's policy, else its client's, else the MSP-wide one.">
	<form id="sensor-policy" class="space-y-5" onsubmit={save}>
		{#if !p}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Client" id="sp-client" required>
					<Select id="sp-client" class="w-full" bind:value={clientId} onchange={() => (siteId = '')} options={[{ value: '', label: 'Choose a client…', disabled: true }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
				<Field label="Site" id="sp-site" hint="Leave on “Whole client” to cover every site">
					<Select id="sp-site" class="w-full" bind:value={siteId} disabled={!client} options={[{ value: '', label: 'Whole client' }, ...(client?.sites ?? []).map((s) => ({ value: s.id, label: s.name }))]} />
				</Field>
			</div>
			{#if scopeTaken}<p class="text-danger text-xs" role="alert">That {siteId ? 'site' : 'client'} already has a policy; edit it instead.</p>{/if}
		{/if}

		<div class="space-y-1">
			<Switch bind:checked={enabled}>Run our sensor</Switch>
			<p class="hint pl-11.5">Records process, network, file and registry activity on the machine and runs the detection rules. Off: only the machine’s own antivirus is reported.</p>
		</div>
		<fieldset class="space-y-4" disabled={!enabled}>
			<legend class="sr-only">Sensor settings</legend>
			<div class="space-y-1">
				<Switch bind:checked={prevention} disabled={!enabled}>Prevention</Switch>
				<p class="hint pl-11.5">Rules in block mode kill the process or quarantine the file. Off: every rule only detects and alerts.</p>
			</div>
			<div class="space-y-1">
				<Switch bind:checked={autoQuarantine} disabled={!enabled}>Quarantine malicious files found by scans</Switch>
				<p class="hint pl-11.5">Files matching a known-bad hash or file rule are moved to quarantine; they can be restored.</p>
			</div>
			<div class="space-y-1">
				<Switch bind:checked={canaries} disabled={!enabled}>Ransomware decoy files</Switch>
				<p class="hint pl-11.5">Hidden files in user folders; anything that changes them is treated as ransomware.</p>
			</div>
			<div class="grid gap-3 sm:grid-cols-3">
				<Field label="Quick scan every" id="sp-quick" hint="Hours; 0 = never" error={errors.quick}>
					<div class="flex items-center gap-2"><Input id="sp-quick" inputmode="numeric" class="w-20" bind:value={quick} invalid={!!errors.quick} disabled={!enabled} /><span class="text-muted text-sm">hours</span></div>
				</Field>
				<Field label="Full scan every" id="sp-full" hint="Days; 0 = never" error={errors.full}>
					<div class="flex items-center gap-2"><Input id="sp-full" inputmode="numeric" class="w-20" bind:value={full} invalid={!!errors.full} disabled={!enabled} /><span class="text-muted text-sm">days</span></div>
				</Field>
				<Field label="Telemetry store" id="sp-tel" hint="On each machine" error={errors.telemetry}>
					<div class="flex items-center gap-2"><Input id="sp-tel" inputmode="numeric" class="w-20" bind:value={telemetry} invalid={!!errors.telemetry} disabled={!enabled} /><span class="text-muted text-sm">MB</span></div>
				</Field>
			</div>
		</fieldset>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="sensor-policy" loading={busy} disabled={(!p && !clientId) || scopeTaken}>Save policy</Button>
	{/snippet}
</Modal>
