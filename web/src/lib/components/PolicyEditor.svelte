<script lang="ts">
	import { api } from '#lib/api.js';
	import { categories, rebootPolicies, severities } from '#lib/patches.js';
	import { clients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { PatchCategory, PatchPolicy, RebootPolicy, Severity } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Edits a policy, or creates one for a client or site (`policy` null). */
	let {
		policy,
		taken = [],
		onclose,
		onsaved
	}: {
		policy: PatchPolicy | null;
		/** `client:site` scopes that already have a policy. */
		taken?: string[];
		onclose: () => void;
		onsaved: () => void;
	} = $props();

	// svelte-ignore state_referenced_locally
	const p = policy;
	let clientId = $state(p?.client_id ?? '');
	let siteId = $state(p?.site_id ?? '');
	let sevs = $state<Severity[]>(p ? [...p.auto_approve_severities] : ['critical']);
	let cats = $state<PatchCategory[]>(p ? [...p.auto_approve_categories] : ['security', 'critical', 'definition']);
	let deferral = $state(String(p?.deferral_days ?? 0));
	let autoInstall = $state(p?.auto_install ?? false);
	let reboot = $state<RebootPolicy>(p?.reboot_policy ?? 'never');
	let busy = $state(false);
	let error = $state('');

	const client = $derived(clients.list.find((c) => c.id === clientId));
	const scopeTaken = $derived(!p && !!clientId && taken.includes(`${clientId}:${siteId}`));
	const title = $derived(
		p ? (p.site_name ? `Policy for ${p.client_name} › ${p.site_name}` : p.client_name ? `Policy for ${p.client_name}` : 'MSP-wide patch policy') : 'New patch policy'
	);

	function toggle<T>(list: T[], v: T, on: boolean): T[] {
		return on ? [...new Set([...list, v])] : list.filter((x) => x !== v);
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const days = Number(deferral);
		if (!Number.isInteger(days) || days < 0 || days > 365) {
			error = 'A whole number of days, 0–365';
			return;
		}
		error = '';
		busy = true;
		const body = {
			client_id: clientId || null,
			site_id: siteId || null,
			auto_approve_severities: sevs,
			auto_approve_categories: cats,
			deferral_days: days,
			auto_install: autoInstall,
			reboot_policy: reboot
		};
		try {
			if (p) await api.put(`/patch-policies/${p.id}`, body);
			else await api.post('/patch-policies', body);
			toast.success('Patch policy saved. Approvals were re-evaluated.');
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
	<form id="patch-policy" class="space-y-5" onsubmit={save}>
		{#if !p}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Client" id="pol-client" required>
					<Select id="pol-client" class="w-full" bind:value={clientId} onchange={() => (siteId = '')} options={[{ value: '', label: 'Choose a client…', disabled: true }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
				<Field label="Site" id="pol-site" hint="Leave on “Whole client” to cover every site">
					<Select id="pol-site" class="w-full" bind:value={siteId} disabled={!client} options={[{ value: '', label: 'Whole client' }, ...(client?.sites ?? []).map((s) => ({ value: s.id, label: s.name }))]} />
				</Field>
			</div>
			{#if scopeTaken}<p class="text-danger text-xs" role="alert">That {siteId ? 'site' : 'client'} already has a policy; edit it instead.</p>{/if}
		{/if}

		<fieldset>
			<legend class="label">Approve automatically by category</legend>
			<div class="grid gap-x-4 gap-y-2 sm:grid-cols-2">
				{#each categories as c (c.value)}
					<div title={c.hint}><Checkbox checked={cats.includes(c.value)} onchange={(on) => (cats = toggle(cats, c.value, on))}>{c.label}</Checkbox></div>
				{/each}
			</div>
		</fieldset>
		<fieldset>
			<legend class="label">…or by severity</legend>
			<div class="flex flex-wrap gap-x-4 gap-y-2">
				{#each severities.filter((s) => s.value !== 'unspecified') as s (s.value)}
					<Checkbox checked={sevs.includes(s.value)} onchange={(on) => (sevs = toggle(sevs, s.value, on))}>{s.label}</Checkbox>
				{/each}
			</div>
			<p class="hint">Only Windows and RHEL/Fedora rate updates. Debian, Ubuntu and Arch updates are approved by category (apt marks security updates).</p>
		</fieldset>

		<Field label="Defer automatic approvals" id="pol-defer" hint="Days after an update is first seen before it installs automatically. Manual approvals aren’t deferred." error={error}>
			<div class="flex items-center gap-2"><Input id="pol-defer" inputmode="numeric" class="w-24" bind:value={deferral} /><span class="text-muted text-sm">days</span></div>
		</Field>

		<div class="space-y-1">
			<Switch bind:checked={autoInstall}>Install approved updates automatically, during each site’s maintenance window</Switch>
			<p class="hint pl-11.5">Sites without a window install as soon as updates are eligible.</p>
		</div>

		<Field label="Restart after installing" id="pol-reboot" hint={rebootPolicies.find((r) => r.value === reboot)?.hint}>
			<Select id="pol-reboot" class="w-full sm:w-64" bind:value={reboot} options={rebootPolicies.map((r) => ({ value: r.value, label: r.label }))} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="patch-policy" loading={busy} disabled={(!p && !clientId) || scopeTaken}>Save policy</Button>
	{/snippet}
</Modal>
