<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Mute } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';

	/**
	 * Holds alerts back for one agent, site or client: a snooze (from now, or a set period) or
	 * a weekly maintenance window. Without a `target` the client (and optionally site) is
	 * picked here.
	 */
	let {
		target,
		onclose,
		onsaved
	}: {
		target?: { agent_id?: string; site_id?: string; client_id?: string; name: string };
		onclose: () => void;
		onsaved?: (m: Mute) => void;
	} = $props();

	$effect(() => {
		if (!target) loadClients();
	});

	// Snoozes are for one machine; whole clients and sites usually get a weekly window.
	let mode = $state<'snooze' | 'weekly'>(untrack(() => (target?.agent_id ? 'snooze' : 'weekly')));
	const presets = [
		{ value: '60', label: '1 hour' },
		{ value: '240', label: '4 hours' },
		{ value: '1440', label: '1 day' },
		{ value: '4320', label: '3 days' },
		{ value: 'until', label: 'Until…' }
	];
	let preset = $state('240');
	let until = $state('');
	let days = $state<number[]>([6, 0]);
	let start = $state('22:00');
	let hours = $state(6);
	let tz = $state(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
	let reason = $state('');
	let clientId = $state<string | null>(null);
	let siteId = $state<string | null>(null);
	let busy = $state(false);
	const sites = $derived(clients.list.find((c) => c.id === clientId)?.sites ?? []);
	const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

	const valid = $derived(
		(target || clientId) &&
			(mode === 'snooze' ? preset !== 'until' || (!!until && Date.parse(until) > Date.now()) : days.length > 0 && /^\d{2}:\d{2}$/.test(start) && hours > 0 && hours <= 168)
	);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const where = target ? { agent_id: target.agent_id, site_id: target.site_id, client_id: target.client_id } : siteId ? { site_id: siteId } : { client_id: clientId };
		const when =
			mode === 'snooze'
				? preset === 'until'
					? { ends_at: new Date(until).toISOString() }
					: { for_minutes: Number(preset) }
				: { days, start, minutes: Math.round(Number(hours) * 60), tz };
		busy = true;
		try {
			const m = await api.post<Mute>('/alert-mutes', { ...where, ...when, reason });
			toast.success(mode === 'snooze' ? 'Alerts snoozed. New alerts are recorded but nobody is notified.' : 'Maintenance window added.');
			onsaved?.(m);
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal
	title={mode === 'snooze' ? 'Snooze alerts' : 'Alert maintenance window'}
	description={target ? `For ${target.name}. Alerts that open meanwhile are kept, without notifications or tickets, and don’t count against health. Still open when it ends, they’re announced then.` : 'Alerts that open during the window are kept, without notifications or tickets, and don’t count against health.'}
	{onclose}
>
	<form id="mute-form" class="space-y-4" onsubmit={save}>
		{#if !target}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Client" id="m-client">
					<Select id="m-client" bind:value={clientId} onchange={() => (siteId = null)} options={[{ value: null, label: 'Pick a client' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
				<Field label="Site" id="m-site">
					<Select id="m-site" bind:value={siteId} disabled={!clientId} options={[{ value: null, label: 'Every site' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} />
				</Field>
			</div>
		{/if}
		<Segmented label="Kind" size="md" value={mode} onchange={(v) => (mode = v)} options={[{ value: 'snooze', label: 'Once' }, { value: 'weekly', label: 'Every week' }]} />
		{#if mode === 'snooze'}
			<Field label="For" id="m-for">
				<Select id="m-for" class="max-w-48" bind:value={preset} options={presets} />
			</Field>
			{#if preset === 'until'}
				<Field label="Until" id="m-until"><Input id="m-until" type="datetime-local" class="max-w-64" bind:value={until} required /></Field>
			{/if}
		{:else}
			<fieldset>
				<legend class="label">Days</legend>
				<div class="flex flex-wrap gap-3">
					{#each dayNames as d, i (d)}
						<Checkbox checked={days.includes(i)} onchange={(on) => (days = on ? [...days, i] : days.filter((x) => x !== i))}>{d}</Checkbox>
					{/each}
				</div>
			</fieldset>
			<div class="grid grid-cols-2 gap-3 sm:grid-cols-3">
				<Field label="Starts at" id="m-start"><Input id="m-start" type="time" bind:value={start} required /></Field>
				<Field label="Lasts (hours)" id="m-hours"><Input id="m-hours" type="number" min="0.25" max="168" step="0.25" bind:value={hours} /></Field>
				<Field label="Time zone" id="m-tz" class="col-span-2 sm:col-span-1"><Input id="m-tz" bind:value={tz} /></Field>
			</div>
		{/if}
		<Field label="Reason" id="m-reason" hint="Shown on the agent and in the audit log.">
			<Input id="m-reason" bind:value={reason} maxlength={500} placeholder={mode === 'snooze' ? 'e.g. replacing the disk' : 'e.g. nightly backups'} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="mute-form" loading={busy} disabled={!valid}>{mode === 'snooze' ? 'Snooze' : 'Add window'}</Button>
	{/snippet}
</Modal>
