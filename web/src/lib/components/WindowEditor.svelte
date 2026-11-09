<script lang="ts">
	import { api } from '#lib/api.js';
	import { dayNames } from '#lib/patches.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { MaintenanceWindow } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	let { window: w, onclose, onsaved }: { window: MaintenanceWindow; onclose: () => void; onsaved: () => void } = $props();

	// svelte-ignore state_referenced_locally
	const initial = w;
	let days = $state<number[]>(initial.days ?? [6]);
	let start = $state(initial.start ?? '02:00');
	let hours = $state(String(initial.minutes ? initial.minutes / 60 : 3));
	let tz = $state(initial.tz === 'UTC' && !initial.days ? Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' : initial.tz);
	let busy = $state(false);
	let error = $state('');

	async function put(body: Record<string, unknown>, msg: string) {
		busy = true;
		try {
			await api.put(`/sites/${initial.site_id}/maintenance-window`, body);
			toast.success(msg);
			onsaved();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}

	function save(e: SubmitEvent) {
		e.preventDefault();
		const h = Number(hours);
		if (!/^\d{1,2}:\d{2}$/.test(start.trim())) return void (error = 'Start time like 02:00');
		if (!(h >= 0.25 && h <= 24)) return void (error = 'Between 0.25 and 24 hours');
		if (!days.length) return void (error = 'Pick at least one day, or remove the window');
		error = '';
		put({ days, start: start.trim(), minutes: Math.round(h * 60), tz: tz.trim() }, `Maintenance window for ${initial.site_name} saved.`);
	}
</script>

<Modal title="Maintenance window: {initial.client_name} › {initial.site_name}" {onclose} size="sm" description="Automatic installs only start inside this window. Reboots follow straight after an install.">
	<form id="maint-window" class="space-y-4" onsubmit={save}>
		<fieldset>
			<legend class="label">Days</legend>
			<div class="flex flex-wrap gap-x-3 gap-y-2">
				{#each dayNames as d, i (d)}
					<Checkbox checked={days.includes(i)} onchange={(on) => (days = on ? [...new Set([...days, i])].sort() : days.filter((x) => x !== i))}>{d}</Checkbox>
				{/each}
			</div>
		</fieldset>
		<div class="grid grid-cols-2 gap-3">
			<Field label="Starts at" id="mw-start"><Input id="mw-start" type="time" bind:value={start} /></Field>
			<Field label="Lasts (hours)" id="mw-hours"><Input id="mw-hours" inputmode="decimal" bind:value={hours} /></Field>
		</div>
		<Field label="Time zone" id="mw-tz" hint="IANA name, e.g. Europe/London or America/New_York" error={error}>
			<Input id="mw-tz" bind:value={tz} autocomplete="off" />
		</Field>
	</form>
	{#snippet footer()}
		{#if initial.days?.length}<Button variant="ghost" class="mr-auto" disabled={busy} onclick={() => put({ days: [], tz: initial.tz }, `${initial.site_name} has no maintenance window now.`)}>Remove window</Button>{/if}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="maint-window" loading={busy}>Save</Button>
	{/snippet}
</Modal>
