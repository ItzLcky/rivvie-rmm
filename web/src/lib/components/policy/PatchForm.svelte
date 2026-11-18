<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';
	import type { PatchCategory, PatchSeverity, RebootPolicy } from '#lib/types.js';

	type Draft = {
		sevs: PatchSeverity[]; cats: PatchCategory[]; deferral: string; autoInstall: boolean; reboot: RebootPolicy;
		ownWindow: boolean; days: number[]; start: string; hours: string; tz: string;
	};
	type Window = { days: number[]; start: string; minutes: number; tz: string } | null;

	function fromConfig(c: Config): Draft {
		const w = c.window as Window;
		return {
			sevs: [...((c.auto_approve_severities as PatchSeverity[]) ?? [])], cats: [...((c.auto_approve_categories as PatchCategory[]) ?? [])],
			deferral: String(c.deferral_days ?? 0), autoInstall: !!c.auto_install, reboot: (c.reboot_policy as RebootPolicy) ?? 'never',
			ownWindow: !!w, days: w?.days ?? [6], start: w?.start ?? '02:00', hours: String(w ? w.minutes / 60 : 3), tz: w?.tz ?? 'site'
		};
	}
	function toConfig(d: Draft): Config {
		return {
			auto_approve_severities: d.sevs, auto_approve_categories: d.cats, deferral_days: Number(d.deferral), auto_install: d.autoInstall, reboot_policy: d.reboot,
			window: d.ownWindow ? { days: d.days, start: d.start.trim(), minutes: Math.round(Number(d.hours) * 60), tz: d.tz.trim() || 'site' } : null
		};
	}
	export const normalize = (c: Config) => toConfig(fromConfig(c));
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { categories, dayNames, rebootPolicies, severities } from '#lib/patches.js';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** The patch policy: what's approved automatically, when it installs, and restarts. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let d = $state(fromConfig(untrack(() => config)));
	const errors = $derived({
		deferral: Number.isInteger(Number(d.deferral)) && Number(d.deferral) >= 0 && Number(d.deferral) <= 365 ? undefined : 'A whole number of days, 0–365',
		start: !d.ownWindow || /^\d{1,2}:\d{2}$/.test(d.start.trim()) ? undefined : 'A time like 02:00',
		hours: !d.ownWindow || (Number(d.hours) >= 0.25 && Number(d.hours) <= 24) ? undefined : 'Between 0.25 and 24 hours'
	});
	$effect(() => {
		const c = toConfig(d);
		const ok = !errors.deferral && !errors.start && !errors.hours;
		untrack(() => onchange(c, ok));
	});

	function toggle<T>(list: T[], v: T, on: boolean): T[] {
		return on ? [...new Set([...list, v])] : list.filter((x) => x !== v);
	}
	const zones = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return ['UTC'];
		}
	})();
	const zoneItems = [{ value: 'site', label: 'The site’s time zone' }, ...['UTC', ...zones.filter((z) => z !== 'UTC')].map((z) => ({ value: z, label: z }))];
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Patch policy</legend>
	<PField path="auto_approve_categories" name="Categories">
		<fieldset>
			<legend class="label">Approve automatically by category</legend>
			<div class="grid gap-x-4 gap-y-2 sm:grid-cols-2">
				{#each categories as c (c.value)}
					<div title={c.hint}><Checkbox checked={d.cats.includes(c.value)} onchange={(on) => (d.cats = toggle(d.cats, c.value, on))}>{c.label}</Checkbox></div>
				{/each}
			</div>
		</fieldset>
	</PField>
	<PField path="auto_approve_severities" name="Severities">
		<fieldset>
			<legend class="label">…or by severity</legend>
			<div class="flex flex-wrap gap-x-4 gap-y-2">
				{#each severities.filter((s) => s.value !== 'unspecified') as s (s.value)}
					<Checkbox checked={d.sevs.includes(s.value)} onchange={(on) => (d.sevs = toggle(d.sevs, s.value, on))}>{s.label}</Checkbox>
				{/each}
			</div>
			<p class="hint">Only Windows and RHEL/Fedora rate updates. Debian, Ubuntu and Arch updates are approved by category (apt marks security updates).</p>
		</fieldset>
	</PField>

	<PField path="deferral_days" label="Defer automatic approvals" id="pol-defer" hint="Days after an update is first seen before it installs automatically. Manual approvals aren’t deferred." error={errors.deferral}>
		<div class="flex items-center gap-2"><Input id="pol-defer" inputmode="numeric" class="w-24" bind:value={d.deferral} invalid={!!errors.deferral} /><span class="text-muted text-sm">days</span></div>
	</PField>

	<PField path="auto_install" name="Automatic install" hint="Inside the install window below. Without a window, as soon as updates are eligible.">
		<Switch bind:checked={d.autoInstall} {disabled}>Install approved updates automatically</Switch>
	</PField>

	<PField path="window" name="Install window">
		<fieldset class="space-y-3">
			<legend class="label">Install window</legend>
			<Segmented label="Install window" size="md" value={d.ownWindow ? 'own' : 'site'} onchange={(v) => (d.ownWindow = v === 'own')} options={[{ value: 'site', label: 'Each site’s maintenance window' }, { value: 'own', label: 'Its own' }]} />
			{#if d.ownWindow}
				<div class="flex flex-wrap gap-x-3 gap-y-2" role="group" aria-label="Days">
					{#each dayNames as name, i (name)}
						<Checkbox checked={d.days.includes(i)} onchange={(on) => (d.days = on ? [...new Set([...d.days, i])].sort() : d.days.filter((x) => x !== i))}>{name}</Checkbox>
					{/each}
				</div>
				<div class="grid gap-3 sm:grid-cols-[8rem_8rem_1fr]">
					<div>
						<label class="label" for="pw-start">Starts at</label>
						<Input id="pw-start" type="time" bind:value={d.start} invalid={!!errors.start} />
						{#if errors.start}<p class="text-danger mt-1 text-xs" role="alert">{errors.start}</p>{/if}
					</div>
					<div>
						<label class="label" for="pw-hours">Lasts (hours)</label>
						<Input id="pw-hours" inputmode="decimal" bind:value={d.hours} invalid={!!errors.hours} />
						{#if errors.hours}<p class="text-danger mt-1 text-xs" role="alert">{errors.hours}</p>{/if}
					</div>
					<div>
						<label class="label" for="pw-tz">Time zone</label>
						<Combobox id="pw-tz" bind:value={d.tz} items={zoneItems} label="Time zone" {disabled} />
					</div>
				</div>
				<p class="hint">{d.days.length ? 'Lets servers and workstations at one site patch at different times.' : 'No days ticked: installs may start at any time.'}</p>
			{:else}
				<p class="hint">Set per site under Patches › Maintenance windows. Sites without one install as soon as updates are eligible.</p>
			{/if}
		</fieldset>
	</PField>

	<PField path="reboot_policy" label="Restart after installing" id="pol-reboot" hint={rebootPolicies.find((r) => r.value === d.reboot)?.hint}>
		<Select id="pol-reboot" class="w-full sm:w-64" bind:value={d.reboot} options={rebootPolicies.map((r) => ({ value: r.value, label: r.label }))} />
	</PField>
</fieldset>
