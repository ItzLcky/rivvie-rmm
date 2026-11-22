<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';
	import type { Want } from '#lib/software.js';

	type Window = { days: number[]; start: string; minutes: number; tz: string } | null;
	type Draft = { package_id: string; state: Want; bootstrap: boolean; ownWindow: boolean; days: number[]; start: string; hours: string; tz: string };

	function fromConfig(c: Config): Draft {
		const w = c.window as Window;
		return {
			package_id: (c.package_id as string) ?? '', state: (c.state as Want) ?? 'present', bootstrap: !!c.bootstrap_choco,
			ownWindow: !!w, days: w?.days ?? [6], start: w?.start ?? '02:00', hours: String(w ? w.minutes / 60 : 3), tz: w?.tz ?? 'site'
		};
	}
	function toConfig(d: Draft): Config {
		return {
			package_id: d.package_id || null, state: d.state, bootstrap_choco: d.bootstrap,
			window: d.ownWindow ? { days: d.days, start: d.start.trim(), minutes: Math.round(Number(d.hours) * 60), tz: d.tz.trim() || 'site' } : null
		};
	}
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	export const blankSoftware = (): Config => ({ package_id: null, state: 'present', bootstrap_choco: false, window: null });
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { dayNames } from '#lib/patches.js';
	import { resource } from '#lib/resource.svelte.js';
	import { sourcesOf, wantHints, wantLabels, type SoftwarePackage } from '#lib/software.js';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** A software requirement: which catalog package, and whether it must be there, kept current or gone. */
	let {
		config,
		onchange,
		disabled = false,
		below = false,
		clientId = null,
		onpackage
	}: {
		config: Config;
		onchange: (config: Config, valid: boolean) => void;
		disabled?: boolean;
		/** Shown in a set below the one it's defined in: the package itself can't change. */
		below?: boolean;
		/** The client it's limited to: its own packages may be used. */
		clientId?: string | null;
		/** A package was picked (to suggest a name). */
		onpackage?: (name: string) => void;
	} = $props();

	let d = $state(fromConfig(untrack(() => config)));
	const errors = $derived({
		start: !d.ownWindow || /^\d{1,2}:\d{2}$/.test(d.start.trim()) ? undefined : 'A time like 02:00',
		hours: !d.ownWindow || (Number(d.hours) >= 0.25 && Number(d.hours) <= 24) ? undefined : 'Between 0.25 and 24 hours'
	});
	$effect(() => {
		const c = toConfig(d);
		const ok = !!c.package_id && !errors.start && !errors.hours;
		untrack(() => onchange(c, ok));
	});

	const packages = resource(() => api.get<SoftwarePackage[]>('/software/packages'));
	const items = $derived(
		(packages.data ?? []).filter((p) => !p.client_id || p.client_id === clientId).map((p) => ({ value: p.id, label: p.name, hint: [p.client_name, sourcesOf(p).join(' · ')].filter(Boolean).join(' · ') || undefined }))
	);
	const pkg = $derived(packages.data?.find((p) => p.id === d.package_id));
	const fixed = $derived(disabled || below);
	const zones = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return ['UTC'];
		}
	})();
	const zoneItems = [{ value: 'site', label: 'The site’s time zone' }, ...['UTC', ...zones.filter((z) => z !== 'UTC')].map((z) => ({ value: z, label: z }))];
	function pick(id: string) {
		const p = packages.data?.find((x) => x.id === id);
		if (p) onpackage?.(p.name);
	}
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Software requirement</legend>
	<PField path="package_id" label="Package" id="sw-pkg" hint={below ? 'The same package in every set.' : 'From the software catalog.'}>
		{#if packages.data}<Combobox id="sw-pkg" bind:value={d.package_id} items={items} placeholder="Pick a catalog package" label="Package" onchange={pick} disabled={fixed} />{:else}<Skeleton class="h-8 w-full" />{/if}
	</PField>
	{#if pkg}
		<p class="text-muted -mt-3 text-xs">
			{sourcesOf(pkg).join(', ') || 'No source yet'} · {pkg.version ? `held at ${pkg.version}` : 'latest version'} · <a class="link" href="/software/{pkg.id}">open in the catalog</a>
		</p>
	{/if}

	<PField path="state" name="Requirement">
		<fieldset>
			<legend class="label">Devices must have it</legend>
			<Segmented label="Requirement" size="md" value={d.state} onchange={(v) => (d.state = v as Want)} options={(['present', 'latest', 'absent'] as Want[]).map((w) => ({ value: w, label: wantLabels[w] }))} />
			<p class="hint">{wantHints[d.state]}</p>
		</fieldset>
	</PField>

	{#if d.state === 'latest'}
		<PField path="window" name="Upgrade window">
			<fieldset class="space-y-3">
				<legend class="label">Upgrade window</legend>
				<Segmented label="Upgrade window" size="md" value={d.ownWindow ? 'own' : 'site'} onchange={(v) => (d.ownWindow = v === 'own')} options={[{ value: 'site', label: 'Each site’s maintenance window' }, { value: 'own', label: 'Its own' }]} />
				{#if d.ownWindow}
					<div class="flex flex-wrap gap-x-3 gap-y-2" role="group" aria-label="Days">
						{#each dayNames as name, i (name)}
							<Checkbox checked={d.days.includes(i)} onchange={(on) => (d.days = on ? [...new Set([...d.days, i])].sort() : d.days.filter((x) => x !== i))}>{name}</Checkbox>
						{/each}
					</div>
					<div class="grid gap-3 sm:grid-cols-[8rem_8rem_1fr]">
						<div>
							<label class="label" for="sw-start">Starts at</label>
							<Input id="sw-start" type="time" bind:value={d.start} invalid={!!errors.start} />
							{#if errors.start}<p class="text-danger mt-1 text-xs" role="alert">{errors.start}</p>{/if}
						</div>
						<div>
							<label class="label" for="sw-hours">Lasts (hours)</label>
							<Input id="sw-hours" inputmode="decimal" bind:value={d.hours} invalid={!!errors.hours} />
							{#if errors.hours}<p class="text-danger mt-1 text-xs" role="alert">{errors.hours}</p>{/if}
						</div>
						<div>
							<label class="label" for="sw-tz">Time zone</label>
							<Combobox id="sw-tz" bind:value={d.tz} items={zoneItems} label="Time zone" {disabled} />
						</div>
					</div>
				{:else}
					<p class="hint">Set per site under Patches › Maintenance windows. Sites without one upgrade as soon as a newer version is offered. Installs and removals never wait.</p>
				{/if}
			</fieldset>
		</PField>
	{/if}

	{#if pkg?.choco_id && !pkg.winget_id}
		<PField path="bootstrap_choco" name="Chocolatey install" hint="This package is only available through Chocolatey. Installing it downloads and runs Chocolatey’s install script from chocolatey.org on devices that lack it.">
			<Switch bind:checked={d.bootstrap} {disabled}>Install Chocolatey on devices that don’t have it</Switch>
		</PField>
	{/if}
</fieldset>
