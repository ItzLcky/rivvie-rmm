<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	type Draft = { script_id: string; cron: string; timezone: string; args: string; timeout_secs: string; retain_days: number };
	export const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

	function fromConfig(c: Config): Draft {
		return {
			script_id: (c.script_id as string) ?? '', cron: (c.cron as string) ?? '0 2 * * *', timezone: (c.timezone as string) ?? 'UTC',
			args: ((c.args as string[]) ?? []).join('\n'), timeout_secs: c.timeout_secs == null ? '' : String(c.timeout_secs), retain_days: Number(c.retain_days ?? 30)
		};
	}
	function toConfig(d: Draft): Config {
		return {
			script_id: d.script_id || null, cron: d.cron.trim(), timezone: d.timezone, args: d.args.split('\n').map((a) => a.trim()).filter(Boolean),
			timeout_secs: d.timeout_secs.trim() ? Number(d.timeout_secs) : null, retain_days: Number(d.retain_days)
		};
	}
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	export const blankSchedule = (): Config => ({ script_id: null, cron: '0 2 * * *', timezone: localTz, args: [], timeout_secs: null, retain_days: 30 });
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import { describeCron } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { Script } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import PField from './PField.svelte';

	/** A scheduled script: what runs, with which arguments, and when, as a config. */
	let {
		config,
		onchange,
		disabled = false,
		below = false,
		clientId = null,
		onscript
	}: {
		config: Config;
		onchange: (config: Config, valid: boolean) => void;
		disabled?: boolean;
		/** Shown in a set below the one it's defined in: only arguments and the timeout can change. */
		below?: boolean;
		/** The client it's limited to: its own scripts may be used. */
		clientId?: string | null;
		/** A script was picked (to suggest a name). */
		onscript?: (s: Script) => void;
	} = $props();

	const presets = [
		{ label: 'Hourly', cron: '0 * * * *' },
		{ label: 'Daily 02:00', cron: '0 2 * * *' },
		{ label: 'Weekdays 07:00', cron: '0 7 * * 1-5' },
		{ label: 'Sundays 03:00', cron: '0 3 * * 0' },
		{ label: 'Monthly, 1st', cron: '0 4 1 * *' }
	];

	let draft = $state(fromConfig(untrack(() => config)));
	const timeoutError = $derived(draft.timeout_secs.trim() && !(Number.isInteger(Number(draft.timeout_secs)) && Number(draft.timeout_secs) >= 1 && Number(draft.timeout_secs) <= 86400) ? 'Whole seconds, 1–86400' : undefined);
	$effect(() => {
		const c = toConfig(draft);
		const ok = !!c.script_id && !timeoutError && !preview?.error;
		untrack(() => onchange(c, ok));
	});

	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived((scripts.data ?? []).filter((s) => !s.client_id || s.client_id === clientId).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined })));
	const script = $derived(scripts.data?.find((s) => s.id === draft.script_id));
	const zones = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return [localTz];
		}
	})();
	const zoneItems = ['UTC', ...zones.filter((z) => z !== 'UTC')].map((z) => ({ value: z, label: z }));
	const fixed = $derived(disabled || below);

	// Next runs, previewed by the server (the same parser the scheduler uses).
	let preview = $state<{ runs: string[]; error?: string } | null>(null);
	$effect(() => {
		const c = draft.cron;
		const tz = draft.timezone;
		if (!c.trim()) return void (preview = null);
		const t = setTimeout(() => {
			api.get<{ runs: string[]; error?: string }>(`/schedules/preview${qs({ cron: c, timezone: tz })}`).then((p) => (preview = p), () => {});
		}, 300);
		return () => clearTimeout(t);
	});

	function pick(id: string) {
		const s = scripts.data?.find((x) => x.id === id);
		if (s) onscript?.(s);
	}
</script>

<div class="grid gap-4 xl:grid-cols-2">
	<fieldset class="card space-y-4 self-start p-4" {disabled}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">What</legend>
		<PField path="script_id" label="Script" id="sc-script" class="clear-both" hint={below ? 'The same script in every set.' : undefined}>
			<!-- Mounted once the scripts are in: the input shows the selected label from its first render. -->
			{#if scripts.data}<Combobox id="sc-script" bind:value={draft.script_id} items={scriptItems} placeholder="Pick a saved script" label="Script" onchange={pick} disabled={fixed} />{:else}<Skeleton class="h-8 w-full" />{/if}
		</PField>
		<PField path="args" label="Arguments" id="sc-args" hint="One per line, passed to the script in order.">
			<Textarea id="sc-args" rows={2} class="font-mono text-[13px]" bind:value={draft.args} />
		</PField>
		<div class="grid gap-3 sm:grid-cols-2">
			<PField path="timeout_secs" label="Timeout (s)" id="sc-timeout" error={timeoutError}>
				<Input id="sc-timeout" inputmode="numeric" bind:value={draft.timeout_secs} invalid={!!timeoutError} placeholder={script ? `${script.timeout_secs} (script)` : 'Script default'} />
			</PField>
			<PField path="retain_days" label="Keep runs (days)" id="sc-keep" hint="Each run's output is deleted after this many days.">
				<Input id="sc-keep" type="number" min="1" max="3650" bind:value={draft.retain_days} disabled={fixed} />
			</PField>
		</div>
	</fieldset>

	<fieldset class="card space-y-4 self-start p-4" disabled={fixed}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">When</legend>
		{#if below}<p class="hint clear-both -mt-1">One timetable for every set: change it where the script is defined.</p>{/if}
		<div class="clear-both flex flex-wrap gap-1.5">
			{#each presets as p (p.cron)}<Button size="sm" variant={draft.cron === p.cron ? 'primary' : 'secondary'} disabled={fixed} onclick={() => (draft.cron = p.cron)}>{p.label}</Button>{/each}
		</div>
		<div class="grid gap-3 sm:grid-cols-[1fr_14rem]">
			<PField path="cron" label="Cron expression" id="sc-cron" hint="minute hour day-of-month month day-of-week" error={preview?.error}>
				<Input id="sc-cron" class="font-mono" bind:value={draft.cron} invalid={!!preview?.error} />
			</PField>
			<PField path="timezone" label="Time zone" id="sc-tz"><Combobox id="sc-tz" bind:value={draft.timezone} items={zoneItems} label="Time zone" disabled={fixed} /></PField>
		</div>
		{#if preview && !preview.error}
			<div class="text-sm">
				<p class="font-medium">{describeCron(draft.cron)}</p>
				<ul class="text-muted mt-1 space-y-0.5 text-xs tabular">{#each preview.runs as r (r)}<li>{datetime(r)}</li>{/each}</ul>
			</div>
		{/if}
		<p class="hint">Every device using this set (or one below it) gets a job when it fires. Offline devices run it when they reconnect, unless the last run is still waiting for them. A run that comes due while the server is down runs once when it's back.</p>
	</fieldset>
</div>
