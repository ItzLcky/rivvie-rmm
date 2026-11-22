<script lang="ts" module>
	import { oncePerDevice, type AutomationTrigger } from '#lib/policy/policy.js';
	import type { Config } from '#lib/policy/types.js';
	import type { PolicyKind } from '#lib/types.js';

	type Draft = {
		trigger: AutomationTrigger; script_id: string; args: string; timeout_secs: string;
		offline_minutes: number; alert_kind: PolicyKind;
		retry_failed: boolean; max_attempts: number; retry_minutes: number;
		cooldown_minutes: number; max_runs_per_hour: number; respect_window: boolean; retain_days: number;
	};
	function fromConfig(c: Config): Draft {
		return {
			trigger: (c.trigger as AutomationTrigger) ?? 'enrollment', script_id: (c.script_id as string) ?? '',
			args: ((c.args as string[]) ?? []).join('\n'), timeout_secs: c.timeout_secs == null ? '' : String(c.timeout_secs),
			offline_minutes: Number(c.offline_minutes ?? 30), alert_kind: (c.alert_kind as PolicyKind) ?? 'disk',
			retry_failed: !!c.retry_failed, max_attempts: Number(c.max_attempts ?? 3), retry_minutes: Number(c.retry_minutes ?? 30),
			cooldown_minutes: Number(c.cooldown_minutes ?? 60), max_runs_per_hour: Number(c.max_runs_per_hour ?? 100),
			respect_window: !!c.respect_window, retain_days: Number(c.retain_days ?? 30)
		};
	}
	/** Fields that belong to another trigger are sent as null, so switching trigger never leaves them behind. */
	function toConfig(d: Draft): Config {
		const once = oncePerDevice.includes(d.trigger);
		return {
			trigger: d.trigger, script_id: d.script_id || null, args: d.args.split('\n').map((a) => a.trim()).filter(Boolean),
			timeout_secs: d.timeout_secs.trim() ? Number(d.timeout_secs) : null,
			offline_minutes: d.trigger === 'agent_online' ? Number(d.offline_minutes) : null,
			alert_kind: d.trigger === 'alert_opened' ? d.alert_kind : null,
			retry_failed: once && d.retry_failed, max_attempts: Number(d.max_attempts), retry_minutes: Number(d.retry_minutes),
			cooldown_minutes: Number(d.cooldown_minutes), max_runs_per_hour: Number(d.max_runs_per_hour),
			respect_window: d.respect_window, retain_days: Number(d.retain_days)
		};
	}
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	export const blankAutomation = (): Config => toConfig(fromConfig({}));
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { kindLabels } from '#lib/monitoring/labels.js';
	import { triggerHelp, triggerLabels } from '#lib/policy/policy.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { Script } from '#lib/types.js';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import PField from './PField.svelte';

	/** An automation: what starts it, which script runs, and the safeguards that keep it from running away. */
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
		/** Shown in a set below the one it's defined in: the trigger and script are fixed. */
		below?: boolean;
		/** The client it's limited to: its own scripts may be used. */
		clientId?: string | null;
		onscript?: (s: Script) => void;
	} = $props();

	let draft = $state(fromConfig(untrack(() => config)));
	const once = $derived(oncePerDevice.includes(draft.trigger));
	const int = (v: unknown, lo: number, hi: number) => (Number.isInteger(Number(v)) && Number(v) >= lo && Number(v) <= hi ? undefined : `Whole number, ${lo}–${hi}`);
	const errors = $derived({
		timeout: draft.timeout_secs.trim() ? int(draft.timeout_secs, 1, 86400) : undefined,
		offline: draft.trigger === 'agent_online' ? int(draft.offline_minutes, 5, 43200) : undefined,
		attempts: once && draft.retry_failed ? int(draft.max_attempts, 1, 10) : undefined,
		retry: once && draft.retry_failed ? int(draft.retry_minutes, 5, 1440) : undefined,
		cooldown: once ? undefined : int(draft.cooldown_minutes, 0, 10080),
		rate: int(draft.max_runs_per_hour, 1, 10000),
		keep: once ? undefined : int(draft.retain_days, 1, 3650)
	});
	$effect(() => {
		const c = toConfig(draft);
		const ok = !!c.script_id && !Object.values(errors).some(Boolean);
		untrack(() => onchange(c, ok));
	});

	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived((scripts.data ?? []).filter((s) => !s.client_id || s.client_id === clientId).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined })));
	const script = $derived(scripts.data?.find((s) => s.id === draft.script_id));
	const fixed = $derived(disabled || below);
	const triggers = (Object.keys(triggerLabels) as (keyof typeof triggerLabels)[]).map((t) => ({ value: t, label: triggerLabels[t] }));
	const kinds = (Object.keys(kindLabels) as PolicyKind[]).map((k) => ({ value: k, label: kindLabels[k] }));

	function pick(id: string) {
		const s = scripts.data?.find((x) => x.id === id);
		if (s) onscript?.(s);
	}
</script>

<div class="grid gap-4 xl:grid-cols-2">
	<fieldset class="card space-y-4 self-start p-4" disabled={fixed}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">When</legend>
		{#if below}<p class="hint clear-both -mt-1">The trigger and the script are the same in every set: change them where the automation is defined.</p>{/if}
		<PField path="trigger" label="Trigger" id="au-trigger" class="clear-both" hint={triggerHelp[draft.trigger]}>
			<Select id="au-trigger" class="w-full" bind:value={draft.trigger} options={triggers} disabled={fixed} />
		</PField>
		{#if draft.trigger === 'agent_online'}
			<PField path="offline_minutes" label="Offline for at least (minutes)" id="au-offline" error={errors.offline} hint="Counted from the last time the device was heard from. After the server restarts, from the restart.">
				<Input id="au-offline" type="number" min="5" max="43200" bind:value={draft.offline_minutes} invalid={!!errors.offline} disabled={fixed} />
			</PField>
		{:else if draft.trigger === 'alert_opened'}
			<PField path="alert_kind" label="Type of alert" id="au-kind"><Select id="au-kind" class="w-full" bind:value={draft.alert_kind} options={kinds} disabled={fixed} /></PField>
		{/if}
	</fieldset>

	<fieldset class="card space-y-4 self-start p-4" {disabled}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">What runs</legend>
		<PField path="script_id" label="Script" id="au-script" class="clear-both" hint={below ? 'The same script in every set.' : 'A saved script, run as a job on the device. Its result is in Jobs and in the device’s automation history.'}>
			{#if scripts.data}<Combobox id="au-script" bind:value={draft.script_id} items={scriptItems} placeholder="Pick a saved script" label="Script" onchange={pick} disabled={fixed} />{:else}<Skeleton class="h-8 w-full" />{/if}
		</PField>
		<PField path="args" label="Arguments" id="au-args" hint="One per line, passed to the script in order.">
			<Textarea id="au-args" rows={2} class="font-mono text-[13px]" bind:value={draft.args} />
		</PField>
		<PField path="timeout_secs" label="Timeout (s)" id="au-timeout" error={errors.timeout}>
			<Input id="au-timeout" inputmode="numeric" bind:value={draft.timeout_secs} invalid={!!errors.timeout} placeholder={script ? `${script.timeout_secs} (script)` : 'Script default'} />
		</PField>
	</fieldset>

	<fieldset class="card space-y-4 self-start p-4 xl:col-span-2" {disabled}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">Safeguards</legend>
		<div class="clear-both grid gap-4 md:grid-cols-2 xl:grid-cols-3">
			{#if !once}
				<PField path="cooldown_minutes" label="Cooldown per device (minutes)" id="au-cool" error={errors.cooldown} hint="The same device doesn’t run this again within this time; 0 = no limit. Skipped events are listed as Skipped.">
					<Input id="au-cool" type="number" min="0" max="10080" bind:value={draft.cooldown_minutes} invalid={!!errors.cooldown} />
				</PField>
			{/if}
			<PField path="max_runs_per_hour" label="Most runs per hour" id="au-rate" error={errors.rate} hint={once ? 'Across all devices. Devices over the limit wait for the next hour: none is dropped.' : 'Across all devices. Events over the limit are skipped, so one cause hitting hundreds of devices doesn’t start hundreds of scripts.'}>
				<Input id="au-rate" type="number" min="1" max="10000" bind:value={draft.max_runs_per_hour} invalid={!!errors.rate} />
			</PField>
			{#if !once}
				<PField path="retain_days" label="Keep history (days)" id="au-keep" error={errors.keep}>
					<Input id="au-keep" type="number" min="1" max="3650" bind:value={draft.retain_days} invalid={!!errors.keep} disabled={fixed} />
				</PField>
			{/if}
		</div>
		<PField path="respect_window" label="Maintenance window" hint="Held until the device’s site maintenance window is open, then started. Sites without a window run it at once. Event runs held for more than a day are dropped.">
			<Switch bind:checked={draft.respect_window} {disabled}>Only run inside the site’s maintenance window</Switch>
		</PField>
		{#if once}
			<div class="border-border space-y-3 border-t pt-3">
				<PField path="retry_failed" label="Retry failures" hint="A device where the script fails runs it again after the wait, up to the number of attempts. Cancelled runs aren’t retried.">
					<Switch bind:checked={draft.retry_failed} {disabled}>Run again where it fails</Switch>
				</PField>
				{#if draft.retry_failed}
					<div class="grid gap-3 sm:grid-cols-2">
						<PField path="max_attempts" label="Attempts in all" id="au-att" error={errors.attempts}><Input id="au-att" type="number" min="1" max="10" bind:value={draft.max_attempts} invalid={!!errors.attempts} /></PField>
						<PField path="retry_minutes" label="Wait between attempts (minutes)" id="au-wait" error={errors.retry}><Input id="au-wait" type="number" min="5" max="1440" bind:value={draft.retry_minutes} invalid={!!errors.retry} /></PField>
					</div>
				{/if}
			</div>
		{/if}
	</fieldset>
</div>
