<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';
	import type { RealtimeMode } from '#lib/types.js';

	type Draft = {
		enabled: boolean; prevention: boolean; autoQuarantine: boolean; canaries: boolean; quick: string; full: string; telemetry: string;
		realtime: RealtimeMode; scanOnWrite: boolean; depth: string; dbAge: string;
	};
	function fromConfig(t: Config): Draft {
		return {
			enabled: (t.sensor_enabled as boolean) ?? true, prevention: !!t.prevention, autoQuarantine: (t.auto_quarantine as boolean) ?? true, canaries: !!t.canaries,
			quick: String(t.quick_scan_hours ?? 24), full: String(t.full_scan_days ?? 7), telemetry: String(t.telemetry_mb ?? 256),
			realtime: (t.realtime as RealtimeMode) ?? 'off', scanOnWrite: (t.scan_on_write as boolean) ?? true, depth: String(t.archive_depth ?? 5), dbAge: String(t.database_max_age_hours ?? 72)
		};
	}
	function toConfig(d: Draft): Config {
		return {
			sensor_enabled: d.enabled, quick_scan_hours: Number(d.quick), full_scan_days: Number(d.full), auto_quarantine: d.autoQuarantine, prevention: d.prevention,
			canaries: d.canaries, telemetry_mb: Number(d.telemetry), realtime: d.realtime, scan_on_write: d.scanOnWrite, archive_depth: Number(d.depth),
			database_max_age_hours: Number(d.dbAge)
		};
	}
	export const normalize = (c: Config) => toConfig(fromConfig(c));
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { TriangleAlert } from '@lucide/svelte';
	import { realtimeModeHelp, realtimeModeLabels } from '#lib/security.js';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** The security policy: our sensor, real-time protection, scans and quarantine. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let d = $state(fromConfig(untrack(() => config)));
	const modes: RealtimeMode[] = ['off', 'audit', 'block'];
	const int = (v: string, min: number, max: number) => {
		const n = Number(v);
		return Number.isInteger(n) && n >= min && n <= max;
	};
	const errors = $derived({
		quick: int(d.quick, 0, 720) ? undefined : 'A whole number of hours, 0–720',
		full: int(d.full, 0, 90) ? undefined : 'A whole number of days, 0–90',
		telemetry: int(d.telemetry, 16, 4096) ? undefined : 'A whole number of MB, 16–4096',
		depth: int(d.depth, 1, 20) ? undefined : 'A whole number, 1–20',
		dbAge: int(d.dbAge, 0, 8760) ? undefined : 'A whole number of hours, 0–8760'
	});
	$effect(() => {
		const c = toConfig(d);
		const ok = Object.values(errors).every((e) => !e);
		untrack(() => onchange(c, ok));
	});
	const off = $derived(disabled || !d.enabled);
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Security policy</legend>
	<PField path="sensor_enabled" name="Sensor" hint="Records process, network, file and registry activity on the machine and runs the detection rules. Off: only the machine’s own antivirus is reported.">
		<Switch bind:checked={d.enabled} {disabled}>Run our sensor</Switch>
	</PField>
	<fieldset class="space-y-4" disabled={off}>
		<legend class="sr-only">Sensor settings</legend>
		<PField path="prevention" name="Prevention" hint="Rules in block mode kill the process or quarantine the file, and real-time Block denies known-bad programs. Off: every rule only detects and alerts.">
			<Switch bind:checked={d.prevention} disabled={off}>Prevention</Switch>
		</PField>
		<fieldset class="border-border space-y-3 rounded-md border p-3" aria-describedby="sp-rt-help">
			<legend class="px-1 text-sm font-medium">Real-time protection <span class="text-muted font-normal">(Linux)</span></legend>
			<PField path="realtime" name="Real-time protection">
				<Segmented label="Real-time protection" size="md" value={d.realtime} onchange={(v) => (d.realtime = v)} options={modes.map((m) => ({ value: m, label: realtimeModeLabels[m] }))} />
			</PField>
			<p id="sp-rt-help" class="hint" aria-live="polite">{realtimeModeHelp(d.realtime, d.prevention)}</p>
			{#if d.realtime === 'block' && !d.prevention}
				<p class="border-warning/40 bg-warning-soft flex gap-2 rounded-md border px-3 py-2 text-sm" role="status">
					<TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
					<span><span class="text-warning font-semibold">Nothing will be blocked.</span> Block only denies programs while Prevention is on.</span>
				</p>
			{/if}
			<p class="hint">Windows and macOS agents scan programs just after they start and report real-time protection as not available there; that isn’t counted against them.</p>
			<PField path="scan_on_write" name="Scan on write" hint="Each file is scanned when it’s closed after writing (up to 32 MB). Files the package manager writes are reported, never quarantined.">
				<Switch bind:checked={d.scanOnWrite} disabled={off || d.realtime === 'off'}>Scan files as they’re written</Switch>
			</PField>
		</fieldset>
		<PField path="auto_quarantine" name="Quarantine" hint="Files matching a known-bad hash or file rule are moved to quarantine; they can be restored.">
			<Switch bind:checked={d.autoQuarantine} disabled={off}>Quarantine malicious files found by scans</Switch>
		</PField>
		<PField path="canaries" name="Decoy files" hint="Hidden files in user folders; anything that changes them is treated as ransomware.">
			<Switch bind:checked={d.canaries} disabled={off}>Ransomware decoy files</Switch>
		</PField>
		<div class="grid gap-3 sm:grid-cols-3">
			<PField path="quick_scan_hours" label="Quick scan every" id="sp-quick" hint="Hours; 0 = never" error={errors.quick}>
				<div class="flex items-center gap-2"><Input id="sp-quick" inputmode="numeric" class="w-20" bind:value={d.quick} invalid={!!errors.quick} disabled={off} /><span class="text-muted text-sm">hours</span></div>
			</PField>
			<PField path="full_scan_days" label="Full scan every" id="sp-full" hint="Days; 0 = never" error={errors.full}>
				<div class="flex items-center gap-2"><Input id="sp-full" inputmode="numeric" class="w-20" bind:value={d.full} invalid={!!errors.full} disabled={off} /><span class="text-muted text-sm">days</span></div>
			</PField>
			<PField path="telemetry_mb" label="Telemetry store" id="sp-tel" hint="On each machine" error={errors.telemetry}>
				<div class="flex items-center gap-2"><Input id="sp-tel" inputmode="numeric" class="w-20" bind:value={d.telemetry} invalid={!!errors.telemetry} disabled={off} /><span class="text-muted text-sm">MB</span></div>
			</PField>
		</div>
		<div class="grid gap-3 sm:grid-cols-2">
			<PField path="archive_depth" label="Archive depth" id="sp-depth" hint="Archives inside archives, 1–20. Past it: a low-severity “archive bomb” finding." error={errors.depth}>
				<div class="flex items-center gap-2"><Input id="sp-depth" inputmode="numeric" class="w-20" bind:value={d.depth} invalid={!!errors.depth} disabled={off} /><span class="text-muted text-sm">levels</span></div>
			</PField>
			<PField path="database_max_age_hours" label="Signature database out of date after" id="sp-dbage" hint="Then the agent counts as at risk and can alert. 0 = no limit." error={errors.dbAge}>
				<div class="flex items-center gap-2"><Input id="sp-dbage" inputmode="numeric" class="w-20" bind:value={d.dbAge} invalid={!!errors.dbAge} disabled={off} /><span class="text-muted text-sm">hours</span></div>
			</PField>
		</div>
	</fieldset>
</fieldset>
