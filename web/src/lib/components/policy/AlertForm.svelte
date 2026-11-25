<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';
	import type { LogLevel, PolicyKind, Priority, Severity } from '#lib/types.js';

	/** Every field of every kind; only the chosen kind's params are kept. Lists are edited as text. */
	type Draft = {
		kind: PolicyKind; severity: Severity; channel_ids: string[]; notify_resolved: boolean;
		ticket_board_id: string | null; ticket_priority: Priority; ticket_auto_resolve: boolean; run_script_id: string;
		minutes: number; threshold: number; services: string; auto_only: boolean; exclude: string; script_id: string;
		min_level: LogLevel; channels: string; sources: string; event_ids: string; pattern: string;
		unprotected: boolean; realtime_off: boolean; sensor_down: boolean; sig_check: boolean; sig_hours: number; threats: 'off' | 'active' | 'any';
		sensor_realtime: boolean; database_stale: boolean;
		stale_check: boolean; stale_hours: number;
		patch_failed: boolean; reboot_check: boolean; reboot_hours: number;
		renotify: boolean; renotify_minutes: number;
		metric: 'cpu' | 'memory' | 'interface_util' | 'supply'; net_kinds: string; net_names: string;
		up_failures: number; up_kinds: string; up_cert: boolean; up_cert_days: number; up_latency: boolean; up_latency_ms: number;
		bk_providers: string[]; bk_sources: BackupSource[]; bk_jobs: string; bk_max_age: number; bk_warning: boolean; bk_require: boolean;
		de_volumes: 'os' | 'all_fixed'; de_escrow: boolean; de_grace: number; la_overdue: number;
		vu_severity: 'critical' | 'high' | 'medium' | 'low'; vu_kev: boolean; vu_fix: boolean; vu_days: number; vu_epss_check: boolean; vu_epss: number;
	};
	export type BackupSource = { provider: 'restic' | 'borg' | 'file_age'; env_file: string; repo: string; path: string; glob: string };
	const defaults: Record<PolicyKind, Partial<Draft>> = {
		offline: { minutes: 10 },
		cpu: { threshold: 90, minutes: 15 },
		memory: { threshold: 90, minutes: 15 },
		disk: { threshold: 90, minutes: 5 },
		service: {},
		job_failed: {},
		log: {},
		security: {},
		patch: {},
		net_down: { minutes: 5 },
		net_interface: { minutes: 5 },
		net_threshold: { threshold: 90, minutes: 10, metric: 'cpu' },
		uptime: {},
		backup: {},
		disk_encryption: {},
		local_admin: {},
		vulnerability: {}
	};
	const blank = (kind: PolicyKind): Draft => ({
		kind, severity: 'warning', channel_ids: [], notify_resolved: true, ticket_board_id: null, ticket_priority: 3, ticket_auto_resolve: true, run_script_id: '',
		minutes: 10, threshold: 90, services: '', auto_only: false, exclude: '', script_id: '', min_level: 'error', channels: '', sources: '', event_ids: '', pattern: '',
		unprotected: true, realtime_off: false, sensor_down: true, sig_check: true, sig_hours: 72, threats: 'active', sensor_realtime: true, database_stale: true,
		stale_check: false, stale_hours: 24, patch_failed: true, reboot_check: true, reboot_hours: 72, renotify: false, renotify_minutes: 240, metric: 'cpu', net_kinds: '', net_names: '',
		up_failures: 2, up_kinds: '', up_cert: true, up_cert_days: 14, up_latency: false, up_latency_ms: 1000,
		bk_providers: ['auto'], bk_sources: [], bk_jobs: '*', bk_max_age: 26, bk_warning: false, bk_require: false,
		de_volumes: 'os', de_escrow: true, de_grace: 24, la_overdue: 7,
		vu_severity: 'critical', vu_kev: false, vu_fix: true, vu_days: 14, vu_epss_check: false, vu_epss: 10,
		...defaults[kind]
	});
	const list = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
	const text = (v: unknown) => (Array.isArray(v) ? v.join('\n') : '');

	function fromConfig(c: Config): Draft {
		const kind = (c.kind as PolicyKind) ?? 'offline';
		const q = (c.params ?? {}) as Record<string, unknown>;
		return {
			...blank(kind),
			severity: (c.severity as Severity) ?? 'warning', channel_ids: (c.channel_ids as string[]) ?? [], notify_resolved: c.notify_resolved !== false,
			ticket_board_id: (c.ticket_board_id as string) ?? null, ticket_priority: (c.ticket_priority as Priority) ?? 3, ticket_auto_resolve: !!c.ticket_auto_resolve,
			run_script_id: (c.run_script_id as string) ?? '',
			minutes: Number(q.minutes ?? defaults[kind].minutes ?? 10), threshold: Number(q.threshold ?? 90), services: text(q.services), auto_only: !!q.auto_only, exclude: text(q.exclude),
			script_id: (q.script_id as string) ?? '', min_level: (q.min_level as LogLevel) ?? 'error', channels: text(q.channels).replaceAll('\n', ', '),
			sources: text(q.sources), event_ids: Array.isArray(q.event_ids) ? q.event_ids.join(', ') : '', pattern: (q.pattern as string) ?? '',
			unprotected: !!q.unprotected, realtime_off: !!q.realtime_off, sensor_down: !!q.sensor_down, sig_check: q.signature_max_age_hours != null,
			sig_hours: Number(q.signature_max_age_hours ?? 72), threats: (q.threats as Draft['threats']) ?? 'active',
			sensor_realtime: !!q.sensor_realtime, database_stale: !!q.database_stale,
			stale_check: q.stale_hours != null, stale_hours: Number(q.stale_hours ?? 24),
			patch_failed: q.failed !== false, reboot_check: q.reboot_hours != null, reboot_hours: Number(q.reboot_hours ?? 72),
			renotify: c.renotify_minutes != null, renotify_minutes: (c.renotify_minutes as number) ?? 240,
			metric: (q.metric as Draft['metric']) ?? 'cpu', net_kinds: text(q.kinds).replaceAll('\n', ', '), net_names: text(q.names),
			up_failures: Number(q.failures ?? 2), up_kinds: text(q.kinds).replaceAll('\n', ', '), up_cert: q.cert_days !== 0, up_cert_days: Number(q.cert_days || 14),
			up_latency: q.latency_ms != null, up_latency_ms: Number(q.latency_ms ?? 1000),
			bk_providers: Array.isArray(q.providers) ? (q.providers as string[]) : ['auto'],
			bk_sources: Array.isArray(q.sources)
				? (q.sources as Record<string, string | null>[]).map((s) => ({ provider: (s.provider as BackupSource['provider']) ?? 'restic', env_file: s.env_file ?? '', repo: s.repo ?? '', path: s.path ?? '', glob: s.glob ?? '' }))
				: [],
			bk_jobs: Array.isArray(q.jobs) ? (q.jobs as string[]).join('\n') : '*', bk_max_age: Number(q.max_age_hours ?? 26), bk_warning: !!q.warning_is_failure, bk_require: !!q.require,
			de_volumes: q.volumes === 'all_fixed' ? 'all_fixed' : 'os', de_escrow: q.require_escrow !== false, de_grace: Number(q.grace_hours ?? 24),
			la_overdue: Number(q.overdue_days ?? 7),
			vu_severity: (q.min_severity as Draft['vu_severity']) ?? 'critical', vu_kev: !!q.kev_only, vu_fix: q.fix_available_only !== false,
			vu_days: Number(q.older_than_days ?? 14), vu_epss_check: q.min_epss != null, vu_epss: Math.round(Number(q.min_epss ?? 0.1) * 100)
		};
	}
	function params(d: Draft): Record<string, unknown> {
		switch (d.kind) {
			case 'offline':
				return { minutes: Number(d.minutes) };
			case 'cpu':
			case 'memory':
			case 'disk':
				return { threshold: Number(d.threshold), minutes: Number(d.minutes) };
			case 'service':
				return { services: list(d.services), auto_only: d.auto_only, exclude: list(d.exclude) };
			case 'job_failed':
				return { script_id: d.script_id || null };
			case 'log':
				return {
					min_level: d.min_level, channels: list(d.channels), sources: list(d.sources), pattern: d.pattern.trim() || null,
					event_ids: list(d.event_ids).map(Number).filter((n) => Number.isInteger(n) && n >= 0)
				};
			case 'security':
				return {
					unprotected: d.unprotected, realtime_off: d.realtime_off, sensor_down: d.sensor_down, signature_max_age_hours: d.sig_check ? Number(d.sig_hours) : null, threats: d.threats,
					sensor_realtime: d.sensor_realtime, database_stale: d.database_stale,
					stale_hours: d.stale_check ? Number(d.stale_hours) : null
				};
			case 'net_down':
				return { minutes: Number(d.minutes), kinds: list(d.net_kinds) };
			case 'net_interface':
				return { minutes: Number(d.minutes), names: list(d.net_names), kinds: list(d.net_kinds) };
			case 'net_threshold':
				return { metric: d.metric, threshold: Number(d.threshold), minutes: Number(d.minutes), names: d.metric === 'interface_util' ? list(d.net_names) : [], kinds: list(d.net_kinds) };
			case 'patch':
				return { failed: d.patch_failed, reboot_hours: d.reboot_check ? Number(d.reboot_hours) : null };
			case 'uptime':
				return { failures: Number(d.up_failures), kinds: list(d.up_kinds), cert_days: d.up_cert ? Number(d.up_cert_days) : 0, latency_ms: d.up_latency ? Number(d.up_latency_ms) : null };
			case 'disk_encryption':
				return { volumes: d.de_volumes, require_escrow: d.de_escrow, grace_hours: Number(d.de_grace) };
			case 'local_admin':
				return { overdue_days: Number(d.la_overdue) };
			case 'vulnerability':
				return {
					min_severity: d.vu_severity, kev_only: d.vu_kev, fix_available_only: d.vu_fix, older_than_days: Number(d.vu_days),
					min_epss: d.vu_epss_check ? Number(d.vu_epss) / 100 : null
				};
			case 'backup': {
				const opt = (s: string) => s.trim() || null;
				return {
					providers: d.bk_providers,
					sources: d.bk_sources.map((s) => ({ provider: s.provider, env_file: s.provider === 'file_age' ? null : opt(s.env_file), repo: s.provider === 'file_age' ? null : opt(s.repo), path: s.provider === 'file_age' ? opt(s.path) : null, glob: s.provider === 'file_age' ? opt(s.glob) : null })),
					jobs: list(d.bk_jobs).length ? list(d.bk_jobs) : ['*'],
					max_age_hours: Number(d.bk_max_age),
					warning_is_failure: d.bk_warning,
					require: d.bk_require
				};
			}
		}
	}
	function toConfig(d: Draft): Config {
		return {
			kind: d.kind, params: params(d), severity: d.severity, channel_ids: d.channel_ids, notify_resolved: d.notify_resolved,
			renotify_minutes: d.renotify ? Number(d.renotify_minutes) : null, ticket_board_id: d.ticket_board_id, ticket_priority: d.ticket_priority,
			ticket_auto_resolve: d.ticket_auto_resolve, run_script_id: d.run_script_id || null
		};
	}
	/** The config as this form writes it back, so an unchanged form reads as unchanged. */
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	export const blankAlert = (kind: PolicyKind): Config => toConfig(blank(kind));
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { kindHelp, kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { priorities, ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { Board, Channel, Script } from '#lib/types.js';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import PField from './PField.svelte';

	/** An alert policy's rule, notifications, tickets and script, as a config. */
	let {
		config,
		onchange,
		disabled = false,
		pickKind = false,
		clientId = null
	}: {
		/** Read when the form mounts. */
		config: Config;
		onchange: (config: Config, valid: boolean) => void;
		disabled?: boolean;
		/** A new policy: choose what it alerts on. */
		pickKind?: boolean;
		/** The client the policy is limited to: its own scripts may be used. */
		clientId?: string | null;
	} = $props();

	let draft = $state(fromConfig(untrack(() => config)));
	$effect(() => {
		const c = toConfig(draft);
		untrack(() => onchange(c, true));
	});

	const channels = resource(() => api.get<Channel[]>('/notification-channels'));
	let boards = $state<Board[] | null>(null);
	$effect(() => {
		ticketMeta().then((m) => (boards = m.boards));
	});
	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived((scripts.data ?? []).filter((s) => !s.client_id || s.client_id === clientId).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined })));

	function choose(k: PolicyKind) {
		draft = { ...draft, kind: k, ...defaults[k] };
	}
	function toggleChannel(id: string, on: boolean) {
		draft.channel_ids = on ? [...draft.channel_ids, id] : draft.channel_ids.filter((c) => c !== id);
	}
	const backupProviders = [
		{ value: 'auto', label: 'Detect', hint: 'Windows Server Backup and Veeam where installed; Time Machine on a Mac' },
		{ value: 'wsb', label: 'Windows Server Backup' },
		{ value: 'veeam', label: 'Veeam' },
		{ value: 'timemachine', label: 'Time Machine' }
	];
	function toggleProvider(p: string, on: boolean) {
		draft.bk_providers = on ? [...draft.bk_providers.filter((x) => x !== p), p] : draft.bk_providers.filter((x) => x !== p);
	}
	function addSource() {
		draft.bk_sources = [...draft.bk_sources, { provider: 'restic', env_file: '', repo: '', path: '', glob: '' }];
	}
	const hours = (m: number) => (m < 60 ? `${m} minutes` : m < 1440 ? `${m / 60} hour${m === 60 ? '' : 's'}` : `${m / 1440} day${m === 1440 ? '' : 's'}`);
</script>

<div class="grid gap-4 xl:grid-cols-2">
	<fieldset class="card space-y-4 self-start p-4" {disabled}>
		<legend class="float-left w-full pb-3 text-sm font-semibold">Rule</legend>
		{#if pickKind}
			<div role="radiogroup" aria-label="Alert on" class="clear-both space-y-1.5">
				<span class="label">Alert on</span>
				<div class="grid gap-1.5 sm:grid-cols-2">
					{#each Object.keys(kindLabels) as k (k)}
						{@const on = draft.kind === k}
						<button
							type="button"
							role="radio"
							aria-checked={on}
							class={cx('rounded-md border px-3 py-2 text-left text-sm transition-colors', on ? 'border-accent bg-accent-soft' : 'border-border hover:bg-hover')}
							onclick={() => choose(k as PolicyKind)}
						>
							<span class={cx('block font-medium', on && 'text-accent')}>{kindLabels[k as PolicyKind]}</span>
							<span class="text-muted block text-xs">{kindHelp[k as PolicyKind]}</span>
						</button>
					{/each}
				</div>
			</div>
		{:else}
			<div class="clear-both"><span class="label">Alert on</span><p class="text-sm"><span class="font-medium">{kindLabels[draft.kind]}</span> <span class="text-muted">· {kindHelp[draft.kind]}</span></p></div>
		{/if}

		{#if draft.kind === 'offline'}
			<PField path="params.minutes" label="Offline for at least (minutes)" id="p-min" hint="Counted from the last heartbeat. After a server restart, agents get this long to reconnect.">
				<Input id="p-min" type="number" min="1" max="10080" class="max-w-40" bind:value={draft.minutes} />
			</PField>
		{:else if draft.kind === 'cpu' || draft.kind === 'memory' || draft.kind === 'disk'}
			<div class="grid gap-3 sm:grid-cols-2">
				<PField path="params.threshold" label="Threshold (%)" id="p-thr"><Input id="p-thr" type="number" min="1" max="100" step="0.5" bind:value={draft.threshold} /></PField>
				<PField path="params.minutes" label="Held for (minutes)" id="p-min"><Input id="p-min" type="number" min="1" max="1440" bind:value={draft.minutes} /></PField>
			</div>
			<p class="hint -mt-2">Opens when every sample in the window is at or above the threshold{draft.kind === 'disk' ? ' (fullest volume)' : ''}. Clears once the last 5 minutes are all below it.</p>
		{:else if draft.kind === 'service'}
			<PField path="params.services" label="Services" id="p-svc" hint="One per line. Unit names (nginx or nginx.service) or Windows service names (Spooler); * matches anything.">
				<Textarea id="p-svc" rows={4} class="font-mono text-[13px]" bind:value={draft.services} placeholder={'nginx\nSpooler\npostgresql*'} />
			</PField>
			<PField path="params.auto_only" name="Watch automatic services" hint="Enabled systemd units, and Windows services with Automatic start.">
				<Switch bind:checked={draft.auto_only}>Also watch every service set to start automatically</Switch>
			</PField>
			<PField path="params.exclude" label="Except" id="p-ex" hint="Never alert on these, one per line.">
				<Textarea id="p-ex" rows={2} class="font-mono text-[13px]" bind:value={draft.exclude} placeholder={'sppsvc\ngupdate'} />
			</PField>
		{:else if draft.kind === 'job_failed'}
			<PField path="params.script_id" label="Script" id="p-script" hint="Ad-hoc scripts count when watching any script. Each script gets its own alert, which clears when it next succeeds.">
				{#if scripts.data}<Combobox id="p-script" bind:value={draft.script_id} items={scriptItems} placeholder="Any script" clearable label="Script" />{:else}<Skeleton class="h-8 w-full" />{/if}
			</PField>
		{:else if draft.kind === 'log'}
			<PField path="params.min_level" label="Least severe level" id="p-level">
				<Select id="p-level" class="max-w-48" bind:value={draft.min_level} options={[{ value: 'critical', label: 'Critical' }, { value: 'error', label: 'Error' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Information' }]} />
			</PField>
			<PField path="params.pattern" label="Message matches (regular expression)" id="p-pat" hint="Case-insensitive. Leave empty to match every message at that level.">
				<Input id="p-pat" class="font-mono text-[13px]" bind:value={draft.pattern} placeholder="out of memory|segfault" />
			</PField>
			<PField path="params.sources" label="Sources" id="p-src" hint="systemd units or syslog identifiers on Linux, event providers on Windows. One per line; empty = any.">
				<Textarea id="p-src" rows={2} class="font-mono text-[13px]" bind:value={draft.sources} placeholder={'sshd\nService Control Manager'} />
			</PField>
			<div class="grid gap-3 sm:grid-cols-2">
				<PField path="params.channels" label="Windows logs" id="p-ch" hint="Default: System, Application."><Input id="p-ch" bind:value={draft.channels} placeholder="System, Application" /></PField>
				<PField path="params.event_ids" label="Windows event IDs" id="p-ids" hint="Comma-separated; empty = any."><Input id="p-ids" inputmode="numeric" bind:value={draft.event_ids} placeholder="41, 6008" /></PField>
			</div>
			<p class="hint -mt-2">Agents send at most 20 matches a minute per policy; the rest are counted on the alert. Matches stay on one open alert until someone resolves it.</p>
		{:else if draft.kind === 'security'}
			<div class="space-y-3">
				<PField path="params.unprotected" name="No antivirus"><Switch bind:checked={draft.unprotected}>No antivirus is switched on</Switch></PField>
				<PField path="params.realtime_off" name="Real-time protection off" hint="ClamAV only scans on access with clamonacc, so most Linux servers would alert; override this off in a Linux set if that's noise.">
					<Switch bind:checked={draft.realtime_off}>Real-time protection is off</Switch>
				</PField>
				<PField path="params.sensor_down" name="Sensor not running" hint="Only where the security policy switches the sensor on; agents it's off for never alert.">
					<Switch bind:checked={draft.sensor_down}>Our sensor isn't running (crashed, keeps restarting or stopped)</Switch>
				</PField>
				<PField path="params.sensor_realtime" name="Our real-time protection" hint="Linux only, where it can block programs before they run. Windows and macOS agents report it as not available there and never alert.">
					<Switch bind:checked={draft.sensor_realtime}>Our real-time protection isn't on where the security policy asks for it</Switch>
				</PField>
				<PField path="params.database_stale" name="Signature database out of date" hint="Older than the limit in the security policy (72 hours unless changed).">
					<Switch bind:checked={draft.database_stale}>Our signature database is out of date</Switch>
				</PField>
				<PField path="params.signature_max_age_hours" name="Signature age">
					<Switch bind:checked={draft.sig_check}>Signatures are out of date</Switch>
					{#if draft.sig_check}
						<div class="mt-2 ml-11.5 flex items-center gap-2">
							<span class="text-muted text-sm">Older than</span>
							<Input id="p-sig" type="number" min="1" max="8760" class="w-24" aria-label="Signature age in hours" bind:value={draft.sig_hours} />
							<span class="text-muted text-sm">hours</span>
						</div>
					{/if}
				</PField>
				<PField path="params.stale_hours" name="Silence" hint="Agents report at least hourly while online, so a long silence means the security check on the machine is stuck or broken.">
					<Switch bind:checked={draft.stale_check}>The agent stops reporting its protection state</Switch>
					{#if draft.stale_check}
						<div class="mt-2 ml-11.5 flex items-center gap-2">
							<span class="text-muted text-sm">Online, but no report for</span>
							<Input id="p-stale" type="number" min="2" max="168" class="w-24" aria-label="Hours without a report" bind:value={draft.stale_hours} />
							<span class="text-muted text-sm">hours</span>
						</div>
					{/if}
				</PField>
			</div>
			<PField path="params.threats" label="Threats" id="p-threats" hint={draft.threats === 'any' ? 'Raises an alert for each new detection, even one the antivirus already quarantined. These stay open until someone resolves them.' : draft.threats === 'active' ? 'One alert per threat the antivirus hasn’t dealt with; it clears once the threat is quarantined or removed.' : undefined}>
				<Select id="p-threats" class="max-w-80" bind:value={draft.threats} options={[{ value: 'active', label: 'Alert on active threats' }, { value: 'any', label: 'Alert on every detection' }, { value: 'off', label: 'Don’t alert on threats' }]} />
			</PField>
			<p class="hint -mt-2">Agents report Microsoft Defender and other Windows Security Center products, ClamAV, XProtect and our own sensor. The <a class="link" href="/security">Security</a> page shows every agent's state.</p>
		{:else if draft.kind === 'net_down' || draft.kind === 'net_interface' || draft.kind === 'net_threshold'}
			{#if draft.kind === 'net_threshold'}
				<PField path="params.metric" label="Measure" id="p-metric">
					<Select
						id="p-metric"
						class="max-w-72"
						value={draft.metric}
						onchange={(e) => {
							draft.metric = e.currentTarget.value as Draft['metric'];
							draft.threshold = draft.metric === 'supply' ? 10 : 90;
						}}
						options={[{ value: 'cpu', label: 'CPU load' }, { value: 'memory', label: 'Memory use' }, { value: 'interface_util', label: 'Port use (of its speed)' }, { value: 'supply', label: 'Toner or ink left' }]}
					/>
				</PField>
			{/if}
			<div class="grid gap-3 sm:grid-cols-2">
				{#if draft.kind === 'net_threshold'}
					<PField path="params.threshold" label={draft.metric === 'supply' ? 'At or below (%)' : 'At or above (%)'} id="p-thr">
						<Input id="p-thr" type="number" min={draft.metric === 'supply' ? 0 : 1} max={draft.metric === 'supply' ? 99 : 100} step="0.5" bind:value={draft.threshold} />
					</PField>
				{/if}
				{#if !(draft.kind === 'net_threshold' && draft.metric === 'supply')}
					<PField path="params.minutes" label={draft.kind === 'net_threshold' ? 'Held for (minutes)' : draft.kind === 'net_down' ? 'No answer for (minutes)' : 'Down for (minutes)'} id="p-min">
						<Input id="p-min" type="number" min="1" max="1440" bind:value={draft.minutes} />
					</PField>
				{/if}
			</div>
			{#if draft.kind === 'net_interface' || (draft.kind === 'net_threshold' && draft.metric === 'interface_util')}
				<PField path="params.names" label="Only ports named" id="p-names" hint="One per line; * matches anything (uplink*, *trunk*). Matches the port's name, description or alias. Empty: every monitored port.">
					<Textarea id="p-names" rows={2} class="font-mono text-[13px]" bind:value={draft.net_names} placeholder={'uplink*\nGi1/0/48'} />
				</PField>
			{/if}
			<PField path="params.kinds" label="Only these kinds of device" id="p-kinds" hint="Comma-separated: switch, router, firewall, printer, ap, ups, nas. Empty: all.">
				<Input id="p-kinds" bind:value={draft.net_kinds} placeholder="switch, firewall" />
			</PField>
			<p class="hint -mt-2">
				{#if draft.kind === 'net_down'}Opens when a monitored device hasn’t answered SNMP for that long. If the site’s designated agent is offline nothing opens: the devices aren’t being read.
				{:else if draft.kind === 'net_interface'}Only ports that are switched on in the device’s configuration and have been seen up count; a port someone turned off isn’t a fault.
				{:else}Evaluated whenever the designated agent reads the device. Add this item to the <em>designated agent’s</em> policy set; scope it with the item’s client and site.{/if}
			</p>
		{:else if draft.kind === 'uptime'}
			<div class="grid gap-3 sm:grid-cols-2">
				<PField path="params.failures" label="Down after (failed checks in a row)" id="p-fail" hint="One failure alone is often a blip.">
					<Input id="p-fail" type="number" min="1" max="20" class="max-w-40" bind:value={draft.up_failures} />
				</PField>
				<PField path="params.kinds" label="Only these kinds of monitor" id="p-ukinds" hint="Comma-separated: ping, tcp, http, tls, dns. Empty: all.">
					<Input id="p-ukinds" bind:value={draft.up_kinds} placeholder="http, tls" />
				</PField>
			</div>
			<PField path="params.cert_days" name="Certificate expiry" hint="TLS monitors, and HTTP monitors of https:// addresses.">
				<Switch bind:checked={draft.up_cert}>A certificate is about to expire</Switch>
				{#if draft.up_cert}
					<div class="mt-2 ml-11.5 flex items-center gap-2">
						<span class="text-muted text-sm">Within</span>
						<Input id="p-cert" type="number" min="1" max="365" class="w-24" aria-label="Days before expiry" bind:value={draft.up_cert_days} />
						<span class="text-muted text-sm">days</span>
					</div>
				{/if}
			</PField>
			<PField path="params.latency_ms" name="Slow answers">
				<Switch bind:checked={draft.up_latency}>Answers are slow</Switch>
				{#if draft.up_latency}
					<div class="mt-2 ml-11.5 flex items-center gap-2">
						<span class="text-muted text-sm">Slower than</span>
						<Input id="p-lat" type="number" min="1" max="120000" class="w-28" aria-label="Latency limit in milliseconds" bind:value={draft.up_latency_ms} />
						<span class="text-muted text-sm">ms, as many checks in a row</span>
					</div>
				{/if}
			</PField>
			<p class="hint -mt-1">Add this item to the policy set of the <em>agents that run the monitors</em> (each monitor’s agent, or its site’s designated agent). A monitor whose agent is offline shows as unknown and doesn’t alert. Monitors are set up on the <a class="link" href="/uptime">Uptime</a> page.</p>
		{:else if draft.kind === 'vulnerability'}
			<PField path="params.min_severity" label="At least" id="p-vsev" hint="Findings this severe or worse count (CVSS, or the distribution’s own rating).">
				<Select id="p-vsev" class="max-w-48" bind:value={draft.vu_severity} options={[{ value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }]} />
			</PField>
			<PField path="params.fix_available_only" name="Fixes"><Switch bind:checked={draft.vu_fix}>Only when a fixed version is available</Switch></PField>
			<PField path="params.kev_only" name="Exploited"><Switch bind:checked={draft.vu_kev}>Only CVEs known to be exploited (CISA KEV)</Switch></PField>
			<PField path="params.older_than_days" label="Open for at least (days)" id="p-vdays" hint="Time to patch the usual way first. 0: at once.">
				<Input id="p-vdays" type="number" min="0" max="365" class="max-w-40" bind:value={draft.vu_days} />
			</PField>
			<PField path="params.min_epss" name="Likely to be exploited">
				<Switch bind:checked={draft.vu_epss_check}>Only with an EPSS score of at least</Switch>
				{#if draft.vu_epss_check}
					<div class="mt-2 ml-11.5 flex items-center gap-2">
						<Input id="p-vepss" type="number" min="0" max="100" class="w-24" aria-label="Minimum EPSS in percent" bind:value={draft.vu_epss} />
						<span class="text-muted text-sm">% chance of exploitation in the next 30 days</span>
					</div>
				{/if}
			</PField>
			<p class="hint -mt-1">One alert per device, listing its worst CVEs; accepted risks don’t count. The <a class="link" href="/vulnerabilities">Vulnerabilities</a> page lists every finding.</p>
		{:else if draft.kind === 'backup'}
			<PField path="params.providers" name="Look for">
				<div class="grid gap-1.5 sm:grid-cols-2">
					{#each backupProviders as p (p.value)}
						<Checkbox checked={draft.bk_providers.includes(p.value)} onchange={(on) => toggleProvider(p.value, on)}>
							{p.label}{#if p.hint}<span class="text-muted block text-xs">{p.hint}</span>{/if}
						</Checkbox>
					{/each}
				</div>
			</PField>
			<PField path="params.sources" name="Repositories and folders" hint="restic and Borg read an env file that is already on the machine (repository, password file or command); no secret comes from here. Backup files: the newest file in a folder.">
				<div class="space-y-2">
					{#each draft.bk_sources as s, i (i)}
						<div class="border-border grid gap-2 rounded-md border p-2 sm:grid-cols-[9rem_1fr_1fr_auto]">
							<Select id={`p-src-${i}`} aria-label="Source type" bind:value={s.provider} options={[{ value: 'restic', label: 'restic' }, { value: 'borg', label: 'Borg' }, { value: 'file_age', label: 'Backup files' }]} />
							{#if s.provider === 'file_age'}
								<Input id={`p-src-path-${i}`} aria-label="Folder" class="font-mono text-[13px]" bind:value={s.path} placeholder="D:\SQLBackups" />
								<Input id={`p-src-glob-${i}`} aria-label="File names" class="font-mono text-[13px]" bind:value={s.glob} placeholder="*.bak" />
							{:else}
								<Input id={`p-src-env-${i}`} aria-label="Env file" class="font-mono text-[13px]" bind:value={s.env_file} placeholder="/etc/restic/env" />
								<Input id={`p-src-repo-${i}`} aria-label="Repository (if not in the env file)" class="font-mono text-[13px]" bind:value={s.repo} placeholder="Repository (optional)" />
							{/if}
							<button type="button" class="btn btn-ghost btn-sm" aria-label="Remove source" onclick={() => (draft.bk_sources = draft.bk_sources.filter((_, j) => j !== i))}>Remove</button>
						</div>
					{/each}
					<button type="button" class="btn btn-sm" onclick={addSource}>Add a source</button>
				</div>
			</PField>
			<div class="grid gap-3 sm:grid-cols-2">
				<PField path="params.max_age_hours" label="No success for (hours)" id="p-bage" hint="26 hours suits a nightly job.">
					<Input id="p-bage" type="number" min="1" max="8760" class="max-w-40" bind:value={draft.bk_max_age} />
				</PField>
				<PField path="params.jobs" label="Jobs" id="p-bjobs" hint="Job names, one per line; * matches anything.">
					<Textarea id="p-bjobs" rows={2} class="font-mono text-[13px]" bind:value={draft.bk_jobs} placeholder="*" />
				</PField>
			</div>
			<PField path="params.warning_is_failure" name="Warnings"><Switch bind:checked={draft.bk_warning}>A job that finished with warnings counts as failed</Switch></PField>
			<PField path="params.require" name="Required" hint="For server sets, where a backup must exist."><Switch bind:checked={draft.bk_require}>Alert when no backup job is found at all</Switch></PField>
			<p class="hint -mt-1">The device reads its backups every hour. The <a class="link" href="/backups">Backups</a> page lists every job.</p>
		{:else if draft.kind === 'disk_encryption'}
			<PField path="params.volumes" label="Volumes" id="p-devol">
				<Segmented label="Volumes" size="md" value={draft.de_volumes} onchange={(v) => (draft.de_volumes = v)} options={[{ value: 'os', label: 'System volume' }, { value: 'all_fixed', label: 'Every fixed volume' }]} />
			</PField>
			<PField path="params.require_escrow" name="Recovery keys" hint="BitLocker only: FileVault and LUKS keys can't be read back to escrow.">
				<Switch bind:checked={draft.de_escrow}>Alert when a BitLocker recovery key isn't in the vault</Switch>
			</PField>
			<PField path="params.grace_hours" label="Suspended for more than (hours)" id="p-degrace" hint="Updates suspend BitLocker for a restart; 0 alerts at once.">
				<Input id="p-degrace" type="number" min="0" max="720" class="max-w-40" bind:value={draft.de_grace} />
			</PField>
			<p class="hint -mt-1">One alert per volume. Encrypting isn't a finding. Escrow itself is set in the set's <em>Disk encryption</em> section.</p>
		{:else if draft.kind === 'local_admin'}
			<PField path="params.overdue_days" label="Overdue after (days)" id="p-laover" hint="Counted from when the rotation was due.">
				<Input id="p-laover" type="number" min="1" max="365" class="max-w-40" bind:value={draft.la_overdue} />
			</PField>
			<p class="hint -mt-1">Also opens when a rotation fails or Windows LAPS manages the same account. Rotation itself is set in the set's <em>Local admin</em> section.</p>
		{:else if draft.kind === 'patch'}
			<div class="space-y-3">
				<PField path="params.failed" name="Failed installs" hint="One alert per agent, listing the updates. It clears once they install, or once someone declines them.">
					<Switch bind:checked={draft.patch_failed}>An update fails to install</Switch>
				</PField>
				<PField path="params.reboot_hours" name="Pending restart">
					<Switch bind:checked={draft.reboot_check}>A restart to finish updates stays pending</Switch>
					{#if draft.reboot_check}
						<div class="mt-2 ml-11.5 flex items-center gap-2">
							<span class="text-muted text-sm">For more than</span>
							<Input id="p-reboot" type="number" min="1" max="8760" class="w-24" aria-label="Hours a restart may stay pending" bind:value={draft.reboot_hours} />
							<span class="text-muted text-sm">hours</span>
						</div>
					{/if}
				</PField>
			</div>
			<p class="hint -mt-1">Missing security updates (over a week old) and restarts pending over a day already count against an agent's health without a policy.</p>
		{/if}

		<PField path="severity" label="Severity" id="p-sev" hint="Open critical alerts make an agent unhealthy; warnings make it need attention.">
			<Segmented label="Severity" size="md" value={draft.severity} onchange={(v) => (draft.severity = v)} options={[{ value: 'critical', label: 'Critical' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Info' }]} />
		</PField>
	</fieldset>

	<div class="space-y-4 self-start">
		<fieldset class="card space-y-3 p-4" {disabled}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">Notify</legend>
			<PField path="channel_ids" name="Channels" class="clear-both">
				<div class="space-y-2">
					{#each channels.data ?? [] as c (c.id)}
						<div>
							<Checkbox checked={draft.channel_ids.includes(c.id)} onchange={(on) => toggleChannel(c.id, on)}>
								{c.name} <span class="text-muted text-xs">{c.kind}{c.enabled ? '' : ', disabled'}</span>
							</Checkbox>
						</div>
					{:else}
						<p class="text-muted text-sm">
							No notification channels yet. {#if can('admin')}<a class="link" href="/settings/notifications">Add one</a> for email, a webhook, Slack or Teams.{:else}An admin can add them under Company settings.{/if}
						</p>
					{/each}
				</div>
			</PField>
			<PField path="notify_resolved" name="Clear notice"><Switch bind:checked={draft.notify_resolved}>Also notify when the alert clears</Switch></PField>
			<PField path="renotify_minutes" name="Reminders" hint="Until someone acknowledges or resolves it. Nothing is sent during a maintenance window.">
				<Switch bind:checked={draft.renotify}>Remind while it stays open</Switch>
				{#if draft.renotify}
					<div class="mt-2 ml-11.5 flex items-center gap-2">
						<span class="text-muted text-sm">Every</span>
						<Select id="p-renotify" class="w-40" aria-label="Reminder interval" bind:value={draft.renotify_minutes} options={[15, 30, 60, 120, 240, 480, 720, 1440, 4320].map((m) => ({ value: m, label: hours(m) }))} />
					</div>
				{/if}
			</PField>
		</fieldset>

		<fieldset class="card space-y-3 p-4" {disabled}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">Tickets and scripts</legend>
			<div class="clear-both grid gap-3 sm:grid-cols-2">
				<PField path="ticket_board_id" label="Open a ticket on" id="p-tboard" hint="One ticket per alert per agent; a repeat adds to it instead of opening another.">
					<Select id="p-tboard" class="w-full" bind:value={draft.ticket_board_id} options={[{ value: null, label: 'Don’t open tickets' }, ...(boards ?? []).map((b) => ({ value: b.id, label: b.name }))]} />
				</PField>
				<PField path="ticket_priority" label="Ticket priority" id="p-tprio">
					<Select id="p-tprio" class="w-full" bind:value={draft.ticket_priority} disabled={!draft.ticket_board_id} options={priorities.map((p) => ({ value: p.value, label: p.label }))} />
				</PField>
			</div>
			<PField path="ticket_auto_resolve" name="Ticket auto-resolve" hint="Only while nobody has worked the ticket, and not once the alert has come back three times (flapping needs a person).">
				<Switch bind:checked={draft.ticket_auto_resolve} disabled={disabled || !draft.ticket_board_id}>Resolve the ticket when the alert clears</Switch>
			</PField>
			<PField path="run_script_id" label="Run a script when it opens" id="p-run" hint="Once per alert, on the agent it's about; not while a maintenance window holds the alert back (it runs when the window ends, if the alert is still open). The job is linked from the alert.">
				{#if scripts.data}<Combobox id="p-run" bind:value={draft.run_script_id} items={scriptItems} placeholder="No script" clearable label="Script to run" />{:else}<Skeleton class="h-8 w-full" />{/if}
			</PField>
		</fieldset>
	</div>
</div>
