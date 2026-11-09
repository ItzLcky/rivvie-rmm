<script lang="ts">
	import { goto } from '$app/navigation';
	import { untrack } from 'svelte';
	import { page } from '$app/state';
	import { Play, Save, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, ms } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { describeCron } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Job, Page, Schedule, Script } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';

	type Draft = {
		name: string; script_id: string; client_id: string | null; site_id: string | null; os_family: string | null; cron: string; timezone: string;
		args: string; timeout_secs: string; retain_days: number; enabled: boolean;
	};
	const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
	const presets = [
		{ label: 'Hourly', cron: '0 * * * *' },
		{ label: 'Daily 02:00', cron: '0 2 * * *' },
		{ label: 'Weekdays 07:00', cron: '0 7 * * 1-5' },
		{ label: 'Sundays 03:00', cron: '0 3 * * 0' },
		{ label: 'Monthly, 1st', cron: '0 4 1 * *' }
	];

	const isNew = $derived(page.params.id === 'new');
	let schedule = $state<Schedule | null>(null);
	let draft = $state<Draft | null>(null);
	let saved = $state('');
	let error = $state<Error | null>(null);
	let busy = $state(false);

	function fromSchedule(s: Schedule): Draft {
		return {
			name: s.name, script_id: s.script_id, client_id: s.client_id, site_id: s.site_id, os_family: s.os_family, cron: s.cron, timezone: s.timezone,
			args: s.args.join('\n'), timeout_secs: s.timeout_secs?.toString() ?? '', retain_days: s.retain_days, enabled: s.enabled
		};
	}

	$effect(() => {
		untrack(() => loadClients());
		const id = page.params.id!;
		error = null;
		if (id === 'new') {
			schedule = null;
			const client = untrack(() => clientId()) || (can('admin') ? null : (untrack(() => clients.list[0]?.id) ?? null));
			const d: Draft = { name: '', script_id: '', client_id: client, site_id: null, os_family: null, cron: '0 2 * * *', timezone: localTz, args: '', timeout_secs: '', retain_days: 30, enabled: true };
			draft = d;
			saved = JSON.stringify(d);
			return;
		}
		draft = null;
		api.get<Schedule>(`/schedules/${id}`)
			.then((s) => {
				schedule = s;
				const d = fromSchedule(s);
				draft = d;
				saved = JSON.stringify(d);
			})
			.catch((e) => (error = e));
	});

	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived(
		(scripts.data ?? []).filter((s) => !s.client_id || s.client_id === draft?.client_id).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined }))
	);
	const script = $derived(scripts.data?.find((s) => s.id === draft?.script_id));
	const sites = $derived(clients.list.find((c) => c.id === draft?.client_id)?.sites ?? []);
	const zones = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return [localTz];
		}
	})();
	const zoneItems = ['UTC', ...zones.filter((z) => z !== 'UTC')].map((z) => ({ value: z, label: z }));
	const editable = $derived(!!draft && (schedule ? (schedule.client_id ? can('technician') : can('admin')) : can('technician')));
	const dirty = $derived(!!draft && JSON.stringify(draft) !== saved);

	// Next runs, previewed by the server (the same parser the scheduler uses).
	let preview = $state<{ runs: string[]; error?: string } | null>(null);
	$effect(() => {
		const c = draft?.cron ?? '';
		const tz = draft?.timezone ?? 'UTC';
		if (!c.trim()) return void (preview = null);
		const t = setTimeout(() => {
			api.get<{ runs: string[]; error?: string }>(`/schedules/preview${qs({ cron: c, timezone: tz })}`).then((p) => (preview = p), () => {});
		}, 300);
		return () => clearTimeout(t);
	});

	// A script for one OS: suggest that OS filter so the others don't run it and fail.
	function onScript(id: string) {
		const s = scripts.data?.find((x) => x.id === id);
		if (!draft || !s) return;
		if (!draft.name.trim()) draft.name = s.name;
		const os = { powershell: 'windows', cmd: 'windows', bash: 'linux', sh: 'linux', python: null }[s.interpreter];
		if (os && !draft.os_family) draft.os_family = os;
	}

	async function save(e?: SubmitEvent) {
		e?.preventDefault();
		if (!draft) return;
		const d = draft;
		const body = {
			name: d.name, script_id: d.script_id, client_id: d.client_id, site_id: d.client_id ? d.site_id : null, os_family: d.os_family, cron: d.cron,
			timezone: d.timezone, args: d.args.split('\n').map((a) => a.trim()).filter(Boolean), timeout_secs: d.timeout_secs.trim() ? Number(d.timeout_secs) : null,
			retain_days: Number(d.retain_days), enabled: d.enabled
		};
		busy = true;
		try {
			if (isNew) {
				const s = await api.post<Schedule>('/schedules', body);
				saved = JSON.stringify(draft);
				toast.success(`${s.name} saved. Next run ${datetime(s.next_run_at)}.`);
				await goto(`/schedules/${s.id}`, { replace: true });
			} else {
				schedule = await api.put<Schedule>(`/schedules/${schedule!.id}`, body);
				saved = JSON.stringify(draft);
				toast.success('Saved.');
			}
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	async function remove() {
		const s = schedule!;
		const ok = await confirmAction({ title: `Delete ${s.name}?`, message: 'Past runs stay in Jobs, and are no longer deleted by this schedule’s retention.', confirmLabel: 'Delete schedule', danger: true });
		if (ok && (await attempt(() => api.del(`/schedules/${s.id}`), `${s.name} deleted.`))) await goto('/schedules');
	}
	async function runNow() {
		const s = schedule!;
		await attempt(async () => {
			const r = await api.post<{ sent: number; queued: number; skipped: number }>(`/schedules/${s.id}/run`);
			toast.success(`Sent to ${r.sent}, queued for ${r.queued} offline${r.skipped ? `, skipped ${r.skipped} still busy with the last run` : ''}.`);
			runs.reload();
		});
	}

	const runs = resource(() => (schedule ? api.get<Page<Job>>(`/jobs?schedule_id=${schedule.id}&limit=100`) : Promise.resolve(null)));
	liveReload(() => schedule && runs.reload(), (e) => e.type === 'job' && !e.output, { debounceMs: 1500 });
</script>

<svelte:head><title>{isNew ? 'New schedule' : (schedule?.name ?? 'Schedule')}</title></svelte:head>

{#if error}
	<div class="card"><ErrorState {error} onretry={() => goto(page.url.pathname, { refreshAll: true })} /></div>
{:else if !draft}
	<div class="mb-4 space-y-2"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-64" /></div>
	<div class="card space-y-3 p-4"><Skeleton lines={8} /></div>
{:else}
	<PageHeader
		title={isNew ? 'New schedule' : schedule!.name}
		crumbs={[{ label: 'Schedules', href: '/schedules' }, { label: isNew ? 'New' : schedule!.name }]}
		menu={!isNew && editable ? [{ label: 'Delete schedule…', icon: Trash2, danger: true, onSelect: remove }] : undefined}
	>
		{#snippet meta()}
			{#if dirty}<span class="text-warning text-xs font-medium">Unsaved changes</span>{:else if schedule?.next_run_at && schedule.enabled}<span class="text-muted text-xs">Next run {datetime(schedule.next_run_at)}</span>{/if}
		{/snippet}
		{#snippet actions()}
			{#if schedule && editable}<Button icon={Play} onclick={runNow} disabled={dirty} title={dirty ? 'Save first' : undefined}>Run now</Button>{/if}
			{#if editable}<Button variant="primary" icon={Save} type="submit" form="schedule-form" loading={busy} disabled={!dirty || !draft?.name.trim() || !draft?.script_id}>Save</Button>{/if}
		{/snippet}
	</PageHeader>
	{#if !editable}<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm">Read only: {can('technician') ? 'MSP-wide schedules can only be changed by admins.' : 'your role can’t change schedules.'}</p>{/if}

	<form id="schedule-form" class="grid max-w-5xl gap-4 lg:grid-cols-2" onsubmit={save}>
		<fieldset class="card space-y-4 self-start p-4" disabled={!editable}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">What</legend>
			<Field label="Script" id="sc-script" class="clear-both" required>
				<!-- Mounted once the scripts are in: the input shows the selected label from its first render. -->
				{#if scripts.data}<Combobox id="sc-script" bind:value={draft.script_id} items={scriptItems} placeholder="Pick a saved script" label="Script" onchange={onScript} />{:else}<Skeleton class="h-8 w-full" />{/if}
			</Field>
			<Field label="Name" id="sc-name" required><Input id="sc-name" bind:value={draft.name} required maxlength={200} placeholder="e.g. Nightly temp cleanup" /></Field>
			<Field label="Arguments" id="sc-args" hint="One per line, passed to the script in order.">
				<Textarea id="sc-args" rows={2} class="font-mono text-[13px]" bind:value={draft.args} />
			</Field>
			<div class="grid grid-cols-2 gap-3">
				<Field label="Timeout (s)" id="sc-timeout"><Input id="sc-timeout" inputmode="numeric" bind:value={draft.timeout_secs} placeholder={script ? `${script.timeout_secs} (script)` : 'Script default'} /></Field>
				<Field label="Keep runs (days)" id="sc-keep"><Input id="sc-keep" type="number" min="1" max="3650" bind:value={draft.retain_days} /></Field>
			</div>
			<p class="hint -mt-2">Each run's output is deleted after this many days.</p>
		</fieldset>

		<fieldset class="card space-y-4 self-start p-4" disabled={!editable}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">When</legend>
			<div class="clear-both flex flex-wrap gap-1.5">
				{#each presets as p (p.cron)}<Button size="sm" variant={draft.cron === p.cron ? 'primary' : 'secondary'} onclick={() => (draft!.cron = p.cron)}>{p.label}</Button>{/each}
			</div>
			<div class="grid gap-3 sm:grid-cols-[1fr_14rem]">
				<Field label="Cron expression" id="sc-cron" hint="minute hour day-of-month month day-of-week" error={preview?.error}>
					<Input id="sc-cron" class="font-mono" bind:value={draft.cron} invalid={!!preview?.error} />
				</Field>
				<Field label="Time zone" id="sc-tz"><Combobox id="sc-tz" bind:value={draft.timezone} items={zoneItems} label="Time zone" /></Field>
			</div>
			{#if preview && !preview.error}
				<div class="text-sm">
					<p class="font-medium">{describeCron(draft.cron)}</p>
					<ul class="text-muted mt-1 space-y-0.5 text-xs tabular">{#each preview.runs as r (r)}<li>{datetime(r)}</li>{/each}</ul>
				</div>
			{/if}
			<div class="border-border border-t pt-3">
				<Switch bind:checked={draft.enabled}>Enabled</Switch>
				<p class="hint ml-11.5">A run that comes due while the server is down runs once when it's back.</p>
			</div>
		</fieldset>

		<fieldset class="card space-y-4 self-start p-4 lg:col-span-2" disabled={!editable}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">Runs on</legend>
			<div class="clear-both grid gap-3 sm:grid-cols-3">
				<Field label="Client" id="sc-client">
					<Select
						id="sc-client"
						bind:value={draft.client_id}
						onchange={() => ((draft!.site_id = null), script?.client_id && script.client_id !== draft!.client_id && (draft!.script_id = ''))}
						options={[...(can('admin') ? [{ value: null, label: 'All clients (MSP-wide)' }] : []), ...clients.list.map((c) => ({ value: c.id, label: c.name }))]}
					/>
				</Field>
				<Field label="Site" id="sc-site"><Select id="sc-site" bind:value={draft.site_id} disabled={!draft.client_id} options={[{ value: null, label: 'Every site' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} /></Field>
				<Field label="Operating system" id="sc-os">
					<Select id="sc-os" bind:value={draft.os_family} options={[{ value: null, label: 'Any' }, { value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }, { value: 'macos', label: 'macOS' }]} />
				</Field>
			</div>
			<p class="hint">Every agent that matches when the schedule fires gets a job. Offline agents run it when they reconnect, unless the last run is still waiting for them.</p>
		</fieldset>
	</form>

	{#if schedule}
		{#snippet whenCell(j: Job)}<a class="hover:text-accent whitespace-nowrap" href="/jobs/{j.id}" title={datetime(j.created_at)}>{ago(j.created_at)}</a>{/snippet}
		{#snippet agentCell(j: Job)}<a class="hover:text-accent font-medium" href="/agents/{j.agent_id}">{j.hostname}</a>{/snippet}
		{#snippet statusCell(j: Job)}<JobBadge status={j.status} />{/snippet}
		{#snippet durCell(j: Job)}{#if j.duration_ms != null}{ms(j.duration_ms)}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
		<h2 class="mt-6 mb-2 text-sm font-semibold">Recent runs</h2>
		<DataTable
			id="schedule-runs"
			caption="Recent runs"
			rows={runs.data?.items ?? []}
			key={(j) => j.id}
			loading={runs.loading}
			rowHref={(j) => `/jobs/${j.id}`}
			scroll={false}
			columns={[
				{ id: 'created', label: 'Started', cell: whenCell, hideable: false },
				{ id: 'agent', label: 'Agent', cell: agentCell },
				{ id: 'status', label: 'Status', cell: statusCell },
				{ id: 'duration', label: 'Duration', cell: durCell, align: 'right', from: 'sm' }
			] satisfies Column<Job>[]}
		>
			{#snippet empty()}<EmptyState compact title="No runs yet" description={schedule?.enabled && schedule.next_run_at ? `The first run is ${datetime(schedule.next_run_at)}.` : undefined} />{/snippet}
			{#snippet footer()}{#if runs.data?.next}<p class="text-muted px-3 py-2 text-xs">Showing the latest 100. <a class="link" href="/jobs?q={encodeURIComponent(schedule?.script_name ?? '')}">See all in Jobs</a></p>{/if}{/snippet}
		</DataTable>
	{/if}
{/if}
