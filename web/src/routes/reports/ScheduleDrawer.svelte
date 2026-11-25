<script lang="ts" module>
	import type { ScheduleRange, ScheduledReport } from '#lib/work/types.js';

	export const reportLabels: Record<ScheduledReport, string> = {
		service_desk: 'Service desk',
		utilisation: 'Utilisation',
		profitability: 'Profitability',
		qbr: 'Business review'
	};
	export const rangeLabels: Record<ScheduleRange, string> = {
		last_week: 'Last week (Monday–Sunday)',
		last_month: 'Last month',
		last_quarter: 'Last quarter',
		last_30_days: 'The 30 days before'
	};
	/** Timetables with a range that suits them. */
	export const timetables: { value: string; label: string; cron: string; range: ScheduleRange }[] = [
		{ value: 'weekly', label: 'Weekly, Mondays 07:00', cron: '0 7 * * 1', range: 'last_week' },
		{ value: 'monthly', label: 'Monthly, the 1st at 07:00', cron: '0 7 1 * *', range: 'last_month' },
		{ value: 'quarterly', label: 'Quarterly, 1 Jan/Apr/Jul/Oct at 07:00', cron: '0 7 1 1,4,7,10 *', range: 'last_quarter' }
	];
	export function timetableLabel(cron: string): string {
		return timetables.find((t) => t.cron === cron)?.label ?? cron;
	}
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { Download, Send, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { bytes, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { allowed, can, session } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Contact, Technician } from '#lib/types.js';
	import type { ReportRun, ReportSchedule } from '#lib/work/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Create or edit a report schedule, with its history. */
	let {
		schedule = null,
		report = 'service_desk',
		clientId = '',
		onclose,
		onsaved
	}: {
		/** The one being edited; `null` for a new one. */
		schedule?: ReportSchedule | null;
		/** For a new one: the report tab it was started from. */
		report?: ScheduledReport;
		clientId?: string;
		onclose: () => void;
		onsaved: () => void;
	} = $props();

	const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
	const s = untrack(() => schedule);
	const start = untrack(() => s?.report ?? report);
	let d = $state({
		name: s?.name ?? '',
		report: start,
		client: s?.client_id ?? (start === 'utilisation' || start === 'profitability' ? '' : untrack(() => clientId)),
		cron: s?.cron ?? (start === 'qbr' ? timetables[2].cron : timetables[1].cron),
		range: (s?.params.range ?? (start === 'qbr' ? 'last_quarter' : 'last_month')) as ScheduleRange,
		timezone: s?.timezone ?? localTz,
		users: new Set(s?.user_ids ?? (s ? [] : [session.user?.id ?? ''].filter(Boolean))),
		contacts: new Set(s?.contact_ids ?? []),
		extra: (s?.extra_emails ?? []).join('\n'),
		subject: s?.subject ?? '',
		message: s?.message ?? '',
		enabled: s?.enabled ?? true
	});
	let saving = $state(false);
	let error = $state('');

	$effect(() => {
		loadClients();
	});
	let technicians = $state<Technician[]>([]);
	$effect(() => {
		ticketMeta().then((m) => (technicians = m.technicians), () => {});
	});
	const perClient = $derived(d.report === 'qbr' || d.report === 'service_desk');
	const contacts = resource(() => (perClient && d.client ? api.get<Contact[]>(`/contacts?client_id=${d.client}`) : Promise.resolve([] as Contact[])));
	const runs = resource(() => (s ? api.get<ReportRun[]>(`/report-schedules/${s.id}/runs`) : Promise.resolve([] as ReportRun[])));

	const reportOptions = $derived(
		(Object.keys(reportLabels) as ScheduledReport[])
			.filter((r) => (r === 'profitability' ? allowed('billing.read') : r === 'utilisation' ? allowed('billing.read') || allowed('time.approve') : true))
			.map((r) => ({ value: r, label: reportLabels[r] }))
	);
	const timetable = $derived(timetables.find((t) => t.cron === d.cron)?.value ?? 'custom');
	const zones = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return [localTz];
		}
	})();
	const zoneItems = ['UTC', ...zones.filter((z) => z !== 'UTC')].map((z) => ({ value: z, label: z }));
	const extraList = $derived(d.extra.split(/[\s,;]+/).map((e) => e.trim()).filter(Boolean));
	const recipients = $derived(d.users.size + (perClient ? d.contacts.size : 0) + extraList.length);
	const valid = $derived(!!d.name.trim() && !!d.cron.trim() && recipients > 0 && (d.report !== 'qbr' || !!d.client));

	function pickTimetable(v: string) {
		const t = timetables.find((x) => x.value === v);
		if (t) {
			d.cron = t.cron;
			d.range = t.range;
		}
	}
	function toggle(set: Set<string>, id: string, on: boolean): Set<string> {
		const n = new Set(set);
		if (on) n.add(id);
		else n.delete(id);
		return n;
	}

	async function save() {
		saving = true;
		error = '';
		const body = {
			name: d.name.trim(),
			report: d.report,
			client_id: d.report === 'utilisation' || d.report === 'profitability' || !d.client ? null : d.client,
			params: { range: d.range },
			cron: d.cron.trim(),
			timezone: d.timezone,
			user_ids: [...d.users],
			contact_ids: perClient ? [...d.contacts] : [],
			extra_emails: extraList,
			subject: d.subject,
			message: d.message,
			enabled: d.enabled
		};
		try {
			if (s) await api.put(`/report-schedules/${s.id}`, body);
			else await api.post('/report-schedules', body);
			toast.success(s ? 'Schedule saved.' : 'Report scheduled.');
			onsaved();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			saving = false;
		}
	}
	let sending = $state(false);
	async function sendNow() {
		if (!s) return;
		sending = true;
		try {
			const r = await api.post<ReportRun>(`/report-schedules/${s.id}/run`);
			if (r.status === 'sent') toast.success(`Sent to ${r.recipients.filter((x) => x.status === 'queued').length} recipient(s).`);
			else toast.error(r.error ?? 'The report wasn’t sent.');
			runs.reload();
			onsaved();
		} catch (e) {
			toast.error(e);
		} finally {
			sending = false;
		}
	}
	async function remove() {
		if (!s) return;
		const ok = await confirmAction({ title: `Delete “${s.name}”?`, message: 'Its history and stored PDFs are deleted too.', confirmLabel: 'Delete schedule', danger: true });
		if (ok && (await attempt(() => api.del(`/report-schedules/${s.id}`), 'Schedule deleted.'))) onsaved();
	}
	const runTone = (st: ReportRun['status']) => (st === 'sent' ? 'success' : st === 'failed' ? 'danger' : 'neutral');
</script>

<Drawer open title={s ? 'Report schedule' : 'Schedule a report'} side="right" width="w-[40rem]" {onclose}>
	<form class="space-y-4 px-4 pb-6" aria-label="Report schedule" onsubmit={(e) => (e.preventDefault(), save())}>
		<h2 class="text-base font-semibold">{s ? s.name : 'Schedule a report'}</h2>
		<Field label="Name" id="rs-name">
			<Input id="rs-name" bind:value={d.name} placeholder="e.g. Monthly review for Contoso" />
		</Field>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Report" id="rs-report">
				<Select id="rs-report" class="w-full" bind:value={d.report} options={reportOptions} />
			</Field>
			{#if perClient}
				<Field label="Client" id="rs-client" hint={d.report === 'service_desk' ? 'Empty: every client you can see.' : undefined}>
					<Combobox id="rs-client" bind:value={d.client} clearable={d.report === 'service_desk'} items={clients.list.map((c) => ({ value: c.id, label: c.name }))} placeholder={d.report === 'qbr' ? 'Choose a client…' : 'Every client'} />
				</Field>
			{/if}
		</div>

		<fieldset class="space-y-3">
			<legend class="label">When</legend>
			<Select id="rs-when" aria-label="Timetable" class="w-full" value={timetable} onchange={(e) => pickTimetable(e.currentTarget.value)} options={[...timetables.map((t) => ({ value: t.value, label: t.label })), { value: 'custom', label: 'Custom cron…' }]} />
			<div class="grid gap-3 sm:grid-cols-2">
				{#if timetable === 'custom'}
					<Field label="Cron expression" id="rs-cron" hint="minute hour day-of-month month day-of-week">
						<Input id="rs-cron" class="font-mono" bind:value={d.cron} />
					</Field>
				{/if}
				<Field label="Time zone" id="rs-tz"><Combobox id="rs-tz" bind:value={d.timezone} items={zoneItems} label="Time zone" /></Field>
				<Field label="Covers" id="rs-range">
					<Select id="rs-range" class="w-full" bind:value={d.range} options={(Object.keys(rangeLabels) as ScheduleRange[]).map((r) => ({ value: r, label: rangeLabels[r] }))} />
				</Field>
			</div>
		</fieldset>

		<fieldset class="space-y-2">
			<legend class="label">Send to</legend>
			<p class="hint">Each person gets their own email with the PDF. Users must be able to open the report themselves.</p>
			<div class="border-border max-h-40 space-y-1.5 overflow-y-auto rounded-md border p-2" role="group" aria-label="Users">
				{#each technicians as t (t.id)}
					<div><Checkbox checked={d.users.has(t.id)} onchange={(on) => (d.users = toggle(d.users, t.id, on))}>{t.name} <span class="text-muted text-xs">{t.email}</span></Checkbox></div>
				{:else}
					<p class="text-muted text-xs">Loading users…</p>
				{/each}
			</div>
			{#if perClient && d.client}
				<div class="border-border max-h-40 space-y-1.5 overflow-y-auto rounded-md border p-2" role="group" aria-label="Client contacts">
					{#each (contacts.data ?? []).filter((c) => c.email) as c (c.id)}
						<div><Checkbox checked={d.contacts.has(c.id)} onchange={(on) => (d.contacts = toggle(d.contacts, c.id, on))}>{c.name} <span class="text-muted text-xs">{c.email}</span></Checkbox></div>
					{:else}
						<p class="text-muted text-xs">This client has no contacts with an email address.</p>
					{/each}
				</div>
			{:else if !perClient}
				<p class="hint">{reportLabels[d.report]} reports never go to client contacts.</p>
			{/if}
			{#if can('admin')}
				<Field label="Other addresses" id="rs-extra" hint="One per line. Admins only.">
					<Textarea id="rs-extra" rows={2} bind:value={d.extra} />
				</Field>
			{/if}
		</fieldset>

		<Field label="Subject" id="rs-subject" hint="Empty: the report’s name and period.">
			<Input id="rs-subject" bind:value={d.subject} />
		</Field>
		<Field label="Message" id="rs-message">
			<Textarea id="rs-message" rows={3} bind:value={d.message} />
		</Field>
		<Switch bind:checked={d.enabled}>Send on the timetable</Switch>

		{#if error}<p class="text-danger text-sm" role="alert">{error}</p>{/if}
		<div class="flex flex-wrap gap-2">
			<Button type="submit" variant="primary" loading={saving} disabled={!valid}>{s ? 'Save' : 'Schedule'}</Button>
			{#if s}
				<Button icon={Send} loading={sending} onclick={sendNow}>Send now</Button>
				<Button icon={Trash2} variant="ghost" class="ml-auto" onclick={remove}>Delete</Button>
			{/if}
		</div>
	</form>

	{#if s}
		<section class="border-border border-t px-4 py-4" aria-labelledby="rs-history">
			<h3 id="rs-history" class="mb-2 text-sm font-semibold">History</h3>
			{#if !runs.data?.length}
				<EmptyState compact title="Not sent yet" description="Runs appear here, with the PDF each one sent." />
			{:else}
				<ul class="space-y-2">
					{#each runs.data as r (r.id)}
						<li class="flex flex-wrap items-start gap-2 text-sm">
							<Badge tone={runTone(r.status)}>{r.status}</Badge>
							<div class="min-w-0 flex-1">
								<div>{datetime(r.started_at)} <span class="text-muted text-xs">{r.trigger === 'manual' ? `· sent by ${r.started_by_name ?? 'a user'}` : '· on schedule'}</span></div>
								{#if r.from_date}<div class="text-muted text-xs">{r.from_date} – {r.to_date} · {r.recipients.filter((x) => x.status === 'queued').length} recipient(s)</div>{/if}
								{#if r.error}<div class="text-danger text-xs">{r.error}</div>{/if}
								{#each r.recipients.filter((x) => x.status === 'skipped') as x (x.kind + (x.id ?? x.email))}
									<div class="text-warning text-xs">Skipped {x.email || x.kind}: {x.reason}</div>
								{/each}
							</div>
							{#if r.stored}<a class="hover:text-accent text-xs inline-flex items-center gap-1" href="/api/report-runs/{r.id}/download" target="_blank" rel="noopener"><Download class="size-3.5" />PDF{r.bytes ? ` (${bytes(r.bytes)})` : ''}</a>{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/if}
</Drawer>
