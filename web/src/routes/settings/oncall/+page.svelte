<script lang="ts">
	import { CalendarClock, Pencil, PhoneCall, Plus, Trash2, UserPlus, Workflow } from '@lucide/svelte';
	import { api, qs } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { cx, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed, can, session } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Channel, EscalationPolicy, EscalationTarget, OncallLayer, OncallPerson, OncallSchedule, OncallShifts, ShiftSegment } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	const manage = $derived(can('admin') || allowed('oncall.manage'));
	const schedules = resource(() => api.get<OncallSchedule[]>('/oncall/schedules'));
	const policies = resource(() => api.get<EscalationPolicy[]>('/oncall/escalation-policies'));
	const people = resource(() => api.get<OncallPerson[]>('/oncall/people'));
	const channels = resource(() => api.get<Channel[]>('/notification-channels'));
	const settings = resource(() => api.get<{ p1_escalation_policy_id: string | null }>('/oncall/settings'));

	const selectedId = $derived(param('schedule') || schedules.data?.[0]?.id || '');
	const selected = $derived(schedules.data?.find((s) => s.id === selectedId));

	// --- timeline: the next 7 days from the start of today (UTC) --------------------------------
	const DAYS = 7;
	const from = $derived.by(() => {
		const d = new Date();
		d.setUTCHours(0, 0, 0, 0);
		return d;
	});
	const to = $derived(new Date(from.getTime() + DAYS * 86_400_000));
	const shifts = resource(() =>
		selectedId ? api.get<OncallShifts>(`/oncall/schedules/${selectedId}/shifts${qs({ from: from.toISOString(), to: to.toISOString() })}`) : Promise.resolve(null)
	);
	const palette = ['bg-accent-soft text-accent-ink', 'bg-info-soft text-info', 'bg-warning-soft text-warning', 'bg-success-soft text-success', 'bg-danger-soft text-danger'];
	const colourOf = (userId: string) => {
		const ids = [...new Set((shifts.data?.final ?? []).concat(shifts.data?.layers.flatMap((l) => l.segments) ?? []).map((s) => s.user_id))].sort();
		return palette[Math.max(0, ids.indexOf(userId)) % palette.length];
	};
	const pos = (s: ShiftSegment) => {
		const span = to.getTime() - from.getTime();
		const a = Math.max(0, Date.parse(s.start) - from.getTime()) / span;
		const b = Math.min(span, Date.parse(s.end) - from.getTime()) / span;
		return `left:${(a * 100).toFixed(3)}%;width:${((b - a) * 100).toFixed(3)}%`;
	};
	const dayLabels = $derived(Array.from({ length: DAYS }, (_, i) => new Date(from.getTime() + i * 86_400_000).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', timeZone: 'UTC' })));

	// --- schedule editor -------------------------------------------------------------------------
	type LayerForm = { name: string; user_ids: string[]; start: string; shift_hours: number; restricted: boolean; days: number[]; from: string; to: string };
	type ScheduleForm = { id: string | null; name: string; timezone: string; layers: LayerForm[] };
	let editing = $state<ScheduleForm | null>(null);
	let saving = $state(false);
	const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
	const shiftOptions = [
		{ value: 8, label: '8 hours' },
		{ value: 12, label: '12 hours' },
		{ value: 24, label: 'Daily' },
		{ value: 168, label: 'Weekly' },
		{ value: 336, label: 'Every 2 weeks' }
	];
	const hhmm = (m: number) => `${String(Math.floor(m / 60) % 24).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
	const minutes = (t: string) => {
		const [h, m] = t.split(':').map(Number);
		return h * 60 + (m || 0);
	};
	const localInput = (iso: string) => iso.slice(0, 16);
	function layerForm(l?: OncallLayer): LayerForm {
		const w = l?.restrict[0];
		return {
			name: l?.name ?? '',
			user_ids: l?.user_ids ?? [],
			start: localInput(l?.start_at ?? new Date(from.getTime() + 9 * 3_600_000).toISOString()),
			shift_hours: l?.shift_hours ?? 168,
			restricted: !!w,
			days: w?.days ?? [0, 1, 2, 3, 4],
			from: hhmm(w?.start ?? 540),
			to: hhmm(w?.end ?? 1020)
		};
	}
	function edit(s?: OncallSchedule) {
		editing = s
			? { id: s.id, name: s.name, timezone: s.timezone, layers: s.layers.map(layerForm) }
			: { id: null, name: '', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', layers: [layerForm()] };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const f = editing!;
		const body = {
			name: f.name,
			timezone: f.timezone,
			layers: f.layers.map((l) => ({
				name: l.name,
				user_ids: l.user_ids,
				start_at: new Date(`${l.start}:00Z`).toISOString(),
				shift_hours: Number(l.shift_hours),
				restrict: l.restricted ? [{ days: l.days, start: minutes(l.from), end: minutes(l.to) }] : []
			}))
		};
		saving = true;
		try {
			const saved = f.id ? await api.put<OncallSchedule>(`/oncall/schedules/${f.id}`, body) : await api.post<OncallSchedule>('/oncall/schedules', body);
			toast.success(`${saved.name} saved.`);
			editing = null;
			schedules.reload();
			shifts.reload();
			setParams({ schedule: saved.id });
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function removeSchedule(s: OncallSchedule) {
		if (!(await confirmAction({ title: `Delete ${s.name}?`, message: 'Its layers and overrides go too.', confirmLabel: 'Delete schedule', danger: true }))) return;
		if (await attempt(() => api.del(`/oncall/schedules/${s.id}`), `${s.name} deleted.`)) {
			setParams({ schedule: null });
			schedules.reload();
		}
	}

	// --- overrides -------------------------------------------------------------------------------
	let override = $state<{ user_id: string; starts: string; ends: string } | null>(null);
	function addOverride() {
		const now = new Date();
		override = { user_id: session.user!.id, starts: localInput(now.toISOString()), ends: localInput(new Date(now.getTime() + 8 * 3_600_000).toISOString()) };
	}
	async function saveOverride(e: SubmitEvent) {
		e.preventDefault();
		const o = override!;
		const body = { schedule_id: selectedId, user_id: o.user_id, starts_at: new Date(`${o.starts}:00Z`).toISOString(), ends_at: new Date(`${o.ends}:00Z`).toISOString() };
		if (await attempt(() => api.post('/oncall/overrides', body), 'Override added.')) {
			override = null;
			schedules.reload();
			shifts.reload();
		}
	}
	async function removeOverride(id: string) {
		if (await attempt(() => api.del(`/oncall/overrides/${id}`), 'Override removed.')) {
			schedules.reload();
			shifts.reload();
		}
	}

	// --- escalation policies ----------------------------------------------------------------------
	type StepForm = { delay_minutes: number; targets: string[] };
	let policy = $state<{ id: string | null; name: string; repeat: number; steps: StepForm[] } | null>(null);
	const targetKey = (t: EscalationTarget) => ('schedule' in t ? `schedule:${t.schedule}` : 'user' in t ? `user:${t.user}` : `channel:${t.channel}`);
	const targetOf = (k: string): EscalationTarget => {
		const [kind, id] = k.split(':');
		return kind === 'schedule' ? { schedule: id } : kind === 'user' ? { user: id } : { channel: id };
	};
	const targetOptions = $derived([
		...(schedules.data ?? []).map((s) => ({ value: `schedule:${s.id}`, label: `On call: ${s.name}` })),
		...(people.data ?? []).map((p) => ({ value: `user:${p.id}`, label: p.name })),
		...(channels.data ?? []).filter((c) => c.kind !== 'oncall').map((c) => ({ value: `channel:${c.id}`, label: `Channel: ${c.name}` }))
	]);
	const targetLabel = (t: EscalationTarget) => targetOptions.find((o) => o.value === targetKey(t))?.label ?? 'Deleted';
	function editPolicy(p?: EscalationPolicy) {
		policy = p
			? { id: p.id, name: p.name, repeat: p.repeat, steps: p.steps.map((s) => ({ delay_minutes: s.delay_minutes, targets: s.targets.map(targetKey) })) }
			: { id: null, name: '', repeat: 0, steps: [{ delay_minutes: 15, targets: targetOptions[0] ? [targetOptions[0].value] : [] }] };
	}
	async function savePolicy(e: SubmitEvent) {
		e.preventDefault();
		const p = policy!;
		const body = { name: p.name, repeat: Number(p.repeat), steps: p.steps.map((s) => ({ delay_minutes: Number(s.delay_minutes), targets: s.targets.filter(Boolean).map(targetOf) })) };
		saving = true;
		try {
			if (p.id) await api.put(`/oncall/escalation-policies/${p.id}`, body);
			else await api.post('/oncall/escalation-policies', body);
			toast.success(`${p.name} saved.`);
			policy = null;
			policies.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function removePolicy(p: EscalationPolicy) {
		if (!(await confirmAction({ title: `Delete ${p.name}?`, message: 'Pages already open through it stop escalating.', confirmLabel: 'Delete policy', danger: true }))) return;
		if (await attempt(() => api.del(`/oncall/escalation-policies/${p.id}`), `${p.name} deleted.`)) policies.reload();
	}
	async function setP1(v: string) {
		if (await attempt(() => api.put('/oncall/settings', { p1_escalation_policy_id: v || null }), v ? 'New P1 tickets will page.' : 'P1 tickets no longer page.')) settings.reload();
	}
</script>

<div class="max-w-6xl space-y-5">
	<section class="card" aria-labelledby="sch-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="sch-h" class="font-semibold">On-call schedules</h2>
				<p class="text-muted text-xs">Rotations in layers: where layers overlap, the lower one in the list wins; overrides win over every layer.</p>
			</div>
			<div class="flex flex-wrap gap-2">
				{#if selected}<Button icon={UserPlus} onclick={addOverride}>{manage ? 'Add override' : 'Put me on call'}</Button>{/if}
				{#if manage}<Button variant="primary" icon={Plus} onclick={() => edit()}>Add schedule</Button>{/if}
			</div>
		</header>
		<Async res={schedules} compact>
			{#snippet children(list)}
				{#if list.length}
					<div class="border-border flex flex-wrap gap-2 border-b px-5 py-3" role="tablist" aria-label="Schedules">
						{#each list as s (s.id)}
							<button
								role="tab"
								aria-selected={s.id === selectedId}
								class={cx('rounded-full border px-3 py-1 text-sm', s.id === selectedId ? 'border-accent bg-accent-soft text-accent-ink font-medium' : 'border-border hover:bg-hover')}
								onclick={() => setParams({ schedule: s.id })}
							>
								{s.name} <span class="text-muted text-xs">· {s.now.user_name ?? 'nobody'}</span>
							</button>
						{/each}
					</div>
					{#if selected}
						<div class="space-y-4 px-5 py-4">
							<div class="flex flex-wrap items-center gap-2 text-sm">
								<PhoneCall class="text-accent size-4" aria-hidden="true" />
								<span>On call now: <span class="font-semibold">{selected.now.user_name ?? 'nobody'}</span>{#if selected.now.until}{' '}<span class="text-muted">until {datetime(selected.now.until)}</span>{/if}</span>
								{#if selected.now.source === 'override'}<Badge tone="info">Override</Badge>{/if}
								<span class="text-muted ml-auto text-xs">Times in {selected.timezone}</span>
								{#if manage}
									<IconButton icon={Pencil} size="sm" label="Edit {selected.name}" onclick={() => edit(selected)} />
									<IconButton icon={Trash2} size="sm" label="Delete {selected.name}" onclick={() => removeSchedule(selected!)} />
								{/if}
							</div>
							<Async res={shifts} compact>
								{#snippet children(sh)}
									{#if sh}
										<div class="overflow-x-auto">
											<div class="min-w-[44rem] text-xs">
												<div class="text-muted ml-32 grid" style="grid-template-columns: repeat({DAYS}, 1fr)">
													{#each dayLabels as d (d)}<div class="border-border border-l px-1 pb-1">{d}</div>{/each}
												</div>
												{#snippet row(label: string, segs: ShiftSegment[], strong = false)}
													<div class="flex items-center gap-2 py-1">
														<div class={cx('w-30 shrink-0 truncate', strong ? 'font-semibold' : 'text-muted')} title={label}>{label}</div>
														<div class="bg-sunken relative h-7 flex-1 rounded">
															{#each segs as s (s.start)}
																<div class={cx('absolute inset-y-0.5 overflow-hidden rounded px-1.5 leading-6 whitespace-nowrap', colourOf(s.user_id))} style={pos(s)} title="{s.user_name}: {datetime(s.start)} – {datetime(s.end)}">
																	{s.user_name}
																</div>
															{/each}
														</div>
													</div>
												{/snippet}
												{#each sh.layers as l, i (l.id)}{@render row(l.name || `Layer ${i + 1}`, l.segments)}{/each}
												{@render row('Overrides', sh.overrides)}
												{@render row('On call', sh.final, true)}
											</div>
										</div>
									{/if}
								{/snippet}
							</Async>
							{#if selected.overrides.length}
								<div>
									<h3 class="label">Overrides</h3>
									<ul class="divide-border divide-y text-sm">
										{#each selected.overrides as o (o.id)}
											<li class="flex items-center gap-3 py-1.5">
												<span class="font-medium">{o.user_name}</span>
												<span class="text-muted">{datetime(o.starts_at)} – {datetime(o.ends_at)}</span>
												{#if manage || o.user_id === session.user?.id}<IconButton icon={Trash2} size="sm" class="ml-auto" label="Remove override for {o.user_name}" onclick={() => removeOverride(o.id)} />{/if}
											</li>
										{/each}
									</ul>
								</div>
							{/if}
						</div>
					{/if}
				{:else}
					<EmptyState compact icon={CalendarClock} title="No schedules yet" description="A schedule says who is on call when. Escalation policies page whoever is on." />
				{/if}
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-labelledby="ep-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="ep-h" class="font-semibold">Escalation policies</h2>
				<p class="text-muted text-xs">Who is paged, in what order, and how long each step waits for an acknowledgement. An on-call notification channel pages through one.</p>
			</div>
			{#if manage}<Button variant="primary" icon={Plus} onclick={() => editPolicy()}>Add policy</Button>{/if}
		</header>
		<Async res={policies} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as p (p.id)}
							<li class="flex flex-wrap items-start gap-3 px-5 py-3 text-sm">
								<Workflow class="text-muted mt-0.5 size-4 shrink-0" aria-hidden="true" />
								<div class="min-w-0 flex-1">
									<div class="font-medium">{p.name}</div>
									<ol class="text-muted mt-1 space-y-0.5 text-xs">
										{#each p.steps as s, i (i)}
											<li>{i + 1}. {s.targets.map(targetLabel).join(', ')} <span>· then wait {s.delay_minutes} min</span></li>
										{/each}
									</ol>
									<div class="text-muted mt-1 text-xs">{p.repeat ? `Repeats ${p.repeat}×` : 'No repeats'} · {p.channels.length ? `Used by ${p.channels.map((c) => c.name).join(', ')}` : 'No on-call channel uses it'}</div>
								</div>
								{#if manage}
									<IconButton icon={Pencil} size="sm" label="Edit {p.name}" onclick={() => editPolicy(p)} />
									<IconButton icon={Trash2} size="sm" label="Delete {p.name}" onclick={() => removePolicy(p)} />
								{/if}
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Workflow} title="No escalation policies" description="Add one, then a notification channel of type On-call that uses it." />
				{/if}
			{/snippet}
		</Async>
		{#if manage && settings.data && policies.data?.length}
			<div class="border-border flex flex-wrap items-center gap-3 border-t px-5 py-3 text-sm">
				<label for="p1-policy">Page new P1 tickets through</label>
				<Select
					id="p1-policy"
					class="w-64"
					value={settings.data.p1_escalation_policy_id ?? ''}
					onchange={(e) => setP1((e.currentTarget as HTMLSelectElement).value)}
					options={[{ value: '', label: 'Nothing (don’t page)' }, ...policies.data.map((p) => ({ value: p.id, label: p.name }))]}
				/>
			</div>
		{/if}
	</section>
</div>

{#if editing}
	<Modal title={editing.id ? `Edit ${editing.name}` : 'Add schedule'} size="lg" onclose={() => (editing = null)}>
		<form id="schedule-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="s-name" required><Input id="s-name" bind:value={editing.name} required maxlength={100} placeholder="e.g. Out of hours" /></Field>
				<Field label="Time zone" id="s-tz" hint="Handovers and restrictions use it."><Input id="s-tz" bind:value={editing.timezone} required /></Field>
			</div>
			{#each editing.layers as l, i (i)}
				<fieldset class="border-border space-y-3 rounded-lg border p-3">
					<legend class="px-1 text-sm font-medium">Layer {i + 1}</legend>
					<div class="grid gap-3 sm:grid-cols-3">
						<Field label="Name" id="l-name-{i}"><Input id="l-name-{i}" bind:value={l.name} placeholder="Primary" /></Field>
						<Field label="Starts (UTC)" id="l-start-{i}"><Input id="l-start-{i}" type="datetime-local" bind:value={l.start} required /></Field>
						<Field label="Shift" id="l-shift-{i}"><Select id="l-shift-{i}" bind:value={l.shift_hours} options={shiftOptions} /></Field>
					</div>
					<div>
						<div class="label">People, in rotation order</div>
						<div class="grid gap-1 sm:grid-cols-2">
							{#each people.data ?? [] as p (p.id)}
								<Checkbox checked={l.user_ids.includes(p.id)} onchange={(c) => (l.user_ids = c ? [...l.user_ids, p.id] : l.user_ids.filter((x) => x !== p.id))}>{p.name}</Checkbox>
							{/each}
						</div>
					</div>
					<Checkbox bind:checked={l.restricted}>Only at certain times</Checkbox>
					{#if l.restricted}
						<div class="flex flex-wrap items-end gap-3">
							<div class="flex flex-wrap gap-2" role="group" aria-label="Days">
								{#each weekdays as d, di (d)}
									<Checkbox checked={l.days.includes(di)} onchange={(c) => (l.days = c ? [...l.days, di].sort() : l.days.filter((x) => x !== di))}>{d}</Checkbox>
								{/each}
							</div>
							<Field label="From" id="l-from-{i}"><Input id="l-from-{i}" type="time" bind:value={l.from} /></Field>
							<Field label="To" id="l-to-{i}" hint="Earlier than From runs overnight."><Input id="l-to-{i}" type="time" bind:value={l.to} /></Field>
						</div>
					{/if}
					{#if editing.layers.length > 1}
						<Button size="sm" variant="ghost" icon={Trash2} onclick={() => editing!.layers.splice(i, 1)}>Remove layer</Button>
					{/if}
				</fieldset>
			{/each}
			<Button size="sm" icon={Plus} onclick={() => editing!.layers.push(layerForm())}>Add layer</Button>
		</form>
		{#snippet footer()}
			<Button onclick={() => (editing = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="schedule-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if override}
	<Modal title="Override {selected?.name}" onclose={() => (override = null)}>
		<form id="override-form" class="space-y-3" onsubmit={saveOverride}>
			{#if manage}
				<Field label="Who" id="o-user"><Select id="o-user" bind:value={override.user_id} options={(people.data ?? []).map((p) => ({ value: p.id, label: p.name }))} /></Field>
			{:else}
				<p class="text-sm">You will be on call for this schedule, instead of the rotation.</p>
			{/if}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="From (UTC)" id="o-from"><Input id="o-from" type="datetime-local" bind:value={override.starts} required /></Field>
				<Field label="Until (UTC)" id="o-to"><Input id="o-to" type="datetime-local" bind:value={override.ends} required /></Field>
			</div>
		</form>
		{#snippet footer()}
			<Button onclick={() => (override = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="override-form">Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if policy}
	<Modal title={policy.id ? `Edit ${policy.name}` : 'Add escalation policy'} size="lg" onclose={() => (policy = null)}>
		<form id="policy-form" class="space-y-4" onsubmit={savePolicy}>
			<div class="grid gap-3 sm:grid-cols-[1fr_10rem]">
				<Field label="Name" id="p-name" required><Input id="p-name" bind:value={policy.name} required maxlength={100} placeholder="e.g. Servers, out of hours" /></Field>
				<Field label="Repeat" id="p-repeat" hint="Times round after the last step."><Input id="p-repeat" type="number" min="0" max="9" bind:value={policy.repeat} /></Field>
			</div>
			{#each policy.steps as s, i (i)}
				<fieldset class="border-border space-y-3 rounded-lg border p-3">
					<legend class="px-1 text-sm font-medium">Step {i + 1}</legend>
					{#each s.targets as _, ti (ti)}
						<div class="flex items-end gap-2">
							<Field label={ti ? 'And' : 'Page'} id="t-{i}-{ti}" class="flex-1"><Select id="t-{i}-{ti}" bind:value={s.targets[ti]} options={targetOptions} /></Field>
							{#if s.targets.length > 1}<IconButton icon={Trash2} size="sm" label="Remove target" onclick={() => s.targets.splice(ti, 1)} />{/if}
						</div>
					{/each}
					<div class="flex flex-wrap items-end gap-3">
						<Button size="sm" icon={Plus} onclick={() => s.targets.push(targetOptions[0]?.value ?? '')}>Add target</Button>
						<Field label="Escalate after (minutes)" id="d-{i}" class="w-48"><Input id="d-{i}" type="number" min="1" max="1440" bind:value={s.delay_minutes} /></Field>
						{#if policy.steps.length > 1}<Button size="sm" variant="ghost" icon={Trash2} onclick={() => policy!.steps.splice(i, 1)}>Remove step</Button>{/if}
					</div>
				</fieldset>
			{/each}
			<Button size="sm" icon={Plus} onclick={() => policy!.steps.push({ delay_minutes: 15, targets: [targetOptions[0]?.value ?? ''] })}>Add step</Button>
		</form>
		{#snippet footer()}
			<Button onclick={() => (policy = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="policy-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
