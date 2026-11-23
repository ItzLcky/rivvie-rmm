<script lang="ts">
	import { untrack, type Component } from 'svelte';
	import { BellRing, History, Play, RotateCcw, Save, Trash2, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { cx, datetime, plural } from '#lib/format.js';
	import { kindLabels } from '#lib/monitoring/labels.js';
	import { provideFields, type FieldState } from '#lib/policy/fields.svelte.js';
	import { changedFields, fieldLabel, inOverride, leaves, moduleLabels, moduleNoun, overlaps, overriddenFields, setHref, setPath, singleModules, sourceOf, unsetPath, sectionOf } from '#lib/policy/policy.js';
	import type { Config, ItemView, Module, SetDetail } from '#lib/policy/types.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { PolicyKind, Script } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu, { type MenuItem } from '#lib/ui/Menu.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import AgentForm, { normalize as agentNorm } from './AgentForm.svelte';
	import AlertForm, { blankAlert, normalize as alertNorm } from './AlertForm.svelte';
	import AutomationForm, { blankAutomation, normalize as automationNorm } from './AutomationForm.svelte';
	import AutomationRuns from './AutomationRuns.svelte';
	import PatchForm, { normalize as patchNorm } from './PatchForm.svelte';
	import PField from './PField.svelte';
	import PolicyStatus from './PolicyStatus.svelte';
	import RemoteAccessForm, { normalize as remoteNorm } from './RemoteAccessForm.svelte';
	import ScheduleForm, { blankSchedule, normalize as scheduleNorm } from './ScheduleForm.svelte';
	import SecurityForm, { normalize as securityNorm } from './SecurityForm.svelte';
	import SoftwareForm, { blankSoftware, normalize as softwareNorm } from './SoftwareForm.svelte';

	/**
	 * One policy as it applies in one set. Where it's defined, edits change the policy itself;
	 * in a set below, each edited field becomes part of this set's override (only that field),
	 * and every field says where its value comes from and can go back to inherited.
	 */
	let {
		set,
		view,
		module,
		kind = 'offline',
		oncreated,
		onsaved,
		ondeleted
	}: {
		set: SetDetail;
		/** null: a new alert or schedule in this set. */
		view: ItemView | null;
		module: Module;
		/** A new alert's starting type. */
		kind?: PolicyKind;
		oncreated?: (v: ItemView) => void;
		onsaved?: (v: ItemView) => void;
		ondeleted?: () => void;
	} = $props();

	type FormProps = { config: Config; onchange: (c: Config, valid: boolean) => void; disabled?: boolean };
	const norms: Record<Module, (c: Config) => Config> = {
		alert: alertNorm,
		schedule: scheduleNorm,
		automation: automationNorm,
		patch: patchNorm,
		security: securityNorm,
		remote_access: remoteNorm,
		agent: agentNorm,
		software: softwareNorm
	};
	const singleForms: Partial<Record<Module, Component<FormProps>>> = { patch: PatchForm, security: SecurityForm, remote_access: RemoteAccessForm, agent: AgentForm };
	// svelte-ignore state_referenced_locally
	const norm = norms[module];
	// svelte-ignore state_referenced_locally
	const Form = singleForms[module];
	// svelte-ignore state_referenced_locally
	const single = singleModules.includes(module);

	let current = $state<ItemView | null>(untrack(() => view));
	const isNew = untrack(() => !view);
	const below = $derived(!!current && current.status !== 'defined');
	const mayCreate = $derived(set.client_id ? can('technician') : can('technician') && (can('admin') || clients.list.length > 0));
	const canEdit = $derived(!current ? mayCreate : below ? current.overridable : current.editable);

	$effect(() => {
		untrack(() => loadClients());
	});

	// What the form mounts with, and what it reports back.
	const initial = untrack(() => (view ? norm(view.config) : module === 'alert' ? blankAlert(kind) : module === 'software' ? blankSoftware() : module === 'automation' ? blankAutomation() : blankSchedule()));
	let formConfig = $state<Config>(initial);
	let formKey = $state(0);
	let edited = $state<Config>(initial);
	let valid = $state(true);
	const base = $derived(current ? norm(current.config) : initial);

	// The item itself (where it's defined): name, on/off, limit.
	let name = $state(untrack(() => view?.name ?? ''));
	let enabled = $state(untrack(() => view?.item_enabled ?? true));
	let limitClient = $state<string | null>(untrack(() => view?.limit.client_id ?? set.client_id ?? null));
	let limitSite = $state<string | null>(untrack(() => view?.limit.site_id ?? null));
	$effect(() => {
		// A technician can't make MSP-wide policies: start with their first client.
		if (isNew && !limitClient && !can('admin') && clients.list.length) untrack(() => (limitClient = clients.list[0].id));
	});
	// This set's on/off override (null: as inherited).
	let enabledOv = $state<boolean | null>(untrack(() => view?.override?.enabled ?? null));

	const savedOv = $derived<Config>(current?.override?.config ?? {});
	const savedEnabled = $derived(current?.override?.enabled ?? null);
	const changed = $derived(below ? changedFields(base, edited) : new Map<string, unknown>());
	const pendingOv = $derived([...changed].reduce((o, [k, v]) => setPath(o, k, v), savedOv));
	const dirty = $derived(
		!current
			? true
			: below
				? changed.size > 0 || enabledOv !== savedEnabled
				: JSON.stringify(edited) !== JSON.stringify(base) ||
					(!single && (name !== current.name || enabled !== current.item_enabled || limitClient !== current.limit.client_id || limitSite !== current.limit.site_id))
	);
	let busy = $state(false);

	function rebase(rest: Map<string, unknown>) {
		let c = current ? norm(current.config) : initial;
		for (const [k, v] of rest) c = setPath(c, k, v);
		formConfig = c;
		edited = c;
		formKey++;
	}
	function fresh(v: ItemView) {
		current = v;
		name = v.name;
		enabled = v.item_enabled;
		limitClient = v.limit.client_id;
		limitSite = v.limit.site_id;
		enabledOv = v.override?.enabled ?? null;
	}
	const overridePath = $derived(current ? `/policy-items/${current.id}/overrides/${set.id}` : '');

	provideFields({
		state(path): FieldState {
			if (!below || !current) return { kind: 'defined' };
			if (path === 'enabled') {
				if (enabledOv !== savedEnabled) return { kind: 'overridden', saved: false };
				if (savedEnabled != null) return { kind: 'overridden', saved: true };
			} else {
				if ([...changed.keys()].some((k) => overlaps(k, path))) return { kind: 'overridden', saved: false };
				if (inOverride(savedOv, path)) return { kind: 'overridden', saved: true };
			}
			return { kind: 'inherited', from: set.chain.find((c) => c.id === sourceOf(current!.sources, path)) };
		},
		reset,
		get canReset() {
			return below && canEdit;
		}
	});

	async function reset(path: string) {
		if (!current) return;
		if (path === 'enabled') {
			if (savedEnabled == null) return void (enabledOv = null);
			await attempt(async () => {
				fresh(await api.put<ItemView>(overridePath, { enabled: null, config: savedOv }));
				onsaved?.(current!);
			}, `${current.name}: on/off follows ${current.origin_set_name} again.`);
			return;
		}
		const rest = new Map([...changed].filter(([k]) => !overlaps(k, path)));
		if (inOverride(savedOv, path)) {
			let cfg = savedOv;
			for (const k of leaves(savedOv).keys()) if (overlaps(k, path)) cfg = unsetPath(cfg, k);
			const ok = await attempt(async () => {
				const keep = current!.override?.enabled ?? null;
				fresh(await api.put<ItemView>(overridePath, { enabled: keep, config: cfg }));
				onsaved?.(current!);
			}, `${fieldLabel(path)} is inherited again.`);
			if (!ok) return;
		}
		rebase(rest);
	}

	async function resetAll() {
		if (!current) return;
		const ok = await confirmAction({
			title: `Reset ${current.name} in ${set.name}?`,
			message: `Every field follows ${current.origin_set_name} again: ${overriddenFields(current.override).join(', ')}.`,
			confirmLabel: 'Reset all'
		});
		if (!ok) return;
		await attempt(async () => {
			fresh(await api.del<ItemView>(overridePath));
			rebase(new Map());
			onsaved?.(current!);
		}, `${current.name} follows ${current.origin_set_name} again.`);
	}

	function discard() {
		if (current) fresh(current);
		rebase(new Map());
	}

	async function save(e?: SubmitEvent) {
		e?.preventDefault();
		busy = true;
		try {
			if (!current) {
				const v = await api.post<ItemView>(`/policy-sets/${set.id}/items`, { module, name: name.trim(), enabled, config: edited, client_id: limitClient, site_id: limitClient ? limitSite : null });
				toast.success(`${v.name} created. It applies from now on.`);
				oncreated?.(v);
				return;
			}
			let v: ItemView;
			if (below) v = await api.put<ItemView>(overridePath, { enabled: enabledOv, config: pendingOv });
			else if (single) v = await api.put<ItemView>(`/policy-items/${current.id}`, { config: edited });
			else v = await api.put<ItemView>(`/policy-items/${current.id}`, { name: name.trim(), enabled, config: edited, client_id: limitClient, site_id: limitClient ? limitSite : null });
			fresh(v);
			rebase(new Map());
			toast.success(below ? `Saved for ${set.name}${v.override ? `: ${overriddenFields(v.override).join(', ')} overridden` : ''}.` : 'Saved. Devices pick it up within a minute.');
			onsaved?.(v);
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}

	async function remove() {
		const v = current!;
		const ok = await confirmAction({
			title: `Delete ${v.name}?`,
			message: v.open_alerts ? `Its ${plural(v.open_alerts, 'open alert')} will be closed without notifications.` : module === 'schedule' ? 'Past runs stay in Jobs.' : module === 'automation' ? 'Its run history goes with it; the jobs it started stay in Jobs.' : 'Past alerts are kept.',
			confirmLabel: `Delete ${moduleNoun[module]}`,
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/policy-items/${v.id}`), `${v.name} deleted.`))) ondeleted?.();
	}
	async function include(agent: { id: string; hostname: string }) {
		await attempt(async () => {
			fresh(await api.del<ItemView>(`/policy-items/${current!.id}/exclusions/${agent.id}`));
		}, `${current!.name} covers ${agent.hostname} again.`);
	}
	async function runNow() {
		await attempt(async () => {
			const r = await api.post<{ sent: number; queued: number; skipped: number }>(`/schedules/${current!.id}/run`);
			toast.success(`Sent to ${r.sent}, queued for ${r.queued} offline${r.skipped ? `, skipped ${r.skipped} still busy with the last run` : ''}.`, { href: { label: 'View runs', href: `/schedules/${current!.id}` } });
		});
	}
	function onscript(s: Script) {
		if (!name.trim()) name = s.name;
	}
	function onpackage(n: string) {
		if (!name.trim()) name = n;
	}

	const client = $derived(clients.list.find((c) => c.id === limitClient));
	const title = $derived(current ? (single ? moduleLabels[module] : current.name) : `New ${moduleNoun[module]}`);
	const menu = $derived<MenuItem[]>([
		...(current && below && current.override && canEdit ? [{ label: 'Reset all to inherited', icon: RotateCcw, onSelect: resetAll }] : []),
		...(current && !below && !single && current.editable ? [{ label: `Delete ${moduleNoun[module]}…`, icon: Trash2, danger: true, onSelect: remove }] : [])
	]);
	const why = $derived(
		!canEdit
			? module === 'security' && !allowed('security.manage')
				? 'Read only: changing the security policy needs the security.manage permission.'
				: can('technician')
					? below
						? `Read only: only admins can change MSP-wide sets.`
						: 'Read only: MSP-wide policies can only be changed by admins.'
					: 'Read only: your role can’t change policies.'
			: ''
	);
</script>

<form class="space-y-4" onsubmit={save} aria-label={title}>
	<header class="flex flex-wrap items-start justify-between gap-3">
		<div class="min-w-0 space-y-1">
			<div class="flex flex-wrap items-center gap-2">
				<h2 class="font-display text-lg font-semibold">{title}</h2>
				{#if current}<PolicyStatus view={current} />{/if}
				{#if current && !current.enabled}<span class="text-muted text-xs font-medium">Off{below ? ' in this set' : ''}</span>{/if}
			</div>
			<p class="text-muted max-w-3xl text-sm">
				{#if !current}
					It applies in {set.name} and every set below it.
				{:else if !below}
					{single ? 'Applies to every device. Any set below can change single fields; the rest keep following this one.' : `Applies in ${set.name} and every set below it.`}
					{#if module === 'alert' && current.open_alerts}<a class="link ml-1" href="/alerts?policy={current.id}">{plural(current.open_alerts, 'open alert')}</a>{/if}
				{:else if current.status === 'overridden'}
					Defined in <a class="link" href={setHref(current.origin_set_id, sectionOf[module])}>{current.origin_set_name}</a>. This set changes {overriddenFields(current.override).join(', ')}; every other field follows {current.origin_set_name}.
				{:else}
					Defined in <a class="link" href={setHref(current.origin_set_id, sectionOf[module])}>{current.origin_set_name}</a>. Change a field to override it for {set.name} and the sets below; the rest keeps following {current.origin_set_name}.
				{/if}
			</p>
		</div>
		<div class="flex items-center gap-2">
			{#if module === 'schedule' && current}
				<Button icon={History} href="/schedules/{current.id}">Runs</Button>
				{#if current.editable}<Button icon={Play} onclick={runNow} disabled={dirty} title={dirty ? 'Save first' : undefined}>Run now</Button>{/if}
			{/if}
			{#if module === 'alert' && current?.open_alerts && below}<Button icon={BellRing} href="/alerts?policy={current.id}">{current.open_alerts} open</Button>{/if}
			{#if menu.length}<Menu items={menu} label="More actions for {title}" />{/if}
		</div>
	</header>

	{#if why}<p class="border-border bg-sunken text-muted rounded-md border px-3 py-2 text-sm">{why}</p>{/if}

	{#if !single}
		{#if !below}
			<fieldset class="card space-y-4 p-4" disabled={!canEdit}>
				<legend class="float-left w-full pb-3 text-sm font-semibold">{module === 'alert' ? 'Policy' : module === 'software' ? 'Requirement' : module === 'automation' ? 'Automation' : 'Scheduled script'}</legend>
				<div class="clear-both grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
					<Field label="Name" id="it-name" required>
						<Input id="it-name" bind:value={name} required maxlength={200} placeholder={module === 'alert' ? 'e.g. Servers offline' : module === 'software' ? 'e.g. Firefox on workstations' : module === 'automation' ? 'e.g. Install the monitoring add-on' : 'e.g. Nightly temp cleanup'} />
					</Field>
					<div class="md:pt-7"><Switch bind:checked={enabled} disabled={!canEdit}>Enabled</Switch></div>
				</div>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Limit to client" id="it-client" hint={set.client_id ? `Policies in ${set.name} are always limited to ${set.client_name}.` : 'Only devices of this client, of the devices using this set.'}>
						<Select
							id="it-client"
							class="w-full"
							bind:value={limitClient}
							disabled={!canEdit || !!set.client_id}
							onchange={() => (limitSite = null)}
							options={[...(can('admin') && !set.client_id ? [{ value: null, label: 'Every client' }] : []), ...clients.list.filter((c) => !set.client_id || c.id === set.client_id).map((c) => ({ value: c.id, label: c.name }))]}
						/>
					</Field>
					<Field label="Site" id="it-site">
						<Select id="it-site" class="w-full" bind:value={limitSite} disabled={!canEdit || !limitClient} options={[{ value: null, label: 'Every site' }, ...(client?.sites ?? []).map((s) => ({ value: s.id, label: s.name }))]} />
					</Field>
				</div>
				{#if current}
					<div class="border-border border-t pt-3">
						<span class="label">Except these devices</span>
						{#if current.limit.excluded.length}
							<ul class="mt-1 flex flex-wrap gap-1.5">
								{#each current.limit.excluded as x (x.id)}
									<li class="border-border bg-sunken inline-flex items-center gap-1 rounded-md border py-0.5 pr-1 pl-2 text-sm">
										<a class="hover:text-accent" href="/agents/{x.id}?tab=policy">{x.hostname}</a>
										{#if canEdit}<button type="button" class="text-muted hover:text-fg hover:bg-hover inline-flex size-6 items-center justify-center rounded" aria-label="Cover {x.hostname} again" onclick={() => include(x)}><X class="size-3.5" /></button>{/if}
									</li>
								{/each}
							</ul>
						{:else}
							<p class="text-muted text-sm">None. To leave one device out, open its Policy section.</p>
						{/if}
					</div>
				{/if}
				{#if module === 'schedule' && current?.schedule}
					<p class="text-muted text-xs">Next run {current.schedule.next_run_at ? datetime(current.schedule.next_run_at) : 'not planned (disabled everywhere, or the timetable doesn’t parse)'} · last run {current.schedule.last_run_at ? datetime(current.schedule.last_run_at) : 'never'}</p>
				{/if}
			</fieldset>
		{:else}
			<div class="card space-y-3 p-4">
				<PField path="enabled" name="On/off" hint={current?.limit.client_id ? `Limited to ${current.limit.client_name}${current.limit.site_name ? ` › ${current.limit.site_name}` : ''}, as set where it's defined.` : undefined}>
					<Switch checked={enabledOv ?? current!.enabled} disabled={!canEdit} onchange={(v) => (enabledOv = v)}>{module === 'alert' ? 'Alert' : module === 'software' ? 'Require it' : 'Run'} on devices using {set.name}</Switch>
				</PField>
				{#if module === 'alert'}<p class="text-muted text-xs">{kindLabels[(current!.config.kind as PolicyKind) ?? 'offline']}: the type can't be changed below where it's defined.</p>{/if}
			</div>
		{/if}
	{/if}

	{#key formKey}
		{#if module === 'alert'}
			<AlertForm config={formConfig} onchange={(c, ok) => ((edited = c), (valid = ok))} disabled={!canEdit} pickKind={!current} clientId={current?.limit.client_id ?? limitClient} />
		{:else if module === 'software'}
			<SoftwareForm config={formConfig} onchange={(c, ok) => ((edited = c), (valid = ok))} disabled={!canEdit} {below} clientId={current?.limit.client_id ?? limitClient} {onpackage} />
		{:else if module === 'schedule'}
			<ScheduleForm config={formConfig} onchange={(c, ok) => ((edited = c), (valid = ok))} disabled={!canEdit} {below} clientId={current?.limit.client_id ?? limitClient} {onscript} />
		{:else if module === 'automation'}
			<AutomationForm config={formConfig} onchange={(c, ok) => ((edited = c), (valid = ok))} disabled={!canEdit} {below} clientId={current?.limit.client_id ?? limitClient} {onscript} />
		{:else if Form}
			<Form config={formConfig} onchange={(c, ok) => ((edited = c), (valid = ok))} disabled={!canEdit} />
		{/if}
	{/key}

	{#if module === 'automation' && current}<AutomationRuns view={current} canReset={current.editable} />{/if}

	{#if canEdit && dirty}
		<!-- Unsaved edits stay in view while scrolling; a new policy just ends with its button. -->
		<div class={cx('border-border bg-raised flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-2.5', current && 'shadow-pop sticky bottom-3 z-10')} role="status">
			<p class="text-sm">
				{#if !current}
					New {moduleNoun[module]}, not saved yet.
				{:else if below}
					<span class="font-medium">Unsaved:</span> {[...(enabledOv !== savedEnabled ? ['On/off'] : []), ...[...changed.keys()].map((k) => fieldLabel(k.startsWith('window') ? 'window' : k))].join(', ')} will be overridden in {set.name}.
				{:else}
					<span class="font-medium">Unsaved changes.</span> {single ? 'They apply to every device that doesn’t override them.' : ''}
				{/if}
			</p>
			<div class="flex gap-2">
				{#if current}<Button variant="ghost" onclick={discard}>Discard</Button>{/if}
				<Button variant="primary" icon={Save} type="submit" loading={busy} disabled={!valid || (!single && !below && !name.trim()) || ((module === 'schedule' || module === 'automation') && !edited.script_id) || (module === 'software' && !edited.package_id)}>{current ? 'Save' : `Create ${moduleNoun[module]}`}</Button>
			</div>
		</div>
	{/if}
</form>
