<script lang="ts">
	import { goto } from '$app/navigation';
	import { untrack } from 'svelte';
	import { page } from '$app/state';
	import { BellRing, Save, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { cx, datetime } from '#lib/format.js';
	import { kindHelp, kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Channel, LogLevel, Policy, PolicyKind, Script, Severity } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Every field of every kind; only the chosen kind's are sent. Lists are edited as text. */
	type Draft = {
		name: string; kind: PolicyKind; severity: Severity; client_id: string | null; site_id: string | null; os_family: string | null;
		channel_ids: string[]; notify_resolved: boolean; enabled: boolean;
		minutes: number; threshold: number; services: string; auto_only: boolean; exclude: string; script_id: string;
		min_level: LogLevel; channels: string; sources: string; event_ids: string; pattern: string;
	};
	const defaults: Record<PolicyKind, Partial<Draft>> = {
		offline: { minutes: 10 },
		cpu: { threshold: 90, minutes: 15 },
		memory: { threshold: 90, minutes: 15 },
		disk: { threshold: 90, minutes: 5 },
		service: {},
		job_failed: {},
		log: {}
	};
	const blank = (kind: PolicyKind, client: string | null): Draft => ({
		name: '', kind, severity: 'warning', client_id: client, site_id: null, os_family: null, channel_ids: [], notify_resolved: true, enabled: true,
		minutes: 10, threshold: 90, services: '', auto_only: false, exclude: '', script_id: '', min_level: 'error', channels: '', sources: '', event_ids: '', pattern: '',
		...defaults[kind]
	});
	const list = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
	const text = (v: unknown) => (Array.isArray(v) ? v.join('\n') : '');

	function fromPolicy(p: Policy): Draft {
		const q = p.params as Record<string, unknown>;
		return {
			...blank(p.kind, p.client_id),
			name: p.name, severity: p.severity, site_id: p.site_id, os_family: p.os_family, channel_ids: p.channel_ids, notify_resolved: p.notify_resolved, enabled: p.enabled,
			minutes: Number(q.minutes ?? 10), threshold: Number(q.threshold ?? 90), services: text(q.services), auto_only: !!q.auto_only, exclude: text(q.exclude),
			script_id: (q.script_id as string) ?? '', min_level: (q.min_level as LogLevel) ?? 'error', channels: text(q.channels).replaceAll('\n', ', '),
			sources: text(q.sources), event_ids: Array.isArray(q.event_ids) ? q.event_ids.join(', ') : '', pattern: (q.pattern as string) ?? ''
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
		}
	}

	const isNew = $derived(page.params.id === 'new');
	let policy = $state<Policy | null>(null);
	let draft = $state<Draft | null>(null);
	let saved = $state('');
	let error = $state<Error | null>(null);
	let busy = $state(false);

	$effect(() => {
		untrack(() => loadClients());
		const id = page.params.id!;
		error = null;
		if (id === 'new') {
			policy = null;
			const preset = (page.url.searchParams.get('kind') as PolicyKind) || 'offline';
			const client = untrack(() => clientId()) || (can('admin') ? null : (untrack(() => clients.list[0]?.id) ?? null));
			const d = blank(preset in kindLabels ? preset : 'offline', client);
			draft = d;
			saved = JSON.stringify(d);
			return;
		}
		draft = null;
		api.get<Policy>(`/alert-policies/${id}`)
			.then((p) => {
				policy = p;
				const d = fromPolicy(p);
				draft = d;
				saved = JSON.stringify(d);
			})
			.catch((e) => (error = e));
	});

	const channels = resource(() => api.get<Channel[]>('/notification-channels'));
	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived(
		(scripts.data ?? []).filter((s) => !s.client_id || s.client_id === draft?.client_id).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined }))
	);
	const sites = $derived(clients.list.find((c) => c.id === draft?.client_id)?.sites ?? []);
	const editable = $derived(!!draft && (policy ? (policy.client_id ? can('technician') : can('admin')) : can('technician')));
	const dirty = $derived(!!draft && JSON.stringify(draft) !== saved);

	function pickKind(k: PolicyKind) {
		if (!draft) return;
		draft = { ...draft, kind: k, ...defaults[k] };
	}

	async function save(e?: SubmitEvent) {
		e?.preventDefault();
		if (!draft) return;
		const d = draft;
		const body = {
			name: d.name, kind: d.kind, params: params(d), severity: d.severity, client_id: d.client_id, site_id: d.client_id ? d.site_id : null,
			os_family: d.os_family, channel_ids: d.channel_ids, notify_resolved: d.notify_resolved, enabled: d.enabled
		};
		busy = true;
		try {
			if (isNew) {
				const p = await api.post<Policy>('/alert-policies', body);
				saved = JSON.stringify(draft);
				toast.success(`${p.name} created. It applies from now on.`);
				await goto(`/policies/${p.id}`, { replace: true });
			} else {
				policy = await api.put<Policy>(`/alert-policies/${policy!.id}`, body);
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
		const p = policy!;
		const ok = await confirmAction({
			title: `Delete ${p.name}?`,
			message: p.open_alerts ? `Its ${p.open_alerts} open alert${p.open_alerts === 1 ? '' : 's'} will be closed without notifications.` : 'Past alerts are kept.',
			confirmLabel: 'Delete policy',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/alert-policies/${p.id}`), `${p.name} deleted.`))) await goto('/policies');
	}
	function toggleChannel(id: string, on: boolean) {
		if (!draft) return;
		draft.channel_ids = on ? [...draft.channel_ids, id] : draft.channel_ids.filter((c) => c !== id);
	}
</script>

<svelte:head><title>{isNew ? 'New alert policy' : (policy?.name ?? 'Alert policy')}</title></svelte:head>

{#if error}
	<div class="card"><ErrorState {error} onretry={() => goto(page.url.pathname, { refreshAll: true })} /></div>
{:else if !draft}
	<div class="mb-4 space-y-2"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-64" /></div>
	<div class="card space-y-3 p-4"><Skeleton lines={8} /></div>
{:else}
	<PageHeader
		title={isNew ? 'New alert policy' : policy!.name}
		crumbs={[{ label: 'Alert policies', href: '/policies' }, { label: isNew ? 'New' : policy!.name }]}
		menu={!isNew && editable ? [{ label: 'Delete policy…', icon: Trash2, danger: true, onSelect: remove }] : undefined}
	>
		{#snippet meta()}
			{#if dirty}<span class="text-warning text-xs font-medium">Unsaved changes</span>{:else if policy}<span class="text-muted text-xs">Updated {datetime(policy.updated_at)}</span>{/if}
		{/snippet}
		{#snippet actions()}
			{#if policy?.open_alerts}<Button icon={BellRing} href="/alerts?policy={policy.id}">{policy.open_alerts} open</Button>{/if}
			{#if editable}<Button variant="primary" icon={Save} type="submit" form="policy-form" loading={busy} disabled={!dirty || !draft?.name.trim()}>Save</Button>{/if}
		{/snippet}
	</PageHeader>
	{#if !editable}<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm">Read only: {can('technician') ? 'MSP-wide policies can only be changed by admins.' : 'your role can’t change policies.'}</p>{/if}

	<form id="policy-form" class="grid max-w-5xl gap-4 lg:grid-cols-2" onsubmit={save}>
		<fieldset class="card space-y-4 self-start p-4" disabled={!editable}>
			<legend class="sr-only">Rule</legend>
			<Field label="Name" id="p-name" required><Input id="p-name" bind:value={draft.name} required maxlength={200} placeholder="e.g. Servers offline" /></Field>

			{#if isNew}
				<div role="radiogroup" aria-label="Alert on" class="space-y-1.5">
					<span class="label">Alert on</span>
					<div class="grid gap-1.5 sm:grid-cols-2">
						{#each Object.keys(kindLabels) as k (k)}
							{@const on = draft.kind === k}
							<button
								type="button"
								role="radio"
								aria-checked={on}
								class={cx('rounded-md border px-3 py-2 text-left text-sm transition-colors', on ? 'border-accent bg-accent-soft' : 'border-border hover:bg-hover')}
								onclick={() => pickKind(k as PolicyKind)}
							>
								<span class={cx('block font-medium', on && 'text-accent')}>{kindLabels[k as PolicyKind]}</span>
								<span class="text-muted block text-xs">{kindHelp[k as PolicyKind]}</span>
							</button>
						{/each}
					</div>
				</div>
			{:else}
				<div><span class="label">Alert on</span><p class="text-sm"><span class="font-medium">{kindLabels[draft.kind]}</span> <span class="text-muted">· {kindHelp[draft.kind]}</span></p></div>
			{/if}

			{#if draft.kind === 'offline'}
				<Field label="Offline for at least (minutes)" id="p-min" hint="Counted from the last heartbeat. After a server restart, agents get this long to reconnect.">
					<Input id="p-min" type="number" min="1" max="10080" class="max-w-40" bind:value={draft.minutes} />
				</Field>
			{:else if draft.kind === 'cpu' || draft.kind === 'memory' || draft.kind === 'disk'}
				<div class="grid grid-cols-2 gap-3">
					<Field label="Threshold (%)" id="p-thr"><Input id="p-thr" type="number" min="1" max="100" step="0.5" bind:value={draft.threshold} /></Field>
					<Field label="Held for (minutes)" id="p-min"><Input id="p-min" type="number" min="1" max="1440" bind:value={draft.minutes} /></Field>
				</div>
				<p class="hint -mt-2">Opens when every sample in the window is at or above the threshold{draft.kind === 'disk' ? ' (fullest volume)' : ''}. Clears once the last 5 minutes are all below it.</p>
			{:else if draft.kind === 'service'}
				<Field label="Services" id="p-svc" hint="One per line. Unit names (nginx or nginx.service) or Windows service names (Spooler); * matches anything.">
					<Textarea id="p-svc" rows={4} class="font-mono text-[13px]" bind:value={draft.services} placeholder={'nginx\nSpooler\npostgresql*'} />
				</Field>
				<div>
					<Switch bind:checked={draft.auto_only}>Also watch every service set to start automatically</Switch>
					<p class="hint ml-11.5">Enabled systemd units, and Windows services with Automatic start.</p>
				</div>
				<Field label="Except" id="p-ex" hint="Never alert on these, one per line.">
					<Textarea id="p-ex" rows={2} class="font-mono text-[13px]" bind:value={draft.exclude} placeholder={'sppsvc\ngupdate'} />
				</Field>
			{:else if draft.kind === 'job_failed'}
				<Field label="Script" id="p-script" hint="Ad-hoc scripts count when watching any script. Each script gets its own alert, which clears when it next succeeds.">
					{#if scripts.data}<Combobox id="p-script" bind:value={draft.script_id} items={scriptItems} placeholder="Any script" clearable label="Script" />{:else}<Skeleton class="h-8 w-full" />{/if}
				</Field>
			{:else if draft.kind === 'log'}
				<Field label="Least severe level" id="p-level">
					<Select id="p-level" class="max-w-48" bind:value={draft.min_level} options={[{ value: 'critical', label: 'Critical' }, { value: 'error', label: 'Error' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Information' }]} />
				</Field>
				<Field label="Message matches (regular expression)" id="p-pat" hint="Case-insensitive. Leave empty to match every message at that level.">
					<Input id="p-pat" class="font-mono text-[13px]" bind:value={draft.pattern} placeholder="out of memory|segfault" />
				</Field>
				<Field label="Sources" id="p-src" hint="systemd units or syslog identifiers on Linux, event providers on Windows. One per line; empty = any.">
					<Textarea id="p-src" rows={2} class="font-mono text-[13px]" bind:value={draft.sources} placeholder={'sshd\nService Control Manager'} />
				</Field>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Windows logs" id="p-ch" hint="Default: System, Application."><Input id="p-ch" bind:value={draft.channels} placeholder="System, Application" /></Field>
					<Field label="Windows event IDs" id="p-ids" hint="Comma-separated; empty = any."><Input id="p-ids" inputmode="numeric" bind:value={draft.event_ids} placeholder="41, 6008" /></Field>
				</div>
				<p class="hint -mt-2">Agents send at most 20 matches a minute per policy; the rest are counted on the alert. Matches stay on one open alert until someone resolves it.</p>
			{/if}

			<div>
				<span class="label" id="p-sev">Severity</span>
				<Segmented label="Severity" size="md" value={draft.severity} onchange={(v) => (draft!.severity = v)} options={[{ value: 'critical', label: 'Critical' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Info' }]} />
				<p class="hint">Open critical alerts make an agent unhealthy; warnings make it need attention.</p>
			</div>
		</fieldset>

		<div class="space-y-4 self-start">
		<fieldset class="card space-y-4 p-4" disabled={!editable}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">Applies to</legend>
			<Field label="Client" id="p-client" class="clear-both">
				<Select
					id="p-client"
					bind:value={draft.client_id}
					onchange={() => (draft!.site_id = null)}
					options={[...(can('admin') ? [{ value: null, label: 'All clients (MSP-wide)' }] : []), ...clients.list.map((c) => ({ value: c.id, label: c.name }))]}
				/>
			</Field>
			<div class="grid grid-cols-2 gap-3">
				<Field label="Site" id="p-site">
					<Select id="p-site" bind:value={draft.site_id} disabled={!draft.client_id} options={[{ value: null, label: 'Every site' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} />
				</Field>
				<Field label="Operating system" id="p-os">
					<Select id="p-os" bind:value={draft.os_family} options={[{ value: null, label: 'Any' }, { value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }, { value: 'macos', label: 'macOS' }]} />
				</Field>
			</div>
		</fieldset>

		<fieldset class="card space-y-3 p-4" disabled={!editable}>
			<legend class="float-left w-full pb-3 text-sm font-semibold">Notify</legend>
			<div class="clear-both space-y-2">
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
			<Switch bind:checked={draft.notify_resolved}>Also notify when the alert clears</Switch>
			<div class="border-border border-t pt-3">
				<Switch bind:checked={draft.enabled}>Policy enabled</Switch>
				<p class="hint ml-11.5">Disabling closes its open alerts without notifications.</p>
			</div>
		</fieldset>
		</div>
	</form>
{/if}
