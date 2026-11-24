<script lang="ts">
	import { BellRing, Hash, Mail, MessageSquare, Pencil, PhoneCall, Plus, Send, Siren, Smartphone, Trash2, Webhook } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Channel, ChannelKind, DeliveryRow, EscalationPolicy, Smtp, SmsSettings } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	const kinds: Record<ChannelKind, { label: string; icon: typeof Mail; hint: string }> = {
		email: { label: 'Email', icon: Mail, hint: 'Sent through the mail server below.' },
		webhook: { label: 'Webhook', icon: Webhook, hint: 'POSTs the alert as JSON. With a secret, X-RMM-Signature carries sha256=HMAC of the body.' },
		slack: { label: 'Slack', icon: Hash, hint: 'A Slack incoming webhook URL (hooks.slack.com/services/…).' },
		teams: { label: 'Microsoft Teams', icon: MessageSquare, hint: 'A Teams Workflows webhook URL (“When a Teams webhook request is received”). Messages are Adaptive Cards.' },
		sms: { label: 'Text message', icon: Smartphone, hint: 'Texts each number through the SMS provider below. Messages are at most 300 characters.' },
		pagerduty: { label: 'PagerDuty', icon: Siren, hint: 'An Events API v2 integration on a PagerDuty service. Alerts trigger incidents; resolving the alert resolves them.' },
		opsgenie: { label: 'Opsgenie', icon: BellRing, hint: 'An API integration in Opsgenie. Alerts create Opsgenie alerts; resolving closes them.' },
		oncall: { label: 'On-call', icon: PhoneCall, hint: 'Pages whoever is on call through an escalation policy (Settings → On-call), instead of telling everyone.' }
	};
	const policies = resource(() => api.get<EscalationPolicy[]>('/oncall/escalation-policies'));
	const calendars = resource(() => api.get<{ id: string; name: string }[]>('/sla/calendars'));

	// --- SMS provider -------------------------------------------------------------------------
	let sms = $state({ account_sid: '', from: '', base_url: '', token: '' });
	let smsTokenSet = $state(false);
	let smsSaved = $state('');
	let smsTo = $state('');
	function applySms(v: SmsSettings) {
		sms = { account_sid: v.account_sid, from: v.from, base_url: v.base_url, token: '' };
		smsTokenSet = v.token_set;
		smsSaved = JSON.stringify(sms);
		return v;
	}
	const smsRes = resource(() => api.get<SmsSettings>('/settings/sms').then(applySms));
	const smsDirty = $derived(JSON.stringify(sms) !== smsSaved);
	async function saveSms(e: SubmitEvent) {
		e.preventDefault();
		const { token, ...rest } = sms;
		await attempt(() => api.put<SmsSettings>('/settings/sms', { ...rest, ...(token ? { token } : {}) }).then(applySms), 'SMS provider saved.');
	}
	async function testSms() {
		try {
			const r = await api.post<{ ok: boolean; error?: string }>('/settings/sms/test', { to: smsTo });
			if (r.ok) toast.success(`Test text sent to ${smsTo}.`);
			else toast.error(r.error ?? 'Failed');
		} catch (err) {
			toast.error(err);
		}
	}

	// --- mail server --------------------------------------------------------------------------
	let smtp = $state({ host: '', port: 587, security: 'starttls' as Smtp['security'], username: '', password: '', from: '' });
	let passwordSet = $state(false);
	let smtpSaved = $state('');
	let smtpBusy = $state(false);
	function applySmtp(s: Smtp) {
		smtp = { host: s.host, port: s.port, security: s.security, username: s.username, password: '', from: s.from };
		passwordSet = s.password_set;
		smtpSaved = JSON.stringify(smtp);
		return s;
	}
	const smtpRes = resource(() => api.get<Smtp>('/settings/smtp').then(applySmtp));
	const smtpDirty = $derived(JSON.stringify(smtp) !== smtpSaved);
	async function saveSmtp(e: SubmitEvent) {
		e.preventDefault();
		smtpBusy = true;
		try {
			const { password, ...rest } = smtp;
			applySmtp(await api.put<Smtp>('/settings/smtp', { ...rest, port: Number(rest.port), ...(password ? { password } : {}) }));
			toast.success('Mail server saved.');
		} catch (err) {
			toast.error(err);
		} finally {
			smtpBusy = false;
		}
	}
	async function clearPassword() {
		if (await attempt(() => api.put<Smtp>('/settings/smtp', { ...smtp, port: Number(smtp.port), password: '' }).then(applySmtp), 'Password removed.')) passwordSet = false;
	}

	// --- channels -----------------------------------------------------------------------------
	const channels = resource(() => api.get<Channel[]>('/notification-channels'));
	const deliveries = resource(() => api.get<DeliveryRow[]>('/notifications'));

	type Form = {
		id: string | null; name: string; kind: ChannelKind; to: string; url: string; secret: string; hasSecret: boolean; clearSecret: boolean; enabled: boolean;
		region: 'us' | 'eu'; policy: string; when: 'always' | 'outside_hours'; calendar: string;
	};
	let editing = $state<Form | null>(null);
	let saving = $state(false);
	let testing = $state<string | null>(null);

	function edit(c?: Channel) {
		editing = c
			? {
					id: c.id, name: c.name, kind: c.kind, to: (c.config?.to ?? []).join('\n'), url: c.config?.url ?? '', secret: '', hasSecret: c.has_secret, clearSecret: false, enabled: c.enabled,
					region: c.config?.region ?? 'us', policy: c.config?.escalation_policy_id ?? '', when: c.config?.when ?? 'always', calendar: c.config?.calendar_id ?? ''
				}
			: { id: null, name: '', kind: 'email', to: '', url: '', secret: '', hasSecret: false, clearSecret: false, enabled: true, region: 'us', policy: '', when: 'always', calendar: '' };
	}
	async function saveChannel(e: SubmitEvent) {
		e.preventDefault();
		const f = editing!;
		const list = f.to.split(/[\n,;]/).map((t) => t.trim()).filter(Boolean);
		const config: Record<string, unknown> =
			f.kind === 'email' || f.kind === 'sms'
				? { to: list }
				: f.kind === 'pagerduty'
					? {}
					: f.kind === 'opsgenie'
						? { region: f.region }
						: f.kind === 'oncall'
							? { escalation_policy_id: f.policy, when: f.when, ...(f.when === 'outside_hours' ? { calendar_id: f.calendar } : {}) }
							: { url: f.url.trim() };
		// A secret (or key) left blank is kept; tick "remove" to drop a webhook's.
		if (f.kind === 'webhook' && (f.secret || f.clearSecret || !f.id)) config.secret = f.clearSecret ? '' : f.secret;
		if ((f.kind === 'pagerduty' || f.kind === 'opsgenie') && f.secret) config.secret = f.secret;
		saving = true;
		try {
			const body = { name: f.name, kind: f.kind, config, enabled: f.enabled };
			if (f.id) await api.put(`/notification-channels/${f.id}`, body);
			else await api.post('/notification-channels', body);
			toast.success(`${f.name} saved.`);
			editing = null;
			channels.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function test(c: Channel) {
		testing = c.id;
		try {
			const r = await api.post<{ ok: boolean; error?: string }>(`/notification-channels/${c.id}/test`);
			if (r.ok) toast.success(`Test sent to ${c.name}.`);
			else toast.error(`${c.name}: ${r.error}`);
		} catch (err) {
			toast.error(err);
		} finally {
			testing = null;
		}
	}
	async function remove(c: Channel) {
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message: c.policies ? `${c.policies} polic${c.policies === 1 ? 'y stops' : 'ies stop'} notifying it. Queued messages are dropped.` : 'Queued messages are dropped.',
			confirmLabel: 'Delete channel',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/notification-channels/${c.id}`), `${c.name} deleted.`))) channels.reload();
	}
	const target = (c: Channel) =>
		c.kind === 'email' || c.kind === 'sms'
			? (c.config?.to ?? []).join(', ')
			: c.kind === 'pagerduty'
				? 'Events API v2'
				: c.kind === 'opsgenie'
					? `${(c.config?.region ?? 'us').toUpperCase()} region`
					: c.kind === 'oncall'
						? `${policies.data?.find((p) => p.id === c.config?.escalation_policy_id)?.name ?? 'Escalation policy'}${c.config?.when === 'outside_hours' ? ', outside business hours' : ''}`
						: (c.config?.url ?? '').replace(/^https?:\/\//, '').slice(0, 60);
</script>

<div class="max-w-4xl space-y-5">
	<section class="card" aria-labelledby="ch-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="ch-h" class="font-semibold">Notification channels</h2>
				<p class="text-muted text-xs">Where alert policies send their alerts. Technicians can pick these in their policies but not see where they point.</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => edit()}>Add channel</Button>
		</header>
		<Async res={channels} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as c (c.id)}
							{@const K = kinds[c.kind]}
							<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
								<K.icon class="text-muted size-4 shrink-0" aria-hidden="true" />
								<div class="min-w-0 flex-1">
									<div class="font-medium">{c.name} {#if !c.enabled}<Badge>Disabled</Badge>{/if}</div>
									<div class="text-muted truncate text-xs">{K.label} · {target(c)}{c.kind === 'webhook' && c.has_secret ? ' · signed' : ''} · {c.policies} polic{c.policies === 1 ? 'y' : 'ies'}</div>
								</div>
								<Button size="sm" icon={Send} loading={testing === c.id} onclick={() => test(c)}>Test</Button>
								<IconButton icon={Pencil} size="sm" label="Edit {c.name}" onclick={() => edit(c)} />
								<IconButton icon={Trash2} size="sm" label="Delete {c.name}" onclick={() => remove(c)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Send} title="No channels yet" description="Add email recipients, a webhook, a Slack channel or a Teams channel, then choose it in an alert policy." />
				{/if}
			{/snippet}
		</Async>
	</section>

	<Async res={smtpRes}>
		{#snippet children()}
			<form class="card space-y-4 p-5" onsubmit={saveSmtp} aria-labelledby="smtp-h">
				<div>
					<h2 id="smtp-h" class="font-semibold">Mail server</h2>
					<p class="text-muted text-xs">Used by email channels. The password is stored in the database as entered: use an account that can only send mail.</p>
				</div>
				<div class="grid gap-3 sm:grid-cols-[1fr_7rem_10rem]">
					<Field label="SMTP host" id="smtp-host"><Input id="smtp-host" bind:value={smtp.host} placeholder="smtp.example.com" autocomplete="off" /></Field>
					<Field label="Port" id="smtp-port"><Input id="smtp-port" type="number" min="1" max="65535" bind:value={smtp.port} /></Field>
					<Field label="Security" id="smtp-sec">
						<Select
							id="smtp-sec"
							bind:value={smtp.security}
							onchange={() => (smtp.port = smtp.security === 'tls' ? 465 : smtp.security === 'starttls' ? 587 : 25)}
							options={[{ value: 'starttls', label: 'STARTTLS' }, { value: 'tls', label: 'TLS' }, { value: 'none', label: 'None' }]}
						/>
					</Field>
				</div>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Username" id="smtp-user"><Input id="smtp-user" bind:value={smtp.username} autocomplete="off" /></Field>
					<Field label="Password" id="smtp-pass" hint={passwordSet ? 'Saved. Leave empty to keep it.' : undefined}>
						<Input id="smtp-pass" type="password" bind:value={smtp.password} autocomplete="new-password" placeholder={passwordSet ? '••••••••' : ''} />
					</Field>
				</div>
				<Field label="From" id="smtp-from" hint="The sender, e.g. Acme RMM <rmm@acme.example>."><Input id="smtp-from" bind:value={smtp.from} /></Field>
				<div class="flex flex-wrap items-center justify-end gap-3">
					{#if passwordSet}<Button size="sm" variant="ghost" onclick={clearPassword}>Remove password</Button>{/if}
					{#if smtpDirty}<span class="text-warning text-xs">Unsaved changes</span>{/if}
					<Button variant="primary" type="submit" loading={smtpBusy} disabled={!smtpDirty}>Save</Button>
				</div>
			</form>
		{/snippet}
	</Async>

	<Async res={smsRes}>
		{#snippet children()}
			<form class="card space-y-4 p-5" onsubmit={saveSms} aria-labelledby="sms-h">
				<div>
					<h2 id="sms-h" class="font-semibold">SMS provider</h2>
					<p class="text-muted text-xs">Text messages for pages and text-message channels, through Twilio’s Messages API (or a compatible one). Registering the sender (A2P 10DLC in the US) is up to you.</p>
				</div>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Account SID" id="sms-sid"><Input id="sms-sid" bind:value={sms.account_sid} autocomplete="off" placeholder="AC…" /></Field>
					<Field label="Auth token" id="sms-token" hint={smsTokenSet ? 'Saved. Leave empty to keep it.' : undefined}>
						<Input id="sms-token" type="password" bind:value={sms.token} autocomplete="new-password" placeholder={smsTokenSet ? '••••••••' : ''} />
					</Field>
					<Field label="From" id="sms-from" hint="A number in international form, or a messaging service SID."><Input id="sms-from" bind:value={sms.from} placeholder="+15005550006" /></Field>
					<Field label="API URL" id="sms-url"><Input id="sms-url" bind:value={sms.base_url} placeholder="https://api.twilio.com" /></Field>
				</div>
				<div class="flex flex-wrap items-end justify-end gap-3">
					<Field label="Send a test to" id="sms-test" class="mr-auto"><Input id="sms-test" bind:value={smsTo} placeholder="+447700900123" /></Field>
					<Button icon={Send} disabled={!smsTo || smsDirty || !smsTokenSet} onclick={testSms}>Send test</Button>
					{#if smsDirty}<span class="text-warning text-xs">Unsaved changes</span>{/if}
					<Button variant="primary" type="submit" disabled={!smsDirty}>Save</Button>
				</div>
			</form>
		{/snippet}
	</Async>

	<section class="card" aria-labelledby="dl-h">
		<header class="border-border flex items-center justify-between border-b px-5 py-3">
			<h2 id="dl-h" class="font-semibold">Recent deliveries</h2>
			<Button size="sm" onclick={() => deliveries.reload()}>Refresh</Button>
		</header>
		<Async res={deliveries} compact>
			{#snippet children(rows)}
				{#if rows.length}
					<div class="overflow-x-auto">
						<table class="table">
							<thead><tr><th>When</th><th>Channel</th><th>Alert</th><th>Status</th></tr></thead>
							<tbody>
								{#each rows as d (d.id)}
									<tr>
										<td class="whitespace-nowrap" title={datetime(d.sent_at ?? d.created_at)}>{ago(d.sent_at ?? d.created_at)}</td>
										<td>{d.channel_name}</td>
										<td class="max-w-xs">
											{#if d.alert_id}<a class="link" href="/alerts/{d.alert_id}">{d.alert_title}</a> <span class="text-muted text-xs">{d.hostname} · {d.event}</span>{:else}<span class="text-muted">Test</span>{/if}
										</td>
										<td>
											<Badge tone={d.status === 'sent' ? 'success' : d.status === 'failed' ? 'danger' : 'warning'}>{d.status === 'pending' ? `Retry ${d.attempts}` : d.status === 'sent' ? 'Sent' : 'Failed'}</Badge>
											{#if d.last_error && d.status !== 'sent'}<div class="text-danger max-w-sm truncate text-xs" title={d.last_error}>{d.last_error}</div>{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else}
					<EmptyState compact title="Nothing sent yet" />
				{/if}
			{/snippet}
		</Async>
	</section>
</div>

{#if editing}
	<Modal title={editing.id ? `Edit ${editing.name}` : 'Add channel'} onclose={() => (editing = null)}>
		<form id="channel-form" class="space-y-4" onsubmit={saveChannel}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="ch-name" required><Input id="ch-name" bind:value={editing.name} required maxlength={100} placeholder="e.g. On-call" /></Field>
				<Field label="Type" id="ch-kind">
					<Select id="ch-kind" bind:value={editing.kind} options={Object.entries(kinds).map(([value, k]) => ({ value: value as ChannelKind, label: k.label }))} />
				</Field>
			</div>
			<p class="hint -mt-2">{kinds[editing.kind].hint}</p>
			{#if editing.kind === 'email'}
				<Field label="Recipients" id="ch-to" hint="One address per line." required><Textarea id="ch-to" rows={3} bind:value={editing.to} placeholder="ops@example.com" /></Field>
			{:else if editing.kind === 'sms'}
				<Field label="Mobile numbers" id="ch-to" hint="One per line, in international form." required><Textarea id="ch-to" rows={3} bind:value={editing.to} placeholder="+447700900123" /></Field>
			{:else if editing.kind === 'pagerduty' || editing.kind === 'opsgenie'}
				{#if editing.kind === 'opsgenie'}
					<Field label="Region" id="ch-region"><Select id="ch-region" bind:value={editing.region} options={[{ value: 'us', label: 'US (api.opsgenie.com)' }, { value: 'eu', label: 'EU (api.eu.opsgenie.com)' }]} /></Field>
				{/if}
				<Field label={editing.kind === 'pagerduty' ? 'Integration key' : 'API key'} id="ch-secret" hint={editing.hasSecret ? 'Saved. Leave empty to keep it.' : undefined} required={!editing.hasSecret}>
					<Input id="ch-secret" type="password" bind:value={editing.secret} autocomplete="new-password" required={!editing.hasSecret} />
				</Field>
			{:else if editing.kind === 'oncall'}
				<Field label="Escalation policy" id="ch-policy" required>
					<Select id="ch-policy" bind:value={editing.policy} required options={[{ value: '', label: 'Choose…' }, ...(policies.data ?? []).map((p) => ({ value: p.id, label: p.name }))]} />
				</Field>
				<Field label="When" id="ch-when">
					<Select id="ch-when" bind:value={editing.when} options={[{ value: 'always', label: 'Always page' }, { value: 'outside_hours', label: 'Only outside business hours' }]} />
				</Field>
				{#if editing.when === 'outside_hours'}
					<Field label="Business hours" id="ch-cal" hint="Inside these hours the page waits until they end (and is dropped if the alert is dealt with first)." required>
						<Select id="ch-cal" bind:value={editing.calendar} required options={[{ value: '', label: 'Choose…' }, ...(calendars.data ?? []).map((c) => ({ value: c.id, label: c.name }))]} />
					</Field>
				{/if}
			{:else}
				<Field label="Webhook URL" id="ch-url" required><Input id="ch-url" type="url" bind:value={editing.url} required placeholder="https://" /></Field>
				{#if editing.kind === 'webhook'}
					<Field label="Signing secret" id="ch-secret" hint={editing.hasSecret ? 'A secret is saved. Leave empty to keep it.' : 'Optional.'}>
						<Input id="ch-secret" type="password" bind:value={editing.secret} autocomplete="new-password" disabled={editing.clearSecret} />
					</Field>
					{#if editing.hasSecret}<Switch bind:checked={editing.clearSecret}>Remove the saved secret</Switch>{/if}
				{/if}
			{/if}
			<Switch bind:checked={editing.enabled}>Enabled</Switch>
		</form>
		{#snippet footer()}
			<Button onclick={() => (editing = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="channel-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
