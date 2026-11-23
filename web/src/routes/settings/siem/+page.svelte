<script lang="ts">
	import { Pencil, Plus, RotateCw, Send, Trash2, Waypoints } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
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
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	type Kind = 'syslog_udp' | 'syslog_tcp' | 'syslog_tls' | 'https';
	interface Destination {
		id: string; name: string; kind: Kind; address: string; framing: 'octet' | 'newline'; https_format: 'generic' | 'splunk_hec';
		has_token: boolean; ca_pem: string | null; facility: number; send_audit: boolean; send_detections: boolean; send_alerts: boolean;
		enabled: boolean; consecutive_failures: number; next_attempt_at: string; last_attempt_at: string | null; last_success_at: string | null;
		last_error: string | null; sent_total: number; dropped_total: number; pending: number; created_at: string;
	}
	const list = resource(() => api.get<{ destinations: Destination[]; retain_days: number }>('/siem/destinations'));

	const kinds: { value: Kind; label: string; example: string }[] = [
		{ value: 'syslog_udp', label: 'Syslog over UDP', example: 'logs.example.com:514' },
		{ value: 'syslog_tcp', label: 'Syslog over TCP', example: 'logs.example.com:514' },
		{ value: 'syslog_tls', label: 'Syslog over TLS', example: 'logs.example.com:6514' },
		{ value: 'https', label: 'HTTPS (JSON)', example: 'https://siem.example.com/ingest' }
	];
	const kindLabel = (k: Kind) => kinds.find((x) => x.value === k)?.label ?? k;
	const facilities = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'log audit', 'log alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];

	type Form = {
		id: string | null; name: string; kind: Kind; address: string; framing: 'octet' | 'newline'; https_format: 'generic' | 'splunk_hec';
		token: string; had_token: boolean; clear_token: boolean; ca_pem: string; facility: number;
		send_audit: boolean; send_detections: boolean; send_alerts: boolean; enabled: boolean;
	};
	let editing = $state<Form | null>(null);
	let saving = $state(false);
	let testing = $state<string | null>(null);

	function edit(d: Destination | null) {
		editing = d
			? { id: d.id, name: d.name, kind: d.kind, address: d.address, framing: d.framing, https_format: d.https_format, token: '', had_token: d.has_token, clear_token: false, ca_pem: d.ca_pem ?? '', facility: d.facility, send_audit: d.send_audit, send_detections: d.send_detections, send_alerts: d.send_alerts, enabled: d.enabled }
			: { id: null, name: '', kind: 'syslog_tls', address: '', framing: 'octet', https_format: 'generic', token: '', had_token: false, clear_token: false, ca_pem: '', facility: 13, send_audit: true, send_detections: false, send_alerts: false, enabled: true };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const f = editing!;
		saving = true;
		try {
			const body: Record<string, unknown> = {
				name: f.name, kind: f.kind, address: f.address, framing: f.framing, https_format: f.https_format, facility: f.facility,
				ca_pem: f.kind === 'syslog_tls' || f.kind === 'https' ? f.ca_pem : '', send_audit: f.send_audit, send_detections: f.send_detections,
				send_alerts: f.send_alerts, enabled: f.enabled
			};
			// Left out, the stored token stays.
			if (f.kind === 'https' && (f.token || f.clear_token)) body.token = f.clear_token ? '' : f.token;
			if (f.id) await api.put(`/siem/destinations/${f.id}`, body);
			else await api.post('/siem/destinations', body);
			toast.success(`${f.name} saved.`);
			editing = null;
			list.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function remove(d: Destination) {
		const ok = await confirmAction({
			title: `Delete ${d.name}?`,
			message: d.pending ? `${num(d.pending)} event${d.pending === 1 ? ' is' : 's are'} still waiting to be sent and will be dropped.` : 'Nothing more is sent there.',
			confirmLabel: 'Delete destination',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/siem/destinations/${d.id}`), `${d.name} deleted.`))) list.reload();
	}
	async function test(d: Destination) {
		testing = d.id;
		try {
			const r = await api.post<{ ok: boolean; error?: string }>(`/siem/destinations/${d.id}/test`);
			if (r.ok) toast.success(`Test event sent to ${d.name}.`);
			else toast.error(`${d.name}: ${r.error}`);
		} catch (err) {
			toast.error(err);
		} finally {
			testing = null;
		}
	}

	function status(d: Destination): { tone: 'success' | 'warning' | 'danger' | 'neutral'; label: string } {
		if (!d.enabled) return { tone: 'neutral', label: 'Disabled' };
		if (d.consecutive_failures) return { tone: 'danger', label: `Failing (${d.consecutive_failures})` };
		if (d.pending) return { tone: 'warning', label: `${num(d.pending)} waiting` };
		return d.last_success_at ? { tone: 'success', label: 'Delivering' } : { tone: 'neutral', label: 'Nothing sent yet' };
	}
	const what = (d: Destination) => [d.send_audit && 'audit log', d.send_detections && 'detections', d.send_alerts && 'alerts'].filter(Boolean).join(', ');
</script>

<div class="max-w-5xl space-y-5">
	<section class="card" aria-labelledby="siem-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="siem-h" class="font-semibold">SIEM and syslog</h2>
				<p class="text-muted text-xs">
					Stream the audit log, and optionally security detections and alerts, to your log collector as they happen. Events wait here while it is unreachable
					and go out in order once it is back{list.data ? `, for up to ${list.data.retain_days} days` : ''}. To download the audit log instead, use Export on the <a class="link" href="/audit">Audit log</a> page.
				</p>
			</div>
			<div class="flex gap-2">
				<Button icon={RotateCw} onclick={() => list.reload()}>Refresh</Button>
				<Button variant="primary" icon={Plus} onclick={() => edit(null)}>Add destination</Button>
			</div>
		</header>
		<Async res={list} compact>
			{#snippet children(data)}
				{#if data.destinations.length}
					<ul class="divide-border divide-y">
						{#each data.destinations as d (d.id)}
							{@const s = status(d)}
							<li class="px-5 py-3 text-sm">
								<div class="flex flex-wrap items-center gap-x-3 gap-y-2">
									<Waypoints class="text-muted size-4 shrink-0" aria-hidden="true" />
									<div class="min-w-0 flex-1">
										<div class="font-medium">{d.name} <Badge tone={s.tone}>{s.label}</Badge></div>
										<div class="text-muted truncate text-xs">{kindLabel(d.kind)} · {d.address} · {what(d)}</div>
									</div>
									<Button size="sm" icon={Send} loading={testing === d.id} onclick={() => test(d)}>Test</Button>
									<IconButton icon={Pencil} size="sm" label="Edit {d.name}" onclick={() => edit(d)} />
									<IconButton icon={Trash2} size="sm" label="Delete {d.name}" onclick={() => remove(d)} />
								</div>
								<dl class="text-muted mt-1.5 ml-7 flex flex-wrap gap-x-5 gap-y-0.5 text-xs">
									<div><dt class="inline">Sent</dt> <dd class="tabular inline">{num(d.sent_total)}</dd></div>
									<div><dt class="inline">Waiting</dt> <dd class="tabular inline">{num(d.pending)}</dd></div>
									{#if d.dropped_total}<div><dt class="inline">Dropped</dt> <dd class="tabular inline">{num(d.dropped_total)}</dd></div>{/if}
									<div><dt class="inline">Last delivered</dt> <dd class="inline" title={d.last_success_at ? datetime(d.last_success_at) : ''}>{d.last_success_at ? ago(d.last_success_at) : 'never'}</dd></div>
									{#if d.consecutive_failures}<div><dt class="inline">Next attempt</dt> <dd class="inline" title={datetime(d.next_attempt_at)}>{ago(d.next_attempt_at)}</dd></div>{/if}
								</dl>
								{#if d.last_error}<p class="text-danger mt-1 ml-7 truncate text-xs" title={d.last_error}>{d.last_error}</p>{/if}
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Waypoints} title="No destinations yet" description="Add a syslog server or an HTTPS endpoint (a Splunk HEC, Elastic or Graylog input, a log shipper) to stream events to it." />
				{/if}
			{/snippet}
		</Async>
	</section>
</div>

{#if editing}
	{@const f = editing}
	{@const kind = kinds.find((k) => k.value === f.kind)!}
	<Modal title={f.id ? `Edit ${f.name}` : 'Add destination'} onclose={() => (editing = null)} size="lg">
		<form id="siem-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="siem-name" required><Input id="siem-name" bind:value={f.name} required maxlength={100} placeholder="e.g. Splunk" /></Field>
				<Field label="Type" id="siem-kind">
					<Select id="siem-kind" bind:value={f.kind} options={kinds.map((k) => ({ value: k.value, label: k.label }))} />
				</Field>
			</div>
			<Field label={f.kind === 'https' ? 'URL' : 'Host and port'} id="siem-address" required>
				<Input id="siem-address" bind:value={f.address} required placeholder={kind.example} />
			</Field>
			{#if f.kind === 'syslog_tcp'}
				<Field label="Framing" id="siem-framing" hint="Octet counting (RFC 6587) is safest; some collectors want one message per line.">
					<Select id="siem-framing" bind:value={f.framing} options={[{ value: 'octet', label: 'Octet counting' }, { value: 'newline', label: 'One message per line' }]} />
				</Field>
			{/if}
			{#if f.kind !== 'https'}
				<Field label="Facility" id="siem-facility" hint="Messages follow RFC 5424. “log audit” is the usual choice.">
					<Select id="siem-facility" value={String(f.facility)} onchange={(e) => (f.facility = Number(e.currentTarget.value))} options={facilities.map((n, i) => ({ value: String(i), label: `${i} · ${n}` }))} />
				</Field>
			{:else}
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Format" id="siem-format" hint="Generic posts {'{"events": [...]}'}; Splunk HEC posts one event per line.">
						<Select id="siem-format" bind:value={f.https_format} options={[{ value: 'generic', label: 'Generic JSON' }, { value: 'splunk_hec', label: 'Splunk HEC' }]} />
					</Field>
					<Field label={f.https_format === 'splunk_hec' ? 'HEC token' : 'Bearer token'} id="siem-token" hint={f.had_token && !f.clear_token ? 'A token is stored. Leave empty to keep it.' : 'Optional. Stored encrypted.'}>
						<Input id="siem-token" type="password" bind:value={f.token} autocomplete="new-password" placeholder={f.had_token && !f.clear_token ? '••••••••' : ''} disabled={f.clear_token} />
					</Field>
				</div>
				{#if f.had_token}<Switch bind:checked={f.clear_token}>Remove the stored token</Switch>{/if}
			{/if}
			{#if f.kind === 'syslog_tls' || f.kind === 'https'}
				<Field label="CA certificate" id="siem-ca" hint="Only if the collector's certificate comes from a private CA. PEM; the system roots are trusted either way.">
					<Textarea id="siem-ca" bind:value={f.ca_pem} rows={4} class="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" />
				</Field>
			{/if}
			<fieldset>
				<legend class="label">Send</legend>
				<div class="grid gap-2 sm:grid-cols-3">
					<Checkbox bind:checked={f.send_audit}>Audit log</Checkbox>
					<Checkbox bind:checked={f.send_detections}>Security detections</Checkbox>
					<Checkbox bind:checked={f.send_alerts}>Alerts</Checkbox>
				</div>
			</fieldset>
			<Switch bind:checked={f.enabled}>Enabled</Switch>
			<p class="hint">Only events from now on are sent; nothing is replayed from the past.</p>
		</form>
		{#snippet footer()}
			<Button onclick={() => (editing = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="siem-form" loading={saving} disabled={!f.send_audit && !f.send_detections && !f.send_alerts}>Save</Button>
		{/snippet}
	</Modal>
{/if}
