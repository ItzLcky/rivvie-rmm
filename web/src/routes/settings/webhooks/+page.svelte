<script lang="ts">
	import { KeyRound, ListChecks, Pencil, Plus, RotateCw, Send, Trash2, Webhook } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients } from '#lib/scope.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	interface Hook {
		id: string; name: string; url: string; client_id: string | null; client_name: string | null; events: string[];
		internal_notes: boolean; enabled: boolean; created_at: string; pending: number; failed_24h: number; last_sent_at: string | null;
	}
	interface Delivery {
		id: number; delivery_id: string; event: string; status: 'pending' | 'sent' | 'failed'; attempts: number; response_status: number | null;
		duration_ms: number | null; last_error: string | null; created_at: string; sent_at: string | null; next_attempt_at: string;
	}
	const list = resource(() => api.get<{ webhooks: Hook[]; events: string[] }>('/webhooks'));

	const eventLabels: Record<string, string> = {
		'ticket.created': 'Ticket created',
		'ticket.updated': 'Ticket updated (assignee, priority, links…)',
		'ticket.status_changed': 'Ticket status changed',
		'ticket.resolved': 'Ticket resolved',
		'ticket.comment': 'Ticket reply or note',
		'alert.created': 'Alert opened',
		'alert.acknowledged': 'Alert acknowledged',
		'alert.resolved': 'Alert resolved'
	};

	type Form = { id: string | null; name: string; url: string; events: string[]; client_id: string; internal_notes: boolean; enabled: boolean };
	let editing = $state<Form | null>(null);
	let saving = $state(false);
	let secret = $state<{ name: string; value: string } | null>(null);

	function edit(h: Hook | null, events: string[]) {
		editing = h
			? { id: h.id, name: h.name, url: h.url, events: [...h.events], client_id: h.client_id ?? '', internal_notes: h.internal_notes, enabled: h.enabled }
			: { id: null, name: '', url: '', events: [...events], client_id: '', internal_notes: false, enabled: true };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const f = editing!;
		saving = true;
		try {
			const body = { name: f.name, url: f.url, events: f.events, client_id: f.client_id || null, internal_notes: f.internal_notes, enabled: f.enabled };
			if (f.id) {
				await api.put(`/webhooks/${f.id}`, body);
				toast.success(`${f.name} saved.`);
			} else {
				const r = await api.post<{ secret: string }>('/webhooks', body);
				secret = { name: f.name, value: r.secret };
			}
			editing = null;
			list.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function remove(h: Hook) {
		const ok = await confirmAction({ title: `Delete ${h.name}?`, message: 'Deliveries still waiting for it are dropped, and its log is deleted.', confirmLabel: 'Delete webhook', danger: true });
		if (ok && (await attempt(() => api.del(`/webhooks/${h.id}`), `${h.name} deleted.`))) list.reload();
	}
	async function rotate(h: Hook) {
		const ok = await confirmAction({
			title: `New secret for ${h.name}?`,
			message: 'Deliveries from now on are signed with the new secret and fail verification until you update the receiver.',
			confirmLabel: 'Rotate secret',
			danger: true
		});
		if (!ok) return;
		try {
			const r = await api.post<{ secret: string }>(`/webhooks/${h.id}/rotate-secret`);
			secret = { name: h.name, value: r.secret };
		} catch (err) {
			toast.error(err);
		}
	}
	async function test(h: Hook) {
		if (await attempt(() => api.post(`/webhooks/${h.id}/test`), `Test queued for ${h.name}; see its log.`)) setTimeout(() => (log?.id === h.id ? deliveries.reload() : list.reload()), 1500);
	}

	// --- delivery log -----------------------------------------------------------------------
	let log = $state<Hook | null>(null);
	let filter = $state('');
	const deliveries = resource(() => (log ? api.get<Delivery[]>(`/webhooks/${log.id}/deliveries?limit=100${filter ? `&status=${filter}` : ''}`) : Promise.resolve([] as Delivery[])));
	async function redeliver(d: Delivery) {
		if (await attempt(() => api.post(`/webhook-deliveries/${d.id}/redeliver`), 'Queued to be sent again.')) setTimeout(() => deliveries.reload(), 1500);
	}
	const tone = { sent: 'success', pending: 'warning', failed: 'danger' } as const;
	const statusLabel = (d: Delivery) => (d.status === 'pending' ? (d.attempts ? `Retry ${d.attempts}` : 'Queued') : d.status === 'sent' ? 'Sent' : 'Failed');
	const target = (u: string) => u.replace(/^https?:\/\//, '').slice(0, 64);
</script>

<div class="max-w-5xl space-y-5">
	<section class="card" aria-labelledby="wh-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="wh-h" class="font-semibold">Webhooks</h2>
				<p class="text-muted text-xs">
					Tell another system when tickets and alerts change. Each delivery is a signed JSON <code>POST</code>, retried for a few hours if the receiver is down.
					<a class="link" href="/developers#webhooks">How to verify them</a>
				</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => edit(null, list.data?.events ?? [])}>Add webhook</Button>
		</header>
		<Async res={list} compact>
			{#snippet children(data)}
				{#if data.webhooks.length}
					<ul class="divide-border divide-y">
						{#each data.webhooks as h (h.id)}
							<li class="flex flex-wrap items-center gap-x-3 gap-y-2 px-5 py-3 text-sm">
								<Webhook class="text-muted size-4 shrink-0" aria-hidden="true" />
								<div class="min-w-0 flex-1">
									<div class="font-medium">
										{h.name}
										{#if !h.enabled}<Badge>Disabled</Badge>{/if}
										{#if h.failed_24h}<Badge tone="danger">{h.failed_24h} failed today</Badge>{:else if h.pending}<Badge tone="warning">{h.pending} waiting</Badge>{/if}
									</div>
									<div class="text-muted truncate text-xs">
										{target(h.url)} · {h.client_name ?? 'All clients'} · {h.events.length === data.events.length ? 'all events' : `${h.events.length} event${h.events.length === 1 ? '' : 's'}`}{h.last_sent_at ? ` · last sent ${ago(h.last_sent_at)}` : ''}
									</div>
								</div>
								<Button size="sm" icon={ListChecks} onclick={() => ((log = h), (filter = ''))}>Log</Button>
								<Button size="sm" icon={Send} onclick={() => test(h)}>Test</Button>
								<IconButton icon={KeyRound} size="sm" label="Rotate secret of {h.name}" onclick={() => rotate(h)} />
								<IconButton icon={Pencil} size="sm" label="Edit {h.name}" onclick={() => edit(h, data.events)} />
								<IconButton icon={Trash2} size="sm" label="Delete {h.name}" onclick={() => remove(h)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Webhook} title="No webhooks yet" description="Add a URL and choose the ticket and alert events to send to it." />
				{/if}
			{/snippet}
		</Async>
	</section>
</div>

{#if editing}
	{@const events = list.data?.events ?? []}
	<Modal title={editing.id ? `Edit ${editing.name}` : 'Add webhook'} onclose={() => (editing = null)} size="lg">
		<form id="hook-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="wh-name" required><Input id="wh-name" bind:value={editing.name} required maxlength={100} placeholder="e.g. Ticket mirror" /></Field>
				<Field label="Client" id="wh-client" hint="Only events of this client.">
					<Select id="wh-client" bind:value={editing.client_id} options={[{ value: '', label: 'All clients' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
			</div>
			<Field label="URL" id="wh-url" required><Input id="wh-url" type="url" bind:value={editing.url} required placeholder="https://" /></Field>
			<fieldset>
				<legend class="label">Events</legend>
				<div class="grid gap-2 sm:grid-cols-2">
					{#each events as ev (ev)}
						<Checkbox
							checked={editing.events.includes(ev)}
							onchange={(on) => (editing!.events = on ? [...editing!.events, ev] : editing!.events.filter((x) => x !== ev))}
						>{eventLabels[ev] ?? ev}</Checkbox>
					{/each}
				</div>
			</fieldset>
			<Switch bind:checked={editing.internal_notes}>Include internal notes in ticket comments</Switch>
			<Switch bind:checked={editing.enabled}>Enabled</Switch>
			{#if !editing.id}<p class="hint">The signing secret is shown once, after you save.</p>{/if}
		</form>
		{#snippet footer()}
			<Button onclick={() => (editing = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="hook-form" loading={saving} disabled={!editing?.events.length}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if secret}
	<Modal title="Signing secret for {secret.name}" description="Shown once. Receivers compute HMAC-SHA256 of the raw body with it and compare with X-RMM-Signature." onclose={() => (secret = null)}>
		<CodeBlock code={secret.value} label="signing secret" />
		{#snippet footer()}<Button variant="primary" onclick={() => (secret = null)}>I’ve copied it</Button>{/snippet}
	</Modal>
{/if}

{#if log}
	<Modal title="Deliveries to {log.name}" description={log.url} onclose={() => (log = null)} size="xl">
		<div class="mb-3 flex items-center justify-between gap-3">
			<Select
				aria-label="Show"
				bind:value={filter}
				onchange={() => deliveries.reload()}
				options={[{ value: '', label: 'All deliveries' }, { value: 'failed', label: 'Failed' }, { value: 'pending', label: 'Waiting or retrying' }, { value: 'sent', label: 'Sent' }]}
			/>
			<Button size="sm" icon={RotateCw} onclick={() => deliveries.reload()}>Refresh</Button>
		</div>
		<Async res={deliveries} compact>
			{#snippet children(rows)}
				{#if rows.length}
					<div class="overflow-x-auto">
						<table class="table">
							<thead><tr><th>When</th><th>Event</th><th>Status</th><th>Response</th><th><span class="sr-only">Actions</span></th></tr></thead>
							<tbody>
								{#each rows as d (d.id)}
									<tr>
										<td class="whitespace-nowrap" title={datetime(d.created_at)}>{ago(d.created_at)}</td>
										<td><code class="text-xs">{d.event}</code><div class="text-muted font-mono text-xs" title="X-RMM-Delivery">{d.delivery_id.slice(0, 8)}</div></td>
										<td>
											<Badge tone={tone[d.status]}>{statusLabel(d)}</Badge>
											{#if d.status === 'pending' && d.attempts}<div class="text-muted text-xs">next {ago(d.next_attempt_at)}</div>{/if}
										</td>
										<td class="max-w-sm">
											{#if d.response_status}<span class="tabular">HTTP {d.response_status}</span>{#if d.duration_ms !== null} <span class="text-muted text-xs">{d.duration_ms} ms</span>{/if}{:else if d.status !== 'sent'}<span class="text-muted">No response</span>{/if}
											{#if d.last_error && d.status !== 'sent'}<div class="text-danger truncate text-xs" title={d.last_error}>{d.last_error}</div>{/if}
										</td>
										<td class="text-right"><Button size="sm" onclick={() => redeliver(d)}>Send again</Button></td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else}
					<EmptyState compact title="Nothing sent yet" description="Use Test to send a ping." />
				{/if}
			{/snippet}
		</Async>
		{#snippet footer()}<Button onclick={() => (log = null)}>Close</Button>{/snippet}
	</Modal>
{/if}
