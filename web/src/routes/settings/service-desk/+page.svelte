<script lang="ts">
	import { ArrowDown, ArrowUp, Inbox, KeyRound, Mail, Pencil, Plus, RefreshCw, Trash2, Webhook, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { categories, categoryOf, ticketMeta, ticketNumber } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Board, InboundMail, Mailbox, StatusCategory, TicketType } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Teams from './Teams.svelte';
	import Canned from './Canned.svelte';
	import PortalSettings from './PortalSettings.svelte';

	const channels = resource(() => api.get<{ id: string; name: string; kind: string }[]>('/notification-channels'));
	const boards = resource(() => api.get<Board[]>('/boards'));
	const meta = resource(() => ticketMeta(true));
	const mailboxes = resource(() => api.get<Mailbox[]>('/mailboxes'));
	const inbound = resource(() => api.get<InboundMail[]>('/mailboxes/inbound'));
	const refreshMeta = () => {
		ticketMeta(true);
		boards.reload();
		meta.reload();
	};

	// --- boards -------------------------------------------------------------------------------
	type StatusDraft = { id?: string; name: string; category: StatusCategory };
	let board = $state<{
		id: string | null; name: string; description: string; statuses: StatusDraft[]; default_team_id: string; notify_channel_ids: string[];
	} | null>(null);
	let saving = $state(false);
	function editBoard(b?: Board) {
		board = b
			? {
					id: b.id, name: b.name, description: b.description, statuses: b.statuses.map((s) => ({ id: s.id, name: s.name, category: s.category })),
					default_team_id: b.default_team_id ?? '', notify_channel_ids: [...b.notify_channel_ids]
				}
			: {
					id: null,
					name: '',
					description: '',
					default_team_id: '',
					notify_channel_ids: [],
					statuses: [
						{ name: 'New', category: 'new' },
						{ name: 'In progress', category: 'open' },
						{ name: 'Waiting on client', category: 'waiting_client' },
						{ name: 'Resolved', category: 'resolved' },
						{ name: 'Closed', category: 'closed' }
					]
				};
	}
	function move(i: number, d: -1 | 1) {
		const s = board!.statuses;
		[s[i], s[i + d]] = [s[i + d], s[i]];
	}
	const missing = $derived(board ? (['new', 'resolved', 'closed'] as const).filter((c) => !board!.statuses.some((s) => s.category === c)) : []);
	async function saveBoard(e: SubmitEvent) {
		e.preventDefault();
		const b = board!;
		saving = true;
		try {
			const body = { name: b.name, description: b.description, statuses: b.statuses, default_team_id: b.default_team_id || null, notify_channel_ids: b.notify_channel_ids };
			if (b.id) await api.put(`/boards/${b.id}`, body);
			else await api.post('/boards', body);
			toast.success(`${b.name} saved.`);
			board = null;
			refreshMeta();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function removeBoard(b: Board) {
		const ok = await confirmAction({ title: `Delete ${b.name}?`, message: 'Only empty boards can be deleted: move their tickets and mailboxes first.', confirmLabel: 'Delete board', danger: true });
		if (ok && (await attempt(() => api.del(`/boards/${b.id}`), `${b.name} deleted.`))) refreshMeta();
	}

	// --- ticket types -------------------------------------------------------------------------
	let types = $state<{ id?: string; name: string }[] | null>(null);
	function editTypes(list: TicketType[]) {
		types = list.map((t) => ({ id: t.id, name: t.name }));
	}
	async function saveTypes(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		const list = types!.filter((t) => t.name.trim());
		if (await attempt(() => api.put('/ticket-types', { types: list }), 'Ticket types saved.')) {
			types = null;
			refreshMeta();
		}
		saving = false;
	}

	// --- mailboxes ----------------------------------------------------------------------------
	type MailboxDraft = {
		id: string | null; name: string; address: string; kind: 'imap' | 'webhook' | 'graph'; imap_host: string; imap_port: number;
		imap_security: 'tls' | 'none'; imap_username: string; imap_password: string; has_password: boolean; imap_folder: string;
		board_id: string; auto_reply: boolean; enabled: boolean;
		graph_tenant: string; graph_client_id: string; graph_secret: string; has_graph_secret: boolean; graph_send: boolean;
	};
	let mailbox = $state<MailboxDraft | null>(null);
	let webhookUrl = $state<{ name: string; url: string } | null>(null);
	let polling = $state<string | null>(null);
	function editMailbox(m?: Mailbox) {
		mailbox = m
			? {
					id: m.id, name: m.name, address: m.address, kind: m.kind, imap_host: m.imap_host, imap_port: m.imap_port, imap_security: m.imap_security,
					imap_username: m.imap_username, imap_password: '', has_password: m.has_password, imap_folder: m.imap_folder, board_id: m.board_id,
					auto_reply: m.auto_reply, enabled: m.enabled, graph_tenant: m.graph_tenant, graph_client_id: m.graph_client_id, graph_secret: '',
					has_graph_secret: m.has_graph_secret, graph_send: m.graph_send
				}
			: {
					id: null, name: '', address: '', kind: 'imap', imap_host: '', imap_port: 993, imap_security: 'tls', imap_username: '', imap_password: '',
					has_password: false, imap_folder: 'INBOX', board_id: boards.data?.[0]?.id ?? '', auto_reply: true, enabled: true,
					graph_tenant: '', graph_client_id: '', graph_secret: '', has_graph_secret: false, graph_send: true
				};
	}
	async function saveMailbox(e: SubmitEvent) {
		e.preventDefault();
		const m = mailbox!;
		saving = true;
		try {
			const { id, has_password: _h, has_graph_secret: _g, imap_password, graph_secret, ...rest } = m;
			const body = { ...rest, imap_port: Number(m.imap_port), ...(imap_password ? { imap_password } : {}), ...(graph_secret ? { graph_secret } : {}) };
			if (id) {
				await api.put(`/mailboxes/${id}`, body);
			} else {
				const created = await api.post<Mailbox>('/mailboxes', body);
				if (created.webhook_url) webhookUrl = { name: created.name, url: created.webhook_url };
			}
			toast.success(`${m.name} saved.`);
			mailbox = null;
			mailboxes.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
	async function poll(m: Mailbox) {
		polling = m.id;
		try {
			const r = await api.post<{ ok: boolean; filed?: number; error?: string }>(`/mailboxes/${m.id}/poll`);
			if (r.ok) toast.success(`${m.name}: connected, ${plural(r.filed ?? 0, 'new message')} filed.`);
			else toast.error(`${m.name}: ${r.error}`);
			mailboxes.reload();
			inbound.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			polling = null;
		}
	}
	async function rotate(m: Mailbox) {
		const ok = await confirmAction({ title: `New webhook URL for ${m.name}?`, message: 'The current URL stops working immediately; update it at your mail provider.', confirmLabel: 'Issue new URL' });
		if (!ok) return;
		await attempt(async () => {
			const r = await api.post<{ webhook_url: string }>(`/mailboxes/${m.id}/rotate-token`);
			webhookUrl = { name: m.name, url: r.webhook_url };
		});
	}
	async function removeMailbox(m: Mailbox) {
		const ok = await confirmAction({ title: `Delete ${m.name}?`, message: 'Mail to it stops becoming tickets. Existing tickets are kept.', confirmLabel: 'Delete mailbox', danger: true });
		if (ok && (await attempt(() => api.del(`/mailboxes/${m.id}`), `${m.name} deleted.`))) mailboxes.reload();
	}
</script>

<div class="max-w-4xl space-y-5">
	<section class="card" aria-labelledby="boards-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="boards-h" class="font-semibold">Boards</h2>
				<p class="text-muted text-xs">Queues for tickets, each with its own statuses. A status's category decides how it behaves.</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => editBoard()}>Add board</Button>
		</header>
		<Async res={boards} compact>
			{#snippet children(list)}
				<ul class="divide-border divide-y">
					{#each list as b (b.id)}
						<li class="flex flex-wrap items-center gap-x-3 gap-y-2 px-5 py-3 text-sm">
							<div class="min-w-0 flex-1">
								<div class="font-medium">{b.name} <span class="text-muted text-xs font-normal">· {plural(b.open_tickets, 'open ticket')}</span></div>
								<div class="mt-1 flex flex-wrap gap-1">
									{#each b.statuses as s (s.id)}<Badge tone={categoryOf(s.category).tone} title={categoryOf(s.category).label}>{s.name}</Badge>{/each}
								</div>
							</div>
							<IconButton icon={Pencil} size="sm" label="Edit {b.name}" onclick={() => editBoard(b)} />
							<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {b.name}" onclick={() => removeBoard(b)} />
						</li>
					{/each}
				</ul>
			{/snippet}
		</Async>
	</section>

	<Teams onchange={refreshMeta} />
	<Canned />
	<PortalSettings boards={boards.data ?? []} />

	<section class="card" aria-labelledby="types-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="types-h" class="font-semibold">Ticket types</h2>
				<p class="text-muted text-xs">Optional labels for reporting (incident, service request, …).</p>
			</div>
			<Button icon={Pencil} disabled={!meta.data} onclick={() => editTypes(meta.data!.types)}>Edit</Button>
		</header>
		<Async res={meta} compact>
			{#snippet children(m)}
				<div class="flex flex-wrap gap-1.5 px-5 py-3">
					{#each m.types as t (t.id)}<Badge>{t.name}</Badge>{:else}<span class="text-muted text-sm">None</span>{/each}
				</div>
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-labelledby="mb-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="mb-h" class="font-semibold">Support mailboxes</h2>
				<p class="text-muted text-xs">
					Mail to these addresses becomes tickets, and replies thread back onto them. Replies to clients are sent through the mail server under Notifications, with Reply-To set to the mailbox.
				</p>
			</div>
			<Button variant="primary" icon={Plus} disabled={!boards.data?.length} onclick={() => editMailbox()}>Add mailbox</Button>
		</header>
		<Async res={mailboxes} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as m (m.id)}
							<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
								{#if m.kind === 'webhook'}<Webhook class="text-muted size-4 shrink-0" aria-hidden="true" />{:else}<Mail class="text-muted size-4 shrink-0" aria-hidden="true" />{/if}
								<div class="min-w-0 flex-1">
									<div class="font-medium">{m.name} <span class="text-muted font-normal">{m.address}</span> {#if !m.enabled}<Badge>Disabled</Badge>{/if}</div>
									<div class="text-muted truncate text-xs">
										{m.kind === 'imap' ? `IMAP ${m.imap_host}:${m.imap_port}/${m.imap_folder}` : m.kind === 'graph' ? `Microsoft 365 (Graph)${m.graph_send ? ', sends replies' : ''}` : 'Provider webhook'} · into {m.board_name} · {plural(m.received_24h, 'message')} today{m.auto_reply ? ' · acknowledges new tickets' : ''}
										{#if m.last_polled_at}{` · checked ${ago(m.last_polled_at)}`}{/if}
									</div>
									{#if m.last_error}<div class="text-danger text-xs break-words">{m.last_error}</div>{/if}
								</div>
								{#if m.kind !== 'webhook'}
									<Button size="sm" icon={RefreshCw} loading={polling === m.id} onclick={() => poll(m)}>Check now</Button>
								{:else}
									<Button size="sm" icon={KeyRound} onclick={() => rotate(m)}>New URL</Button>
								{/if}
								<IconButton icon={Pencil} size="sm" label="Edit {m.name}" onclick={() => editMailbox(m)} />
								<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {m.name}" onclick={() => removeMailbox(m)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Inbox} title="No mailboxes yet" description="Connect a support address over IMAP, or point a mail provider's inbound webhook (Postmark, Mailgun, SES) at a webhook mailbox." />
				{/if}
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-labelledby="in-h">
		<header class="border-border flex items-center justify-between border-b px-5 py-3">
			<div>
				<h2 id="in-h" class="font-semibold">Recent inbound mail</h2>
				<p class="text-muted text-xs">Auto-replies, bulk mail, bounces and mail from our own addresses are recorded but never filed or answered.</p>
			</div>
			<Button size="sm" onclick={() => inbound.reload()}>Refresh</Button>
		</header>
		<Async res={inbound} compact>
			{#snippet children(rows)}
				{#if rows.length}
					<div class="overflow-x-auto">
						<table class="table">
							<thead><tr><th>When</th><th>From</th><th>Subject</th><th>Result</th></tr></thead>
							<tbody>
								{#each rows as r (r.id)}
									<tr>
										<td class="whitespace-nowrap" title={datetime(r.created_at)}>{ago(r.created_at)}</td>
										<td class="max-w-48 truncate">{r.from_addr || '–'}</td>
										<td class="max-w-xs truncate">{r.subject || '(no subject)'}</td>
										<td>
											{#if r.status === 'ignored'}<Badge>Ignored: {r.ignored_reason}</Badge>
											{:else if r.ticket_id}<a class="link" href="/tickets/{r.ticket_id}">{ticketNumber(r.ticket_number ?? 0)}</a>
											{:else}<Badge tone="success">Received</Badge>{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else}
					<EmptyState compact title="Nothing received yet" />
				{/if}
			{/snippet}
		</Async>
	</section>
</div>

{#if board}
	<Modal title={board.id ? `Edit ${board.name}` : 'Add board'} onclose={() => (board = null)} size="lg">
		<form id="board-form" class="space-y-4" onsubmit={saveBoard}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="bd-name" required><Input id="bd-name" bind:value={board.name} required maxlength={100} /></Field>
				<Field label="Description" id="bd-desc"><Input id="bd-desc" bind:value={board.description} maxlength={300} /></Field>
			</div>
			<fieldset>
				<legend class="label">Statuses, in workflow order</legend>
				<ol class="space-y-2">
					{#each board.statuses as s, i (s.id ?? i)}
						<li class="flex items-center gap-2">
							<Input aria-label="Status name" class="min-w-0 flex-1" bind:value={s.name} required maxlength={60} />
							<Select aria-label="Category of {s.name}" class="w-44" bind:value={s.category} options={categories.map((c) => ({ value: c.value, label: c.label }))} />
							<IconButton icon={ArrowUp} size="sm" label="Move {s.name} up" disabled={i === 0} onclick={() => move(i, -1)} />
							<IconButton icon={ArrowDown} size="sm" label="Move {s.name} down" disabled={i === board.statuses.length - 1} onclick={() => move(i, 1)} />
							<IconButton icon={X} size="sm" label="Remove {s.name}" disabled={board.statuses.length === 1} onclick={() => board!.statuses.splice(i, 1)} />
						</li>
					{/each}
				</ol>
				<Button size="sm" variant="ghost" icon={Plus} class="mt-2" onclick={() => board!.statuses.push({ name: '', category: 'open' })}>Add status</Button>
				{#if missing.length}<p class="text-danger mt-2 text-xs" role="alert">A board needs a status in each of: {missing.map((c) => categoryOf(c).label).join(', ')}.</p>{/if}
				<dl class="text-muted mt-3 grid gap-x-3 gap-y-1 text-xs sm:grid-cols-[9rem_1fr]">
					{#each categories as c (c.value)}<dt class="font-medium">{c.label}</dt><dd>{c.hint}</dd>{/each}
				</dl>
			</fieldset>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="New tickets go to team" id="bd-team">
					<Select id="bd-team" class="w-full" bind:value={board.default_team_id} options={[{ value: '', label: 'No team' }, ...(meta.data?.teams ?? []).map((t) => ({ value: t.id, label: t.name }))]} />
				</Field>
				<fieldset>
					<legend class="label">Announce new tickets on</legend>
					{#if channels.data?.length}
						<div class="space-y-1.5">
							{#each channels.data as c (c.id)}
								<Checkbox
									checked={board.notify_channel_ids.includes(c.id)}
									onchange={(on: boolean) => (board!.notify_channel_ids = on ? [...board!.notify_channel_ids, c.id] : board!.notify_channel_ids.filter((x) => x !== c.id))}
								>{c.name}</Checkbox>
							{/each}
						</div>
					{:else}
						<p class="hint">No notification channels yet (Company settings → Notifications).</p>
					{/if}
				</fieldset>
			</div>
		</form>
		{#snippet footer()}
			<Button onclick={() => (board = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="board-form" loading={saving} disabled={!!missing.length}>Save board</Button>
		{/snippet}
	</Modal>
{/if}

{#if types}
	<Modal title="Ticket types" onclose={() => (types = null)} size="sm">
		<form id="types-form" class="space-y-2" onsubmit={saveTypes}>
			{#each types as t, i (t.id ?? i)}
				<div class="flex items-center gap-2">
					<Input aria-label="Type name" class="min-w-0 flex-1" bind:value={t.name} maxlength={60} />
					<IconButton icon={X} size="sm" label="Remove {t.name}" onclick={() => types!.splice(i, 1)} />
				</div>
			{/each}
			<Button size="sm" variant="ghost" icon={Plus} onclick={() => types!.push({ name: '' })}>Add type</Button>
			<p class="hint">Removing a type leaves its tickets without one.</p>
		</form>
		{#snippet footer()}
			<Button onclick={() => (types = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="types-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if mailbox}
	<Modal title={mailbox.id ? `Edit ${mailbox.name}` : 'Add mailbox'} onclose={() => (mailbox = null)} size="lg">
		<form id="mailbox-form" class="space-y-4" onsubmit={saveMailbox}>
			<div class="grid gap-3 sm:grid-cols-3">
				<Field label="Name" id="mb-name" required><Input id="mb-name" bind:value={mailbox.name} required maxlength={100} placeholder="Support" /></Field>
				<Field label="Address" id="mb-addr" required hint="Clients write to this; replies come from it."><Input id="mb-addr" type="email" bind:value={mailbox.address} required placeholder="support@example.com" /></Field>
				<Field label="Receive by" id="mb-kind">
					<Select id="mb-kind" class="w-full" bind:value={mailbox.kind} disabled={!!mailbox.id} options={[{ value: 'imap', label: 'IMAP' }, { value: 'graph', label: 'Microsoft 365' }, { value: 'webhook', label: 'Provider webhook' }]} />
				</Field>
			</div>
			{#if mailbox.kind === 'imap'}
				<div class="grid gap-3 sm:grid-cols-[1fr_6rem_8rem]">
					<Field label="IMAP host" id="mb-host" required><Input id="mb-host" bind:value={mailbox.imap_host} required placeholder="imap.example.com" autocomplete="off" /></Field>
					<Field label="Port" id="mb-port"><Input id="mb-port" type="number" min="1" max="65535" bind:value={mailbox.imap_port} /></Field>
					<Field label="Security" id="mb-sec">
						<Select id="mb-sec" class="w-full" bind:value={mailbox.imap_security} onchange={() => mailbox && (mailbox.imap_port = mailbox.imap_security === 'tls' ? 993 : 143)} options={[{ value: 'tls', label: 'TLS' }, { value: 'none', label: 'None' }]} />
					</Field>
				</div>
				<div class="grid gap-3 sm:grid-cols-3">
					<Field label="Username" id="mb-user" required><Input id="mb-user" bind:value={mailbox.imap_username} required autocomplete="off" /></Field>
					<Field label="Password" id="mb-pass" hint={mailbox.has_password ? 'Saved. Leave empty to keep it.' : 'An app password where the provider offers one.'}>
						<Input id="mb-pass" type="password" bind:value={mailbox.imap_password} autocomplete="new-password" placeholder={mailbox.has_password ? '••••••••' : ''} />
					</Field>
					<Field label="Folder" id="mb-folder"><Input id="mb-folder" bind:value={mailbox.imap_folder} /></Field>
				</div>
				<p class="hint -mt-2">Unread messages are filed every minute and marked read. For Microsoft 365, choose Microsoft 365 instead: it doesn't need IMAP.</p>
			{:else if mailbox.kind === 'graph'}
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Tenant (directory) ID" id="mb-tenant" required><Input id="mb-tenant" bind:value={mailbox.graph_tenant} required autocomplete="off" placeholder="00000000-0000-…" /></Field>
					<Field label="Application (client) ID" id="mb-client" required><Input id="mb-client" bind:value={mailbox.graph_client_id} required autocomplete="off" /></Field>
					<Field label="Client secret" id="mb-secret" required={!mailbox.has_graph_secret} hint={mailbox.has_graph_secret ? 'Saved (encrypted). Leave empty to keep it.' : 'Stored encrypted when RMM_DATA_KEY is set.'}>
						<Input id="mb-secret" type="password" bind:value={mailbox.graph_secret} autocomplete="new-password" placeholder={mailbox.has_graph_secret ? '••••••••' : ''} />
					</Field>
					<Field label="Folder" id="mb-gfolder" hint="INBOX, or a folder ID."><Input id="mb-gfolder" bind:value={mailbox.imap_folder} /></Field>
				</div>
				<p class="hint -mt-2">
					Register an app in Entra ID with the Mail.ReadWrite and Mail.Send application permissions (admin consent), and limit it to this mailbox with an application access policy.
					Unread messages are filed every minute and marked read.
				</p>
				<Switch bind:checked={mailbox.graph_send}>Send replies from this mailbox through Microsoft 365</Switch>
			{:else}
				<p class="hint">After saving you get a secret URL. Point your provider's inbound webhook at it: raw MIME (message/rfc822), Postmark JSON with “Include raw email content”, or a Mailgun route to the <code>mime</code> URL.</p>
			{/if}
			<Field label="File new tickets on" id="mb-board">
				<Select id="mb-board" class="w-full sm:w-64" bind:value={mailbox.board_id} options={(boards.data ?? []).map((b) => ({ value: b.id, label: b.name }))} />
			</Field>
			<div class="space-y-2">
				<Switch bind:checked={mailbox.auto_reply}>Acknowledge new tickets by email</Switch>
				<p class="hint pl-11.5">At most three per sender per hour; never to auto-replies or bulk mail.</p>
				<Switch bind:checked={mailbox.enabled}>Enabled</Switch>
			</div>
		</form>
		{#snippet footer()}
			<Button onclick={() => (mailbox = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="mailbox-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if webhookUrl}
	<Modal title="Webhook URL for {webhookUrl.name}" description="Copy it now: it isn't shown again. Anyone with it can create tickets." onclose={() => (webhookUrl = null)}>
		<CodeBlock code={webhookUrl.url} label="POST raw messages here" />
		{#snippet footer()}<Button variant="primary" onclick={() => (webhookUrl = null)}>Done</Button>{/snippet}
	</Modal>
{/if}
