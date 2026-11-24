<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		ArrowRightLeft,
		BellRing,
		Copy,
		MonitorSmartphone,
		ExternalLink,
		FileText,
		GitMerge,
		Link2,
		Mail,
		MonitorUp,
		Paperclip,
		Play,
		Scissors,
		Send,
		Smile,
		Frown,
		Timer,
		Clock,
		SquareTerminal,
		StickyNote,
		Unlink,
		UserCheck
	} from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, cx, datetime, oversized, pct } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { categoryOf, levels, priorities, priorityOf, sourceLabels, ticketMeta, ticketNumber } from '#lib/servicedesk/tickets.svelte.js';
	import { can, company, session } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, CannedResponse, Contact, Page, Priority, StatusCategory, Ticket, TicketAgent, TicketAttachment, TicketDetail, TicketDoc, TicketEvent, TicketMeta } from '#lib/types.js';
	import { agentLoader, docContext, docPageHref } from '#lib/docs/context.js';
	import type { DocDetail, DocRow } from '#lib/docs/types.js';
	import { targetLabels, until } from '#lib/servicedesk/sla.js';
	import SlaBadge from '#lib/components/ticket/SlaBadge.svelte';
	import TicketTime from '#lib/components/work/TicketTime.svelte';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import DocCredentials from '#lib/components/docs/DocCredentials.svelte';
	import DocView from '#lib/components/docs/DocView.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import RunScript from '#lib/components/RunScript.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import Status from '#lib/components/Status.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import PriorityBadge from '#lib/components/ticket/PriorityBadge.svelte';
	import TicketStatus from '#lib/components/ticket/TicketStatus.svelte';

	const id = $derived(page.params.id!);
	const res = resource(() => api.get<TicketDetail>(`/tickets/${id}`), { keep: false });
	liveReload(
		() => res.reload(),
		(e) => (e.type === 'ticket' && e.id === id) || ((e.type === 'agent' || e.type === 'alert') && !!res.data?.agents.some((a) => a.id === (e.type === 'agent' ? e.id : e.agent_id)) && !(e.type === 'agent' && e.last_metrics)),
		{ debounceMs: 600 }
	);

	let meta = $state<TicketMeta | null>(null);
	$effect(() => {
		loadClients();
		ticketMeta().then((m) => (meta = m));
	});
	const tech = $derived(can('technician'));

	// --- properties ---------------------------------------------------------------------------
	let contacts = $state<Contact[]>([]);
	let clientAgents = $state<AgentSummary[]>([]);
	let clientDocs = $state<DocRow[]>([]);
	$effect(() => {
		const c = res.data?.client_id;
		contacts = [];
		clientAgents = [];
		clientDocs = [];
		if (!c || !tech) return;
		api.get<Contact[]>(`/contacts?client_id=${c}`).then((l) => res.data?.client_id === c && (contacts = l));
		api.get<Page<AgentSummary>>(`/agents?client_id=${c}&limit=500&sort=hostname`).then((p) => res.data?.client_id === c && (clientAgents = p.items));
		api.get<DocRow[]>(`/clients/${c}/docs`).then((l) => res.data?.client_id === c && (clientDocs = l));
	});

	const canned = resource(() => (can('technician') ? api.get<CannedResponse[]>('/canned-responses') : Promise.resolve([])));

	async function patch(body: Record<string, unknown>, done?: string) {
		if (await attempt(() => api.patch(`/tickets/${id}`, body), done)) await res.reload();
	}

	// --- composer -----------------------------------------------------------------------------
	let mode = $state<'reply' | 'note'>('reply');
	let body = $state('');
	let thenStatus = $state('');
	let files = $state<TicketAttachment[]>([]);
	let uploading = $state(false);
	let sending = $state(false);
	let fileInput = $state<HTMLInputElement | null>(null);
	/** A macro's other actions, applied when the message goes out. */
	let macro = $state<{ priority: Priority | null; assign: 'me' | 'none' | null } | null>(null);

	async function insertCanned(cid: string) {
		if (!cid) return;
		try {
			const r = await api.get<{ body: string; kind: 'reply' | 'note'; status_category: StatusCategory | null; priority: Priority | null; assign: 'me' | 'none' | null }>(
				`/tickets/${id}/canned/${cid}`
			);
			mode = r.kind;
			body = body.trim() ? `${body.trimEnd()}\n\n${r.body}` : r.body;
			const st = r.status_category && res.data?.statuses.find((x) => x.category === r.status_category && x.id !== res.data?.status_id);
			if (st) thenStatus = st.id;
			macro = r.priority || r.assign ? { priority: r.priority, assign: r.assign } : null;
		} catch (err) {
			toast.error(err);
		}
	}

	async function upload(list: FileList | null) {
		if (!list?.length) return;
		// Checked here too, so a large file isn't sent only to be refused at the end.
		const tooBig = oversized(list, company.attachmentMaxMb);
		if (tooBig) {
			toast.error(tooBig);
			if (fileInput) fileInput.value = '';
			return;
		}
		uploading = true;
		try {
			const form = new FormData();
			for (const f of list) form.append('file', f);
			const r = await fetch(`/api/tickets/${id}/attachments`, { method: 'POST', body: form, credentials: 'same-origin' });
			const data = await r.json().catch(() => null);
			if (!r.ok) throw new Error(data?.error ?? (r.status === 413 ? `files are limited to ${company.attachmentMaxMb ?? 100} MB each` : r.statusText));
			files = [...files, ...(data as TicketAttachment[])];
		} catch (err) {
			toast.error(err);
		} finally {
			uploading = false;
			if (fileInput) fileInput.value = '';
		}
	}

	async function send(e?: Event) {
		e?.preventDefault();
		if (!body.trim() && !files.length) return;
		sending = true;
		try {
			const r = await api.post<{ emailed: boolean }>(`/tickets/${id}/events`, {
				kind: mode,
				body,
				attachment_ids: files.map((f) => f.id),
				status_id: thenStatus || null
			});
			body = '';
			files = [];
			thenStatus = '';
			if (macro) {
				const m = macro;
				macro = null;
				await api.patch(`/tickets/${id}`, {
					...(m.priority ? { priority: m.priority } : {}),
					...(m.assign ? { assignee_id: m.assign === 'me' ? session.user!.id : null } : {})
				});
			}
			toast.success(mode === 'note' ? 'Note added.' : r.emailed ? 'Reply sent.' : 'Reply added (not emailed: no address).');
			await res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			sending = false;
		}
	}

	// --- agents -------------------------------------------------------------------------------
	let running = $state<TicketAgent | null>(null);
	async function linkAgent(agentId: string) {
		if (agentId && (await attempt(() => api.post(`/tickets/${id}/agents`, { agent_id: agentId })))) res.reload();
	}
	async function unlinkAgent(a: TicketAgent) {
		if (await attempt(() => api.del(`/tickets/${id}/agents/${a.id}`), `${a.hostname} unlinked.`)) res.reload();
	}

	// --- documentation -----------------------------------------------------------------------
	async function linkDoc(docId: string) {
		if (docId && (await attempt(() => api.post(`/tickets/${id}/docs`, { doc_id: docId })))) res.reload();
	}
	async function unlinkDoc(d: TicketDoc) {
		if (await attempt(() => api.del(`/tickets/${id}/docs/${d.id}`), `${d.title} unlinked.`)) res.reload();
	}
	/** The page open in the drawer, read without leaving the ticket. */
	let peek = $state<string | null>(null);
	const peekDoc = resource(() => (peek ? api.get<DocDetail>(`/docs/${peek}`) : Promise.resolve(null)), { keep: false });
	const docAgents = new Map<string, ReturnType<typeof agentLoader>>();
	function agentsOf(clientId: string) {
		let l = docAgents.get(clientId);
		if (!l) docAgents.set(clientId, (l = agentLoader(clientId)));
		return l;
	}
	function openPeek(e: MouseEvent, docId: string) {
		if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button) return;
		e.preventDefault();
		peek = docId;
	}

	// --- merge --------------------------------------------------------------------------------
	let merging = $state(false);
	let mergeQuery = $state('');
	let mergeHits = $state<Ticket[]>([]);
	$effect(() => {
		const q = mergeQuery.trim();
		if (!merging || !q) {
			mergeHits = [];
			return;
		}
		const t = setTimeout(() => {
			api.get<Page<Ticket>>(`/tickets?view=all&limit=8&q=${encodeURIComponent(q)}`).then((p) => (mergeHits = p.items.filter((x) => x.id !== id && !x.merged_into)));
		}, 200);
		return () => clearTimeout(t);
	});
	async function mergeInto(t: Ticket) {
		const cur = res.data!;
		const ok = await confirmAction({
			title: `Merge ${ticketNumber(cur.number)} into ${ticketNumber(t.number)}?`,
			message: `Its timeline, attachments, agents, linked pages and email thread move to ${ticketNumber(t.number)} (“${t.subject}”), and this ticket is closed. This can't be undone.`,
			confirmLabel: 'Merge'
		});
		if (ok && (await attempt(() => api.post(`/tickets/${id}/merge`, { into: t.id }), `Merged into ${ticketNumber(t.number)}.`))) {
			merging = false;
			await goto(`/tickets/${t.id}`);
		}
	}

	// --- split ---------------------------------------------------------------------------------
	async function splitOff(e: TicketEvent) {
		const ok = await confirmAction({
			title: 'Split into a new ticket?',
			message: 'This entry becomes the request of a new ticket for the same client and contact, and its attachments move with it.',
			confirmLabel: 'Split'
		});
		if (!ok) return;
		try {
			const n = await api.post<Ticket>(`/tickets/${id}/split`, { event_id: e.id });
			toast.success(`Split into ${ticketNumber(n.number)}.`);
			await goto(`/tickets/${n.id}`);
		} catch (err) {
			toast.error(err);
		}
	}

	// --- timeline -----------------------------------------------------------------------------
	const fieldLabels: Record<string, string> = {
		status: 'status', subject: 'subject', priority: 'priority', assignee: 'assignee', client: 'client', site: 'site',
		contact: 'contact', board: 'board', type: 'type', team: 'team'
	};
	function changeText(e: TicketEvent): string {
		const d = e.data as { field: string; from: unknown; to: unknown };
		const show = (v: unknown) => (v === null || v === undefined || v === '' ? 'none' : d.field === 'priority' ? priorityOf(v as 1).short : String(v));
		if (d.field === 'assignee') return d.to ? `assigned it to ${d.to}` : `unassigned ${d.from ?? ''}`.trim();
		return `changed the ${fieldLabels[d.field] ?? d.field} from ${show(d.from)} to ${show(d.to)}`;
	}
	const conversational = (k: string) => k === 'created' || k === 'reply' || k === 'message' || k === 'note';
	function attachmentsOf(t: TicketDetail, ev: TicketEvent) {
		return t.attachments.filter((a) => a.event_id === ev.id);
	}
	const isImage = (a: TicketAttachment) => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(a.content_type);
	const href = (a: TicketAttachment, inline = false) => `/api/tickets/${id}/attachments/${a.id}${inline ? '?inline=1' : ''}`;

	function keydown(e: KeyboardEvent) {
		if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') send(e);
	}
</script>

<svelte:head>{#if res.data}<title>{ticketNumber(res.data.number)} {res.data.subject}</title>{/if}</svelte:head>

<Async {res}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-96" /></div>
		<div class="grid gap-4 lg:grid-cols-[1fr_20rem]"><div class="card space-y-3 p-4"><Skeleton lines={8} /></div><div class="card p-4"><Skeleton lines={10} /></div></div>
	{/snippet}
	{#snippet children(t)}
		{@const statusCat = categoryOf(t.status_category)}
		{@const techs = (meta?.technicians ?? []).filter((x) => !x.client_ids || (t.client_id && x.client_ids.includes(t.client_id)))}
		<PageHeader
			title={t.subject}
			crumbs={[{ label: 'Tickets', href: '/tickets' }, ...(t.client_id ? [{ label: t.client_name ?? '', href: `/clients/${t.client_id}?tab=tickets` }] : [{ label: 'Triage', href: '/tickets?view=triage' }]), { label: ticketNumber(t.number) }]}
			menu={[
				{ label: 'Copy ticket number', icon: Copy, onSelect: () => navigator.clipboard?.writeText(ticketNumber(t.number)).then(() => toast.success('Copied.')) },
				...(tech && !t.merged_into ? [{ label: 'Merge into another ticket…', icon: GitMerge, onSelect: () => ((merging = true), (mergeQuery = '')) }] : [])
			]}
		>
			{#snippet subtitle()}
				<span class="font-mono text-xs">{ticketNumber(t.number)}</span>
				<TicketStatus name={t.status_name} category={t.status_category} />
				<PriorityBadge priority={t.priority} long />
				{#if t.client_name}<span>{t.client_name}{#if t.contact_name}{' · '}{t.contact_name}{/if}</span>{:else}<Badge tone="warning">Triage</Badge>{/if}
				{#if t.source === 'agent'}<Badge icon={MonitorSmartphone} title="Asked for through the tray app on the linked device">From device</Badge>{/if}
			{/snippet}
			{#snippet actions()}
				{#if tech && !t.merged_into}
					{#if t.assignee_id !== session.user?.id}<Button icon={UserCheck} onclick={() => patch({ assignee_id: session.user!.id }, 'Assigned to you.')}>Assign to me</Button>{/if}
					<Select aria-label="Status" class="w-44" value={t.status_id} onchange={(e) => patch({ status_id: e.currentTarget.value })} options={t.statuses.map((s) => ({ value: s.id, label: s.name }))} />
				{/if}
			{/snippet}
		</PageHeader>

		{#if t.merged_into}
			<p class="border-border bg-sunken mb-4 rounded-md border px-3 py-2 text-sm">
				Merged into <a class="link" href="/tickets/{t.merged_into}">{ticketNumber(t.merged_into_number ?? 0)}</a>; its history continues there.
			</p>
		{:else if !t.client_id}
			<p class="border-warning/40 bg-warning-soft text-warning mb-4 rounded-md border px-3 py-2 text-sm">
				From an unknown sender ({t.requester_email || 'no address'}). Choose a client to file it; add them as a contact so their next mail is filed automatically.
			</p>
		{/if}

		<div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_21rem]">
			<!-- Timeline and composer -->
			<div class="min-w-0 space-y-4">
				<ol class="space-y-3" aria-label="Timeline">
					{#each t.events as e (e.id)}
						<li>
							{#if conversational(e.kind)}
								<article
									class={cx(
										'card overflow-hidden',
										e.kind === 'note' && 'border-warning/40 bg-warning-soft/40',
										e.kind === 'reply' && 'border-accent/30'
									)}
									aria-label="{e.kind === 'note' ? 'Internal note' : e.kind === 'reply' ? 'Reply' : 'Message'} from {e.author_name}"
								>
									<header class="flex flex-wrap items-center gap-x-2 gap-y-1 px-4 pt-3 text-sm">
										<span class="font-medium">{e.author_name}</span>
										<span class="text-muted text-xs">
											{#if e.kind === 'created'}opened the ticket{t.source !== 'dashboard' ? ` via ${sourceLabels[t.source]?.toLowerCase()}` : ''}{:else if e.kind === 'message'}wrote{#if e.data.from}{' by email'}{/if}{:else if e.kind === 'reply'}replied{:else}added an internal note{/if}
										</span>
										{#if e.kind === 'note'}<Badge tone="warning" icon={StickyNote}>Internal</Badge>{/if}
										<time class="text-muted ml-auto text-xs" datetime={e.created_at} title={datetime(e.created_at)}>{ago(e.created_at)}</time>
										{#if tech && !t.merged_into && e.kind !== 'created'}
											<IconButton size="sm" icon={Scissors} label="Split into a new ticket" onclick={() => splitOff(e)} class="-my-1 -mr-2" />
										{/if}
									</header>
									{#if e.body}<div class="px-4 py-2 text-sm break-words whitespace-pre-wrap">{e.body}</div>{:else if e.kind === 'created'}<p class="text-muted px-4 py-2 text-sm">No description.</p>{/if}
									{#if attachmentsOf(t, e).length}
										<ul class="flex flex-wrap gap-2 px-4 pb-3">
											{#each attachmentsOf(t, e) as a (a.id)}
												<li>
													{#if isImage(a)}
														<a href={href(a, true)} target="_blank" rel="noopener" class="border-border block overflow-hidden rounded-md border"><img src={href(a, true)} alt={a.name} class="h-24 max-w-48 object-cover" loading="lazy" /></a>
													{:else}
														<a href={href(a)} class="border-border hover:bg-hover inline-flex h-8 items-center gap-1.5 rounded-md border px-2 text-xs"><Paperclip class="size-3.5" />{a.name} <span class="text-muted">{bytes(a.size)}</span></a>
													{/if}
												</li>
											{/each}
										</ul>
									{/if}
									{#if e.kind === 'reply'}
										<footer class="text-muted border-border flex flex-wrap items-center gap-2 border-t px-4 py-1.5 text-xs">
											<Mail class="size-3.5" aria-hidden="true" />
											{#if e.email_status}
												Emailed to {e.email_to?.join(', ')}:
												<Badge tone={e.email_status === 'sent' ? 'success' : e.email_status === 'failed' ? 'danger' : 'neutral'}>{e.email_status === 'sent' ? 'Sent' : e.email_status === 'failed' ? 'Not sent' : 'Sending'}</Badge>
												{#if e.email_error && e.email_status !== 'sent'}<span class="text-danger">{e.email_error}</span>{/if}
											{:else}
												Not emailed: the ticket has no contact address.
											{/if}
										</footer>
									{/if}
								</article>
							{:else}
								<div class="text-muted flex items-start gap-2 px-1 text-sm [&>svg]:mt-[3px] [&>span]:min-w-0 [&>span]:flex-1">
									{#if e.kind === 'change'}
										<ArrowRightLeft class="size-3.5 shrink-0" aria-hidden="true" />
										<span><span class="text-fg">{e.author_name}</span> {changeText(e)}</span>
									{:else if e.kind === 'alert'}
										<BellRing class="size-3.5 shrink-0" aria-hidden="true" />
										<span>
											{#if e.body}<span class="break-words whitespace-pre-wrap">{e.body.split('\n')[0]}</span>{:else}Opened by an alert.{/if}
											{#if e.data.alert_id}<a class="link ml-1" href="/alerts/{e.data.alert_id}">View alert</a>{/if}
										</span>
									{:else if e.kind === 'job'}
										<Play class="size-3.5 shrink-0" aria-hidden="true" />
										{#if e.data.status === 'started'}
											<span><span class="text-fg">{e.author_name}</span> ran {e.data.script ?? 'an ad-hoc script'} on {e.data.hostname}. <a class="link" href="/jobs/{e.data.job_id}">View job</a></span>
										{:else}
											<span>
											<details>
												<summary class="cursor-pointer">
													{e.data.script ?? 'Ad-hoc script'} on {e.data.hostname} finished <JobBadge status={e.data.status as never} />
													{#if e.data.exit_code !== null && e.data.exit_code !== undefined}<span class="text-xs">exit {e.data.exit_code}</span>{/if}
												</summary>
												{#if e.body}<pre class="code-block mt-2 max-h-72 text-xs">{e.body}</pre>{:else}<p class="mt-1 text-xs">No output.</p>{/if}
											</details>
											<a class="link inline-flex h-6 items-center" href="/jobs/{e.data.job_id}">View job</a>
											</span>
										{/if}
									{:else if e.kind === 'session'}
										{#if e.data.kind === 'desktop'}<MonitorUp class="size-3.5 shrink-0" aria-hidden="true" />{:else}<SquareTerminal class="size-3.5 shrink-0" aria-hidden="true" />{/if}
										<span><span class="text-fg">{e.author_name}</span>: {e.body}</span>
									{:else if e.kind === 'merge'}
										<GitMerge class="size-3.5 shrink-0" aria-hidden="true" />
										{#if e.data.into}
											<span><span class="text-fg">{e.author_name}</span> merged this into <a class="link" href="/tickets/{e.data.into}">{ticketNumber(e.data.into_number as number)}</a></span>
										{:else}
											<span><span class="text-fg">{e.author_name}</span> merged in <a class="link" href="/tickets/{e.data.from}">{ticketNumber(e.data.from_number as number)}</a> ({e.data.subject})</span>
										{/if}
									{:else if e.kind === 'agent'}
										<Link2 class="size-3.5 shrink-0" aria-hidden="true" />
										<span><span class="text-fg">{e.author_name}</span> {e.data.linked ? 'linked' : 'unlinked'} {e.data.hostname ?? 'an agent'}</span>
									{:else if e.kind === 'doc'}
										<FileText class="size-3.5 shrink-0" aria-hidden="true" />
										<span><span class="text-fg">{e.author_name}</span> {e.data.linked ? 'linked' : 'unlinked'} {e.data.title ?? 'a page'}</span>
									{:else if e.kind === 'sla'}
										<Timer class={cx('size-3.5 shrink-0', e.data.event === 'sla_breach' ? 'text-danger' : 'text-warning')} aria-hidden="true" />
										<span class={e.data.event === 'sla_breach' ? 'text-danger' : ''}>{e.body}</span>
									{:else if e.kind === 'split'}
										<Scissors class="size-3.5 shrink-0" aria-hidden="true" />
										{#if e.data.to}
											<span><span class="text-fg">{e.author_name}</span> split an entry off into <a class="link" href="/tickets/{e.data.to}">{ticketNumber(e.data.to_number as number)}</a></span>
										{:else}
											<span><span class="text-fg">{e.author_name}</span> split this off <a class="link" href="/tickets/{e.data.from}">{ticketNumber(e.data.from_number as number)}</a></span>
										{/if}
									{:else if e.kind === 'time'}
										<Clock class="size-3.5 shrink-0" aria-hidden="true" />
										<span><span class="text-fg">{e.author_name}</span> logged {Math.floor(Number(e.data.minutes) / 60) ? `${Math.floor(Number(e.data.minutes) / 60)} h ` : ''}{Number(e.data.minutes) % 60 ? `${Number(e.data.minutes) % 60} min` : ''} of {e.data.work_type}{e.data.billable ? '' : ' (not billable)'}{#if e.body}: <span class="break-words whitespace-pre-wrap">{e.body}</span>{/if}</span>
									{:else if e.kind === 'csat'}
										{#if e.data.rating === 'good'}<Smile class="text-success size-3.5 shrink-0" aria-hidden="true" />{:else}<Frown class="text-danger size-3.5 shrink-0" aria-hidden="true" />{/if}
										<span><span class="text-fg">{e.author_name}</span> rated the service <strong>{e.data.rating === 'good' ? 'good' : 'bad'}</strong>{#if e.body.includes('\n\n')}: “{e.body.split('\n\n').slice(1).join('\n\n')}”{/if}</span>
									{/if}
									<time class="shrink-0 pt-px text-xs" datetime={e.created_at} title={datetime(e.created_at)}>{ago(e.created_at)}</time>
								</div>
							{/if}
						</li>
					{/each}
				</ol>

				{#if tech && !t.merged_into}
					<form class="card space-y-3 p-4" onsubmit={send} aria-label="Reply or add a note">
						<div class="flex flex-wrap items-center justify-between gap-2">
							<div class="flex flex-wrap items-center gap-2">
								<Segmented label="Kind" value={mode} onchange={(v) => (mode = v)} options={[{ value: 'reply', label: 'Reply' }, { value: 'note', label: 'Internal note' }]} />
								{#if canned.data?.length}
									<Select
										aria-label="Insert a canned response"
										class="h-8 w-auto"
										value=""
										onchange={(e) => {
											insertCanned(e.currentTarget.value);
											e.currentTarget.value = '';
										}}
										options={[{ value: '', label: 'Insert response…' }, ...canned.data.map((c) => ({ value: c.id, label: c.name }))]}
									/>
								{/if}
							</div>
							<span class="text-muted text-xs">
								{#if mode === 'reply'}{#if t.reply_to}Emailed to {t.reply_to}{:else}<span class="text-warning">No address: recorded, not emailed</span>{/if}{:else}Only your team sees notes{/if}
							</span>
						</div>
						<Textarea
							aria-label={mode === 'reply' ? 'Reply' : 'Note'}
							rows={5}
							bind:value={body}
							onkeydown={keydown}
							placeholder={mode === 'reply' ? `Reply to ${t.contact_name ?? (t.requester_name || 'the client')}…` : 'Notes for your team…'}
							class={cx(mode === 'note' && 'bg-warning-soft/30')}
						/>
						{#if files.length}
							<ul class="flex flex-wrap gap-1.5">
								{#each files as f (f.id)}
									<li class="bg-sunken border-border inline-flex h-7 items-center gap-1 rounded-md border pr-1 pl-2 text-xs">
										<Paperclip class="size-3.5" />{f.name}
										<button type="button" class="text-muted hover:text-fg rounded px-1" aria-label="Don't attach {f.name}" onclick={() => (files = files.filter((x) => x.id !== f.id))}>×</button>
									</li>
								{/each}
							</ul>
						{/if}
						<div class="flex flex-wrap items-center gap-2">
							<input bind:this={fileInput} type="file" multiple class="sr-only" id="ticket-files" aria-label="Attach files" tabindex="-1" onchange={(e) => upload(e.currentTarget.files)} />
							<Button size="sm" variant="ghost" icon={Paperclip} loading={uploading} onclick={() => fileInput?.click()}>Attach</Button>
							<div class="ml-auto flex flex-wrap items-center gap-2">
								<Select
									aria-label="Then set status"
									class="h-8 w-auto"
									bind:value={thenStatus}
									options={[{ value: '', label: 'Keep status' }, ...t.statuses.filter((s) => s.id !== t.status_id).map((s) => ({ value: s.id, label: `and set ${s.name}` }))]}
								/>
								<Button variant="primary" type="submit" icon={mode === 'reply' ? Send : StickyNote} loading={sending} disabled={!body.trim() && !files.length} title="Ctrl+Enter">
									{mode === 'reply' ? 'Send reply' : 'Add note'}
								</Button>
							</div>
						</div>
					</form>
				{/if}
			</div>

			<!-- Sidebar -->
			<aside class="space-y-4" aria-label="Ticket details">
				<section class="card p-4" aria-labelledby="props-h">
					<h2 id="props-h" class="mb-3 panel-title">Details</h2>
					{#if tech && !t.merged_into}
						<div class="space-y-3">
							<Field label="Client" id="tp-client">
								{#key `${clients.list.length}:${t.client_id}`}
								<Combobox
									id="tp-client"
									value={t.client_id ?? ''}
									clearable={session.user?.client_ids === null}
									placeholder="Choose a client…"
									items={clients.list.map((c) => ({ value: c.id, label: c.name }))}
									onchange={(v) => v !== (t.client_id ?? '') && patch({ client_id: v || null })}
								/>
								{/key}
							</Field>
							<Field label="Contact" id="tp-contact">
								<Select
									id="tp-contact"
									class="w-full"
									value={t.contact_id ?? ''}
									disabled={!t.client_id}
									onchange={(e) => patch({ contact_id: e.currentTarget.value || null })}
									options={[{ value: '', label: 'No contact' }, ...contacts.map((c) => ({ value: c.id, label: c.name }))]}
								/>
							</Field>
							<div class="grid grid-cols-2 gap-3">
								<Field label="Priority" id="tp-priority">
									<Select id="tp-priority" class="w-full" value={t.priority} onchange={(e) => patch({ priority: Number(e.currentTarget.value) })} options={priorities.map((p) => ({ value: p.value, label: p.label }))} />
								</Field>
								<Field label="Assignee" id="tp-assignee">
									<Select id="tp-assignee" class="w-full" value={t.assignee_id ?? ''} onchange={(e) => patch({ assignee_id: e.currentTarget.value || null })} options={[{ value: '', label: 'Unassigned' }, ...techs.map((x) => ({ value: x.id, label: x.name }))]} />
								</Field>
								<Field label="Impact" id="tp-impact">
									<Select id="tp-impact" class="w-full" value={t.impact ?? ''} onchange={(e) => patch({ impact: e.currentTarget.value ? Number(e.currentTarget.value) : null })} options={[{ value: '', label: '–' }, ...levels.map((l) => ({ value: l.value, label: l.label }))]} />
								</Field>
								<Field label="Urgency" id="tp-urgency">
									<Select id="tp-urgency" class="w-full" value={t.urgency ?? ''} onchange={(e) => patch({ urgency: e.currentTarget.value ? Number(e.currentTarget.value) : null })} options={[{ value: '', label: '–' }, ...levels.map((l) => ({ value: l.value, label: l.label }))]} />
								</Field>
								<Field label="Board" id="tp-board">
									<Select id="tp-board" class="w-full" value={t.board_id} onchange={(e) => patch({ board_id: e.currentTarget.value }, 'Moved.')} options={(meta?.boards ?? []).map((b) => ({ value: b.id, label: b.name }))} />
								</Field>
								<Field label="Type" id="tp-type">
									<Select id="tp-type" class="w-full" value={t.type_id ?? ''} onchange={(e) => patch({ type_id: e.currentTarget.value || null })} options={[{ value: '', label: 'None' }, ...(meta?.types ?? []).map((x) => ({ value: x.id, label: x.name }))]} />
								</Field>
								{#if meta?.teams?.length}
									<Field label="Team" id="tp-team">
										<Select id="tp-team" class="w-full" value={t.team_id ?? ''} onchange={(e) => patch({ team_id: e.currentTarget.value || null })} options={[{ value: '', label: 'No team' }, ...meta.teams.map((x) => ({ value: x.id, label: x.name }))]} />
									</Field>
								{/if}
							</div>
						</div>
					{/if}
					<dl class={cx('dl', tech && !t.merged_into && 'border-border mt-4 border-t pt-3')}>
						{#if !tech || t.merged_into}
							<dt>Client</dt><dd>{#if t.client_id}<a class="link" href="/clients/{t.client_id}">{t.client_name}</a>{:else}Triage{/if}</dd>
							<dt>Contact</dt><dd>{t.contact_name ?? '–'}</dd>
							<dt>Assignee</dt><dd>{t.assignee_name ?? 'Unassigned'}</dd>
							<dt>Board</dt><dd>{t.board_name}</dd>
						{/if}
						{#if t.contact_email || t.requester_email}<dt>Email</dt><dd class="break-all">{t.contact_email || t.requester_email}</dd>{/if}
						<dt>Status</dt><dd>{t.status_name} <span class="text-muted text-xs">({statusCat.label})</span></dd>
						<dt>Source</dt><dd>{sourceLabels[t.source] ?? t.source}{#if t.alert_reopens}<span class="text-muted block text-xs">alert came back {t.alert_reopens}×</span>{/if}</dd>
						<dt>Opened</dt><dd>{datetime(t.created_at)}</dd>
						<dt>First reply</dt><dd>{t.first_response_at ? datetime(t.first_response_at) : '–'}</dd>
						{#if t.resolved_at}<dt>Resolved</dt><dd>{datetime(t.resolved_at)}</dd>{/if}
						{#if t.csat}
							<dt>Survey</dt>
							<dd>
								{#if t.csat.rating}
									<Badge tone={t.csat.rating === 'good' ? 'success' : 'danger'} icon={t.csat.rating === 'good' ? Smile : Frown}>{t.csat.rating === 'good' ? 'Good' : 'Bad'}</Badge>
									{#if t.csat.comment}<span class="text-muted block text-xs break-words">“{t.csat.comment}”</span>{/if}
								{:else}
									<span class="text-muted text-xs">Sent {ago(t.csat.sent_at)}, no answer yet</span>
								{/if}
							</dd>
						{/if}
					</dl>
				</section>

				{#if tech}
					<TicketTime ticketId={t.id} clientId={t.client_id} locked={!!t.merged_into || t.status_category === 'closed'} number={t.number} subject={t.subject} />
				{/if}

				{#if t.sla_policy_id}
					{@const rows = [
						{ key: 'respond' as const, by: t.respond_by, met: t.first_response_at },
						{ key: 'update' as const, by: t.update_by, met: null },
						{ key: 'resolve' as const, by: t.resolve_by, met: t.resolved_at }
					].filter((r) => r.by)}
					<section class="card p-4" aria-labelledby="sla-h">
						<header class="mb-3 flex items-center justify-between gap-2">
							<h2 id="sla-h" class="panel-title">Service level</h2>
							<SlaBadge ticket={t} />
						</header>
						<p class="text-muted mb-2 text-xs">{t.sla_policy_name}{#if t.sla_paused} · clock paused{/if}</p>
						{#if rows.length}
							<dl class="dl">
								{#each rows as r (r.key)}
									{@const missed = t.sla_breached.includes(r.key) || (!!r.met && new Date(r.met) > new Date(r.by!))}
									<dt>{targetLabels[r.key]}</dt>
									<dd title={datetime(r.by)}>
										{#if r.met}
											<Badge tone={missed ? 'danger' : 'success'}>{missed ? 'Missed' : 'Met'}</Badge>
										{:else if missed}
											<Badge tone="danger">Missed</Badge> <span class="text-muted text-xs">due {until(r.by!)}</span>
										{:else}
											{datetime(r.by)} <span class="text-muted block text-xs">{t.sla_paused ? 'paused' : until(r.by!)}</span>
										{/if}
									</dd>
								{/each}
							</dl>
						{:else}
							<p class="text-muted text-sm">No targets for {priorityOf(t.priority).short} in this policy.</p>
						{/if}
					</section>
				{/if}

				<section class="card" aria-labelledby="agents-h">
					<header class="border-border flex items-center justify-between min-h-12 border-b px-4 py-3">
						<h2 id="agents-h" class="panel-title">Agents</h2>
					</header>
					{#if t.agents.length}
						<ul class="divide-border divide-y">
							{#each t.agents as a (a.id)}
								{@const m = a.last_metrics}
								<li class="space-y-2 px-4 py-3">
									<div class="flex items-center gap-2">
										<a class="hover:text-accent min-w-0 flex-1 truncate font-medium" href="/agents/{a.id}">{a.hostname}</a>
										<Status online={a.online} />
									</div>
									<div class="text-muted flex flex-wrap items-center gap-2 text-xs">
										<HealthBadge health={a.health} agent={a} />
										<span>{a.site_name}</span>
										{#if !a.online}<span>seen {ago(a.last_seen_at)}</span>{/if}
										{#if a.missing_patches}<a class="link" href="/agents/{a.id}?tab=patches">{a.missing_patches} update{a.missing_patches === 1 ? '' : 's'} missing</a>{/if}
										{#if a.reboot_pending}<Badge tone="warning">Restart pending</Badge>{/if}
									</div>
									{#if m && a.online}
										<div class="grid grid-cols-3 gap-2 text-xs">
											<div><div class="text-muted">CPU</div><UsageBar value={m.cpu_percent} /></div>
											<div><div class="text-muted">Memory</div><UsageBar value={pct(m.mem_used, m.mem_total)} /></div>
											<div><div class="text-muted">Disk</div><UsageBar value={a.disk_max_pct} /></div>
										</div>
									{/if}
									{#if a.alerts.length}
										<ul class="space-y-1">
											{#each a.alerts as al (al.id)}
												<li class="flex items-center gap-2 text-xs"><SeverityBadge severity={al.severity} /><a class="link min-w-0 flex-1 truncate" href="/alerts/{al.id}">{al.title}</a></li>
											{/each}
										</ul>
									{/if}
									{#if tech && !t.merged_into}
										<div class="flex flex-wrap gap-1.5">
											<Button size="xs" icon={Play} onclick={() => (running = a)}>Run script</Button>
											<Button size="xs" icon={SquareTerminal} disabled={!a.online} href={a.online ? `/agents/${a.id}?tab=terminal&ticket=${t.id}` : undefined}>Terminal</Button>
											{#if a.capabilities.includes('desktop')}<Button size="xs" icon={MonitorUp} disabled={!a.online} href={a.online ? `/agents/${a.id}?tab=desktop&ticket=${t.id}` : undefined}>Desktop</Button>{/if}
											<IconButton size="sm" icon={Unlink} label="Unlink {a.hostname}" onclick={() => unlinkAgent(a)} />
										</div>
									{/if}
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact title="No agents linked" description={t.client_id ? 'Link the machines this ticket is about to see their state here.' : 'Choose a client first.'} />
					{/if}
					{#if tech && t.client_id && !t.merged_into}
						<div class="border-border border-t px-4 py-3">
							{#key t.agents.length}
								<Combobox
									label="Link an agent"
									value=""
									placeholder="Link an agent…"
									items={clientAgents.filter((a) => !t.agents.some((x) => x.id === a.id)).map((a) => ({ value: a.id, label: a.hostname, hint: a.site_name }))}
									onchange={linkAgent}
								/>
							{/key}
						</div>
					{/if}
				</section>

				<section class="card" aria-labelledby="docs-h">
					<header class="border-border flex items-center justify-between min-h-12 border-b px-4 py-3">
						<h2 id="docs-h" class="panel-title">Documentation</h2>
					</header>
					{#if t.docs.length}
						<ul class="divide-border divide-y">
							{#each t.docs as d (d.id)}
								<li class="flex items-center gap-2 px-4 py-2.5">
									<FileText class="text-muted size-4 shrink-0" aria-hidden="true" />
									<div class="min-w-0 flex-1">
										<a class="hover:text-accent block truncate font-medium" href={docPageHref(t.client_id ?? '', d.id)} onclick={(e) => openPeek(e, d.id)} aria-haspopup="dialog">{d.title}</a>
										<p class="text-muted truncate text-xs">{d.category || 'Uncategorised'} · saved <time datetime={d.updated_at} title={datetime(d.updated_at)}>{ago(d.updated_at)}</time></p>
									</div>
									{#if tech && !t.merged_into}<IconButton size="sm" icon={Unlink} label="Unlink {d.title}" onclick={() => unlinkDoc(d)} />{/if}
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact title="No pages linked" description={t.client_id ? 'Link the runbooks and network notes this ticket needs, to read them here.' : 'Choose a client first.'} />
					{/if}
					{#if tech && t.client_id && !t.merged_into}
						<div class="border-border border-t px-4 py-3">
							{#key t.docs.length}
								<Combobox
									label="Link a page"
									value=""
									placeholder="Link a page…"
									items={clientDocs.filter((d) => !t.docs.some((x) => x.id === d.id)).map((d) => ({ value: d.id, label: d.title, hint: d.category || undefined }))}
									onchange={linkDoc}
								/>
							{/key}
						</div>
					{/if}
				</section>

				{#if t.attachments.length}
					<section class="card" aria-labelledby="files-h">
						<header class="border-border min-h-12 border-b px-4 py-3"><h2 id="files-h" class="panel-title">Attachments</h2></header>
						<ul class="divide-border divide-y">
							{#each t.attachments as a (a.id)}
								<li class="flex items-center gap-2 px-4 py-2 text-sm">
									<Paperclip class="text-muted size-3.5 shrink-0" />
									<a class="link min-w-0 flex-1 truncate" href={href(a)}>{a.name}</a>
									<span class="text-muted shrink-0 text-xs">{bytes(a.size)}</span>
								</li>
							{/each}
						</ul>
					</section>
				{/if}
			</aside>
		</div>

		<Drawer open={!!peek} title="Documentation" side="right" width="w-[44rem]" onclose={() => (peek = null)}>
			<Async res={peekDoc}>
				{#snippet skeleton()}
					<div class="space-y-4 px-5 pb-6" aria-busy="true">
						<span class="sr-only">Loading page</span>
						<Skeleton class="h-3 w-24" /><Skeleton class="h-6 w-64" /><Skeleton class="h-4 w-full" lines={6} />
					</div>
				{/snippet}
				{#snippet children(d)}
					{#if d}
						{@const ctx = docContext(d, agentsOf(d.client_id), { docHref: (x) => docPageHref(d.client_id, x), openDoc: (x) => (peek = x) })}
						<article aria-labelledby="peek-title">
							<header class="border-border flex flex-wrap items-start justify-between gap-x-4 gap-y-3 border-b px-5 pb-4">
								<div class="min-w-0">
									<p class="eyebrow">{d.category || 'Uncategorised'}</p>
									<h2 id="peek-title" class="mt-1 text-xl font-bold break-words">{d.title}</h2>
									<p class="text-muted mt-1 text-xs">
										Saved <time datetime={d.updated_at} title={datetime(d.updated_at)}>{ago(d.updated_at)}</time>{d.updated_by_name ? ` by ${d.updated_by_name}` : ''}
									</p>
								</div>
								<Button size="sm" icon={ExternalLink} href={docPageHref(d.client_id, d.id)}>Open page</Button>
							</header>
							<DocCredentials doc={d} {ctx} class="px-5" />
							<div class="px-5 py-5"><DocView source={d.body} {ctx} /></div>
						</article>
					{/if}
				{/snippet}
			</Async>
		</Drawer>
		{#if running}<RunScript agents={[running]} ticketId={t.id} onclose={() => (running = null)} />{/if}
		{#if merging}
			<Modal title="Merge {ticketNumber(t.number)} into…" description="Pick the ticket to keep. Everything on this one moves there." onclose={() => (merging = false)}>
				<Field label="Find a ticket" id="merge-q">
					<!-- svelte-ignore a11y_autofocus -->
					<Input id="merge-q" bind:value={mergeQuery} placeholder="T-10423 or words from the subject" autofocus autocomplete="off" />
				</Field>
				{#if mergeHits.length}
					<ul class="divide-border border-border mt-3 divide-y rounded-md border">
						{#each mergeHits as h (h.id)}
							<li>
								<button type="button" class="hover:bg-hover flex w-full items-center gap-2 px-3 py-2 text-left text-sm" onclick={() => mergeInto(h)}>
									<span class="text-muted font-mono text-xs">{ticketNumber(h.number)}</span>
									<span class="min-w-0 flex-1 truncate">{h.subject}</span>
									<TicketStatus name={h.status_name} category={h.status_category} />
								</button>
							</li>
						{/each}
					</ul>
				{:else if mergeQuery.trim()}
					<p class="text-muted mt-3 text-sm">No matching tickets.</p>
				{/if}
			</Modal>
		{/if}
	{/snippet}
</Async>
