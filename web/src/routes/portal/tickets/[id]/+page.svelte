<script lang="ts">
	import { page } from '$app/state';
	import { ArrowLeft, CircleCheck, Download, GitMerge, Lock, Paperclip, Plus, Send } from '@lucide/svelte';
	import { ago, bytes, cx, datetime } from '#lib/format.js';
	import { attachmentUrl, portal, PortalError } from '#lib/portal/api.js';
	import { formWith, isDone, ticketNumber } from '#lib/portal/format.js';
	import FilePicker from '#lib/portal/FilePicker.svelte';
	import StatusBadge from '#lib/portal/StatusBadge.svelte';
	import type { PortalAttachment, PortalEvent, PortalTicketDetail } from '#lib/portal/types.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	const id = $derived(page.params.id ?? '');

	let t = $state<PortalTicketDetail | null>(null);
	let error = $state<string>('');
	let missing = $state(false);
	let seq = 0;

	async function load(quiet = false) {
		const n = ++seq;
		if (!quiet) {
			t = null;
			error = '';
			missing = false;
		}
		try {
			const d = await portal.get<PortalTicketDetail>(`/tickets/${id}`);
			if (n === seq) t = d;
		} catch (e) {
			if (n !== seq) return;
			if (e instanceof PortalError && (e.status === 404 || e.status === 400)) missing = true;
			else if (!quiet) error = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		void id;
		load();
	});

	const eventIds = $derived(new Set(t?.events.map((e) => e.id) ?? []));
	const filesOf = (e: PortalEvent) => t?.attachments.filter((a) => a.event_id === e.id) ?? [];
	// Files whose entry isn't shown (shouldn't normally happen, but never hide a file).
	const loose = $derived(t?.attachments.filter((a) => a.event_id === null || !eventIds.has(a.event_id)) ?? []);

	const closed = $derived(!!t && (t.status_category === 'closed' || !!t.merged_into));
	const canResolve = $derived(!!t && !t.merged_into && !isDone(t.status_category));

	let body = $state('');
	let files = $state<File[]>([]);
	let sending = $state(false);
	let replyError = $state('');

	async function send(e: SubmitEvent) {
		e.preventDefault();
		if (!body.trim() && !files.length) {
			replyError = 'Write a message or attach a file first.';
			return;
		}
		sending = true;
		replyError = '';
		try {
			await portal.form(`/tickets/${id}/messages`, formWith({ body }, files));
			body = '';
			files = [];
			toast.success('Message sent');
			await load(true);
		} catch (e) {
			const m = e instanceof Error ? e.message : String(e);
			replyError = m.charAt(0).toUpperCase() + m.slice(1);
		} finally {
			sending = false;
		}
	}

	function keydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
			e.preventDefault();
			(e.currentTarget as HTMLTextAreaElement).form?.requestSubmit();
		}
	}

	let resolving = $state(false);
	async function resolve() {
		resolving = true;
		try {
			await portal.post(`/tickets/${id}/resolve`);
			toast.success('Marked as resolved. Thanks for letting us know.');
			await load(true);
		} catch (e) {
			toast.error(e);
		} finally {
			resolving = false;
		}
	}

	const verb = (e: PortalEvent) => (e.kind === 'created' ? 'opened the request' : e.author_kind === 'staff' ? 'replied' : 'wrote');
</script>

<svelte:head>
	{#if t}<title>{ticketNumber(t.number)} {t.subject} · Support portal</title>{/if}
</svelte:head>

{#snippet fileList(list: PortalAttachment[])}
	<ul class="flex flex-wrap gap-2" aria-label="Attachments">
		{#each list as a (a.id)}
			<li class="max-w-full">
				<a
					href={attachmentUrl(id, a.id)}
					download={a.name}
					class="border-border bg-raised hover:bg-hover focus-visible:ring-accent/40 inline-flex h-8 max-w-full items-center gap-1.5 rounded-md border px-2 text-xs focus-visible:ring-2 focus-visible:outline-none"
				>
					<Paperclip class="size-3.5 shrink-0" aria-hidden="true" />
					<span class="truncate">{a.name}</span>
					<span class="text-muted shrink-0">{bytes(a.size)}</span>
					<Download class="text-muted size-3.5 shrink-0" aria-hidden="true" />
					<span class="sr-only">(download)</span>
				</a>
			</li>
		{/each}
	</ul>
{/snippet}

<div class="space-y-6">
	<a href="/portal" class="text-muted hover:text-fg inline-flex items-center gap-1 text-sm"><ArrowLeft class="size-4" aria-hidden="true" />All requests</a>

	{#if missing}
		<div class="card">
			<EmptyState title="Request not found" description="It may have been removed, or it belongs to someone else in your organisation.">
				{#snippet action()}<Button href="/portal">Back to your requests</Button>{/snippet}
			</EmptyState>
		</div>
	{:else if error}
		<div class="card"><ErrorState {error} onretry={() => load()} /></div>
	{:else if !t}
		<div class="card space-y-3 p-4"><Skeleton lines={8} /></div>
	{:else}
		<div class="flex flex-wrap items-start justify-between gap-4">
			<div class="min-w-0">
				<p class="text-muted font-mono text-xs">{ticketNumber(t.number)}</p>
				<h1 class="mt-1 text-2xl font-medium break-words">{t.subject}</h1>
				<div class="text-muted mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
					<StatusBadge category={t.status_category} />
					<span>Opened <time datetime={t.created_at} title={datetime(t.created_at)}>{ago(t.created_at)}</time>{#if t.contact_name} by {t.contact_name}{/if}</span>
				</div>
			</div>
			{#if canResolve}
				<Button icon={CircleCheck} loading={resolving} onclick={resolve}>Mark as resolved</Button>
			{/if}
		</div>

		{#if t.merged_into}
			<p class="border-border bg-sunken flex items-start gap-2 rounded-md border px-3 py-2 text-sm">
				<GitMerge class="text-muted mt-0.5 size-4 shrink-0" aria-hidden="true" />
				<span>
					This request was combined with
					<a class="link" href="/portal/tickets/{t.merged_into}">{t.merged_into_number ? ticketNumber(t.merged_into_number) : 'another request'}</a>; the conversation continues there.
				</span>
			</p>
		{:else if t.status_category === 'waiting_client'}
			<p class="border-warning/40 bg-warning-soft text-warning rounded-md border px-3 py-2 text-sm font-medium">We're waiting for your reply on this request.</p>
		{/if}

		<section aria-labelledby="conv-h">
			<h2 id="conv-h" class="sr-only">Conversation</h2>
			<ol class="space-y-4">
				{#each t.events as e (e.id)}
					{@const mine = e.author_kind === 'contact'}
					{@const list = filesOf(e)}
					<li class={cx('flex', mine ? 'justify-end sm:pl-12' : 'justify-start sm:pr-12')}>
						<article
							class={cx(
								'w-full overflow-hidden rounded-panel border shadow-card',
								mine ? 'border-accent/25 bg-accent-soft' : 'border-border bg-raised'
							)}
							aria-label="{mine ? 'Message' : 'Reply from support'} from {e.author_name}, {datetime(e.created_at)}"
						>
							<header class="flex flex-wrap items-center gap-x-2 gap-y-1 px-4 pt-3 text-sm">
								<span
									class={cx(
										'inline-flex size-6 shrink-0 items-center justify-center rounded-full text-[0.6875rem] font-semibold',
										mine ? 'bg-accent text-on-accent' : 'bg-nav text-white'
									)}
									aria-hidden="true">{(e.author_name || '?').charAt(0).toUpperCase()}</span
								>
								<span class="font-medium">{e.author_name}</span>
								<span class="text-muted text-xs">{mine ? verb(e) : `${verb(e)} · Support team`}</span>
								<time class="text-muted ml-auto text-xs" datetime={e.created_at} title={datetime(e.created_at)}>{ago(e.created_at)}</time>
							</header>
							{#if e.body}
								<div class="px-4 py-2 text-sm break-words whitespace-pre-wrap">{e.body}</div>
							{:else if e.kind === 'created' && !list.length}
								<p class="text-muted px-4 py-2 text-sm">No description.</p>
							{:else}
								<div class="h-2"></div>
							{/if}
							{#if list.length}<div class="px-4 pb-3">{@render fileList(list)}</div>{/if}
						</article>
					</li>
				{/each}
			</ol>
			{#if loose.length}
				<div class="card mt-4 p-4">
					<h3 class="mb-2 text-sm font-medium">Other files</h3>
					{@render fileList(loose)}
				</div>
			{/if}
		</section>

		{#if closed}
			<div class="card flex flex-col items-start gap-3 p-4 sm:flex-row sm:items-center">
				<Lock class="text-muted size-5 shrink-0" aria-hidden="true" />
				<p class="flex-1 text-sm">
					{#if t.merged_into}This request was combined with another one, so it can't take new messages.{:else}This request is closed, so it can't take new messages. If you still need help, open a new request.{/if}
				</p>
				<Button variant="primary" href="/portal/tickets/new" icon={Plus}>New request</Button>
			</div>
		{:else}
			<form class="card space-y-3 p-4" onsubmit={send} aria-labelledby="reply-h">
				<h2 id="reply-h" class="text-[0.9375rem] font-semibold tracking-tight">Reply</h2>
				{#if t.status_category === 'resolved'}
					<p class="text-muted text-sm">This request is resolved. Sending a message reopens it.</p>
				{/if}
				<label for="reply-body" class="sr-only">Your message</label>
				<Textarea id="reply-body" rows={5} bind:value={body} onkeydown={keydown} placeholder="Write a message to the support team…" disabled={sending} />
				<div class="flex flex-wrap items-start gap-3">
					<FilePicker id="reply-files" bind:files disabled={sending} />
					<Button variant="primary" type="submit" class="ml-auto" icon={Send} loading={sending} title="Ctrl+Enter">Send</Button>
				</div>
				{#if replyError}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{replyError}</p>{/if}
			</form>
		{/if}
	{/if}
</div>
