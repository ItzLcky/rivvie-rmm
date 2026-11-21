<script lang="ts">
	import { ArrowLeft, BookmarkPlus, FileDown, FileQuestion, FileText, History, Pencil, Plus, RotateCcw, Search, Trash2 } from '@lucide/svelte';
	import { ApiError, api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, cx, datetime, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { agentLoader, docContext } from '#lib/docs/context.js';
	import type { DocCategory, DocDetail, DocRevision, DocRevisionRef, DocRow, DocTemplate } from '#lib/docs/types.js';
	import { ticketNumber } from '#lib/servicedesk/tickets.svelte.js';
	import TicketStatus from '#lib/components/ticket/TicketStatus.svelte';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import DocCredentials from './DocCredentials.svelte';
	import DocEditor, { type DocDraft, type SaveResult } from './DocEditor.svelte';
	import DocView from './DocView.svelte';
	import NewDocDialog from './NewDocDialog.svelte';

	/**
	 * A client's documentation: pages grouped by category on the left, the selected one
	 * (`?doc=`) rendered on the right, edited in place (`&edit=1`, or `&edit=new` for a draft).
	 */
	let { clientId, clientName }: { clientId: string; clientName: string } = $props();

	const list = resource(() => api.get<DocRow[]>(`/clients/${clientId}/docs`));
	const cats = resource(() => api.get<DocCategory[]>('/doc-categories'));
	const selected = $derived(param('doc') || null);
	const editParam = $derived(param('edit'));
	const doc = resource(() => (selected ? api.get<DocDetail>(`/docs/${selected}`) : Promise.resolve(null)), { keep: false });
	const tech = $derived(can('technician'));
	const select = (id: string | null) => setParams({ doc: id, edit: null }, { push: true });

	// --- the list -----------------------------------------------------------------------------
	let q = $state('');
	const groups = $derived.by(() => {
		const s = q.trim().toLowerCase();
		const rows = (list.data ?? []).filter((d) => !s || d.title.toLowerCase().includes(s) || d.category.toLowerCase().includes(s));
		// The server sends them in category order, uncategorised last.
		const out: { key: string; name: string; docs: DocRow[] }[] = [];
		for (const d of rows) {
			const key = d.category_id ?? '';
			const g = out.find((x) => x.key === key);
			if (g) g.docs.push(d);
			else out.push({ key, name: d.category || 'Uncategorised', docs: [d] });
		}
		return out;
	});

	// --- what blocks can show -----------------------------------------------------------------
	const agents = $derived(agentLoader(clientId));
	const ctxFor = (d: DocDetail) => docContext(d, agents);

	// --- new pages and editing ----------------------------------------------------------------
	let creating = $state(false);
	let templates = $state<DocTemplate[] | undefined>(undefined);
	function startNew() {
		creating = true;
		if (!templates) api.get<DocTemplate[]>('/doc-templates').then((t) => (templates = t), () => (templates = []));
	}
	let draft = $state<DocDraft | null>(null);
	function started(d: DocDraft) {
		creating = false;
		draft = d;
		setParams({ doc: null, edit: 'new' }, { push: true });
	}
	// A reload (or Back) to `edit=new` has no draft any more.
	$effect(() => {
		if (editParam === 'new' && !draft) setParams({ edit: null });
		if (editParam !== 'new' && draft) draft = null;
	});

	let createdId: string | null = null;
	async function saveNew(d: DocDraft): Promise<SaveResult> {
		try {
			const r = await api.post<{ id: string }>(`/clients/${clientId}/docs`, { title: d.title.trim(), category_id: d.category_id, body: d.body });
			createdId = r.id;
			toast.success(`${d.title.trim()} saved.`);
			list.reload();
			cats.reload();
			return 'ok';
		} catch (e) {
			toast.error(e);
			return 'error';
		}
	}
	async function saveExisting(cur: DocDetail, d: DocDraft, force: boolean): Promise<SaveResult> {
		try {
			await api.put(`/docs/${cur.id}`, { title: d.title.trim(), category_id: d.category_id, body: d.body, ...(force ? {} : { expected_updated_at: cur.updated_at }) });
			toast.success('Saved.');
			list.reload();
			doc.reload();
			return 'ok';
		} catch (e) {
			if (e instanceof ApiError && e.status === 409) return 'conflict';
			toast.error(e);
			return 'error';
		}
	}
	function closeEditor(saved: boolean) {
		if (editParam === 'new') {
			const id = saved ? createdId : null;
			createdId = null;
			draft = null;
			setParams({ doc: id, edit: null }, { push: false });
		} else {
			if (!saved) doc.reload();
			setParams({ edit: null });
		}
	}

	async function remove(d: DocDetail) {
		const ok = await confirmAction({ title: `Delete ${d.title}?`, message: 'The page and its history are deleted.', confirmLabel: 'Delete page', danger: true });
		if (ok && (await attempt(() => api.del(`/docs/${d.id}`), `${d.title} deleted.`))) {
			select(null);
			list.reload();
		}
	}

	// --- save as template (admins) ------------------------------------------------------------
	let asTemplate = $state<{ name: string; description: string } | null>(null);
	let templSaving = $state(false);
	async function saveTemplate(e: SubmitEvent, d: DocDetail) {
		e.preventDefault();
		templSaving = true;
		const ok = await attempt(() => api.post('/doc-templates', { name: asTemplate!.name.trim(), description: asTemplate!.description.trim(), category_id: d.category_id, body: d.body }));
		templSaving = false;
		if (ok) {
			toast.success(`Template ${asTemplate!.name.trim()} saved.`, { href: { label: 'Templates', href: '/settings/documentation' } });
			asTemplate = null;
			templates = undefined;
		}
	}

	// --- history ------------------------------------------------------------------------------
	let showHistory = $state(false);
	$effect(() => {
		void selected;
		showHistory = false;
	});
	let revision = $state<{ ref: DocRevisionRef; data: DocRevision | null; error?: string } | null>(null);
	async function openRevision(r: DocRevisionRef) {
		revision = { ref: r, data: null };
		try {
			const data = await api.get<DocRevision>(`/docs/${selected}/revisions/${r.id}`);
			if (revision?.ref.id === r.id) revision = { ref: r, data };
		} catch (e) {
			if (revision?.ref.id === r.id) revision = { ref: r, data: null, error: e instanceof Error ? e.message : String(e) };
		}
	}
	async function restore(d: DocDetail, r: DocRevision) {
		const ok = await confirmAction({ title: 'Restore this version?', message: 'It becomes the current text; the current one goes into the history.', confirmLabel: 'Restore' });
		if (!ok) return;
		try {
			await api.put(`/docs/${d.id}`, { title: r.title, category_id: d.category_id, body: r.body, expected_updated_at: d.updated_at });
			toast.success('Version restored.');
			revision = null;
			doc.reload();
			list.reload();
		} catch (e) {
			toast.error(e instanceof ApiError && e.status === 409 ? 'Someone saved this page since you opened it. Look at their version, then restore again if you still want to.' : e);
			doc.reload();
		}
	}

	const editingExisting = $derived(editParam === '1' && !!selected && tech);
	const editingNew = $derived(editParam === 'new' && !!draft && tech);
	const editing = $derived(editingExisting || editingNew);
	const notFound = $derived(doc.error instanceof ApiError && doc.error.status === 404);
</script>

{#if editingNew}
	<DocEditor heading="New page" initial={draft!} categories={cats.data ?? []} {clientId} onsave={saveNew} ondone={closeEditor} />
{:else if editingExisting}
	<Async res={doc}>
		{#snippet children(d)}
			{#if d}
				{#key d.id}
					<DocEditor
						heading="Editing {d.title}"
						initial={{ title: d.title, category_id: d.category_id, body: d.body, description: '' }}
						categories={cats.data ?? []}
						{clientId}
						credentials={d.credentials}
						onsave={(draft, force) => saveExisting(d, draft, force)}
						ondone={closeEditor}
					/>
				{/key}
			{/if}
		{/snippet}
	</Async>
{:else}
	<div class="grid gap-5 lg:grid-cols-[17rem_minmax(0,1fr)]">
		<nav class={cx('card self-start lg:sticky lg:top-4', selected && 'hidden lg:block')} aria-labelledby="docs-h">
			<header class="panel-head">
				<h2 id="docs-h" class="panel-title">Pages</h2>
				{#if tech}<Button size="sm" icon={Plus} onclick={startNew}>New page</Button>{/if}
			</header>
			<Async res={list} compact>
				{#snippet children(rows)}
					{#if !rows.length}
						<EmptyState compact icon={FileText} title="No pages yet" description="The network, the servers, vendors, how their backups work: start one from a template." />
					{:else}
						<div class="border-border border-b p-2">
							<Input icon={Search} bind:value={q} placeholder="Filter pages" aria-label="Filter pages" class="[&_input]:h-8" />
						</div>
						<div class="max-h-[calc(100dvh-14rem)] overflow-y-auto py-1.5">
							{#each groups as g (g.key)}
								<h3 class="text-muted px-4 pt-2.5 pb-1 font-sans text-[0.6875rem] font-semibold tracking-[0.08em] uppercase">{g.name}</h3>
								<ul>
									{#each g.docs as d (d.id)}
										<li>
											<a
												href="?tab=docs&doc={d.id}"
												class={cx('hover:bg-hover/70 mx-1.5 flex flex-col rounded-md px-2.5 py-1.5 text-sm', selected === d.id && 'bg-accent-soft text-accent-ink hover:bg-accent-soft')}
												aria-current={selected === d.id ? 'page' : undefined}
											>
												<span class="truncate font-medium">{d.title}</span>
												<span class={cx('truncate text-xs', selected === d.id ? 'text-accent-ink/80' : 'text-muted')}>{ago(d.updated_at)}{d.updated_by_name ? ` · ${d.updated_by_name}` : ''}</span>
											</a>
										</li>
									{/each}
								</ul>
							{:else}
								<p class="text-muted px-4 py-6 text-center text-sm">No page matches “{q}”.</p>
							{/each}
						</div>
					{/if}
				{/snippet}
			</Async>
		</nav>

		<div class={cx('min-w-0', !selected && 'hidden lg:block')}>
			{#if selected}
				<a href="?tab=docs" class="text-muted hover:text-fg mb-3 inline-flex items-center gap-1 text-sm lg:hidden"><ArrowLeft class="size-4" aria-hidden="true" />All pages</a>
			{/if}
			{#if !selected}
				<div class="card">
					<EmptyState
						icon={FileText}
						title={list.data?.length ? 'Choose a page' : 'Document how this client works'}
						description={list.data?.length ? 'Pick a page on the left to read it.' : 'Pages are Markdown with blocks for fields, credentials from the vault, callouts and devices. Templates give you a head start.'}
					>
						{#snippet action()}{#if tech && !list.data?.length && !list.loading}<Button variant="primary" icon={Plus} onclick={startNew}>New page</Button>{/if}{/snippet}
					</EmptyState>
				</div>
			{:else if notFound}
				<div class="card">
					<EmptyState icon={FileQuestion} title="This page doesn’t exist" description="It was deleted, or the link points at another client’s page.">
						{#snippet action()}<Button href="?tab=docs">All pages</Button>{/snippet}
					</EmptyState>
				</div>
			{:else}
				<Async res={doc}>
					{#snippet skeleton()}
						<div class="card space-y-4 p-6" aria-busy="true">
							<span class="sr-only">Loading page</span>
							<Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-72" /><Skeleton class="h-4 w-full" lines={6} />
						</div>
					{/snippet}
					{#snippet children(d)}
						{#if d}
							{@const ctx = ctxFor(d)}
							<article class="card" aria-labelledby="doc-title">
								<header class="border-border flex flex-wrap items-start justify-between gap-x-4 gap-y-3 border-b px-6 py-4">
									<div class="min-w-0">
										<p class="eyebrow">{d.category || 'Uncategorised'}</p>
										<h2 id="doc-title" class="mt-1 text-2xl font-bold break-words">{d.title}</h2>
										<p class="text-muted mt-1 text-xs">
											Saved <time datetime={d.updated_at} title={datetime(d.updated_at)}>{ago(d.updated_at)}</time>{d.updated_by_name ? ` by ${d.updated_by_name}` : ''}{d.history.length ? ` · ${plural(d.history.length, 'earlier version')}` : ''}
										</p>
									</div>
									<div class="flex flex-wrap items-center gap-2">
										{#if tech}<Button size="sm" variant="primary" icon={Pencil} onclick={() => setParams({ edit: '1' }, { push: true })}>Edit</Button>{/if}
										<Button size="sm" icon={History} onclick={() => (showHistory = !showHistory)} aria-expanded={showHistory} disabled={!d.history.length}>History</Button>
										<Button size="sm" icon={FileDown} href="/api/docs/{d.id}/export" download>Export</Button>
										{#if tech}
											<Menu
												label="More page actions"
												items={[
													...(can('admin') ? [{ label: 'Save as template…', icon: BookmarkPlus, onSelect: () => (asTemplate = { name: d.title, description: '' }) }] : []),
													{ label: 'Delete page…', icon: Trash2, danger: true, onSelect: () => remove(d) }
												]}
											/>
										{/if}
									</div>
								</header>
								<DocCredentials doc={d} {ctx} class="px-6" />
								{#if d.tickets.length}
									<div class="border-border bg-sunken/40 flex flex-wrap items-start gap-x-3 gap-y-1.5 border-b px-6 py-2.5">
										<span class="text-muted pt-0.5 text-xs font-medium">Linked tickets</span>
										<ul class="flex min-w-0 flex-1 flex-col gap-1 text-sm" aria-label="Linked tickets">
											{#each d.tickets as t (t.id)}
												<li class="flex min-w-0 items-center gap-2">
													<a class="link flex min-w-0 items-baseline gap-1.5" href="/tickets/{t.id}">
														<span class="font-mono text-xs">{ticketNumber(t.number)}</span>
														<span class="truncate">{t.subject}</span>
													</a>
													<TicketStatus name={t.status} category={t.status_category} />
												</li>
											{/each}
										</ul>
									</div>
								{/if}
								{#if showHistory && d.history.length}
									<section class="border-border bg-sunken/50 border-b px-6 py-3" aria-labelledby="hist-h">
										<h3 id="hist-h" class="mb-1.5 text-sm font-semibold">Earlier versions <span class="text-muted font-normal">({d.history.length})</span></h3>
										<ul class="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
											{#each d.history as r (r.id)}
												<li class="min-w-0 truncate">
													<button class="link cursor-pointer text-left" onclick={() => openRevision(r)}>{datetime(r.edited_at)}</button>
													<span class="text-muted text-xs"> · {r.edited_by ?? 'unknown'}{r.title !== d.title ? ` · “${r.title}”` : ''}</span>
												</li>
											{/each}
										</ul>
									</section>
								{/if}
								<div class="px-6 py-5">
									<DocView source={d.body} {ctx} class="max-w-[50rem]" />
								</div>
							</article>
						{/if}
					{/snippet}
				</Async>
			{/if}
		</div>
	</div>
{/if}

{#if creating}
	<NewDocDialog {clientName} categories={cats.data ?? []} {templates} onstart={started} onclose={() => (creating = false)} />
{/if}

{#if asTemplate && doc.data}
	{@const d = doc.data}
	<Modal title="Save as template" description="New pages of any client can start from it. Credentials stay linked only on this page." onclose={() => (asTemplate = null)} size="md">
		<form id="as-template" class="space-y-4" onsubmit={(e) => saveTemplate(e, d)}>
			<Field label="Name" id="tpl-name" required><Input id="tpl-name" bind:value={asTemplate.name} maxlength={200} required /></Field>
			<Field label="Description" id="tpl-desc" hint="Shown on its card in New page."><Input id="tpl-desc" bind:value={asTemplate.description} maxlength={500} /></Field>
			<p class="text-muted text-xs">It goes under {d.category || 'no category'}, with the page’s text as it is now. Edit it under Company settings → Documentation, for example to put <code class="font-mono">{'{{client.name}}'}</code> where this client’s name is.</p>
		</form>
		{#snippet footer()}
			<Button onclick={() => (asTemplate = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="as-template" loading={templSaving}>Save template</Button>
		{/snippet}
	</Modal>
{/if}

{#if revision}
	<Modal title={revision.data?.title ?? revision.ref.title} description="Version from {datetime(revision.ref.edited_at)}{revision.ref.edited_by ? `, by ${revision.ref.edited_by}` : ''}" onclose={() => (revision = null)} size="lg">
		{#if revision.error}
			<p class="text-danger text-sm" role="alert">{revision.error}</p>
		{:else if !revision.data}
			<div class="space-y-2" aria-busy="true"><span class="sr-only">Loading version</span><Skeleton class="h-4 w-full" lines={5} /></div>
		{:else if doc.data}
			<DocView source={revision.data.body} ctx={ctxFor(doc.data)} empty="This version was empty." />
		{/if}
		{#snippet footer()}
			<Button onclick={() => (revision = null)}>Close</Button>
			{#if tech && revision?.data && doc.data}
				<Button variant="primary" icon={RotateCcw} onclick={() => restore(doc.data!, revision!.data!)}>Restore this version</Button>
			{/if}
		{/snippet}
	</Modal>
{/if}
