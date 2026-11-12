<script lang="ts">
	import { FileText, History, Pencil, Plus, RotateCcw, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { ClientDoc, ClientDocDetail, DocRevision, DocRevisionRef } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** A client's documentation pages: grouped by category, plain text, with every earlier version kept. */
	let { clientId }: { clientId: string } = $props();

	const list = resource(() => api.get<ClientDoc[]>(`/clients/${clientId}/docs`));
	let selected = $state<string | null>(null);
	const doc = resource(() => (selected ? api.get<ClientDocDetail>(`/docs/${selected}`) : Promise.resolve(null)), { keep: false });
	const tech = $derived(can('technician'));

	const categories = $derived([...new Set((list.data ?? []).map((d) => d.category).filter(Boolean))].sort((a, b) => a.localeCompare(b)));
	function grouped(rows: ClientDoc[]): [string, ClientDoc[]][] {
		const m = new Map<string, ClientDoc[]>();
		for (const d of rows) m.set(d.category, [...(m.get(d.category) ?? []), d]);
		return [...m.entries()].sort((a, b) => (a[0] ? (b[0] ? a[0].localeCompare(b[0]) : -1) : 1));
	}

	// --- editing ---------------------------------------------------------------------------------
	let draft = $state<{ id: string | null; title: string; category: string; body: string } | null>(null);
	let saving = $state(false);
	function edit(d?: ClientDocDetail) {
		draft = d ? { id: d.id, title: d.title, category: d.category, body: d.body } : { id: null, title: '', category: '', body: '' };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const d = draft!;
		const body = { title: d.title.trim(), category: d.category.trim(), body: d.body };
		saving = true;
		let id = d.id;
		const ok = await attempt(async () => {
			if (d.id) await api.put(`/docs/${d.id}`, body);
			else id = (await api.post<{ id: string }>(`/clients/${clientId}/docs`, body)).id;
		}, `${body.title} saved.`);
		saving = false;
		if (ok) {
			draft = null;
			list.reload();
			if (selected === id) doc.reload();
			else selected = id;
		}
	}
	async function remove(d: ClientDocDetail) {
		const ok = await confirmAction({ title: `Delete ${d.title}?`, message: 'The page and its history are deleted.', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/docs/${d.id}`), `${d.title} deleted.`))) {
			selected = null;
			list.reload();
		}
	}

	// --- history ---------------------------------------------------------------------------------
	let showHistory = $state(false);
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
	async function restore(d: ClientDocDetail, r: DocRevision) {
		const ok = await confirmAction({ title: 'Restore this version?', message: 'It becomes the current text; the current one goes into the history.', confirmLabel: 'Restore' });
		if (ok && (await attempt(() => api.put(`/docs/${d.id}`, { title: r.title, category: d.category, body: r.body }), 'Version restored.'))) {
			revision = null;
			doc.reload();
			list.reload();
		}
	}
	const when = (iso: string) => new Date(iso).toLocaleString();
</script>

<div class="grid gap-5 lg:grid-cols-[16rem_minmax(0,1fr)]">
	<nav class="card self-start" aria-labelledby="docs-h">
		<header class="panel-head">
			<h2 id="docs-h" class="panel-title">Documentation</h2>
			{#if tech}<Button size="sm" icon={Plus} onclick={() => edit()}>New page</Button>{/if}
		</header>
		<Async res={list} compact>
			{#snippet children(rows)}
				{#if !rows.length}
					<EmptyState compact icon={FileText} title="No pages yet" description="Network notes, passwords policy, vendors, how their backups work…" />
				{:else}
					<div class="max-h-[32rem] overflow-y-auto py-1">
						{#each grouped(rows) as [cat, docs] (cat)}
							<h3 class="text-muted px-4 pt-2 pb-1 text-xs font-semibold tracking-wide uppercase">{cat || 'Uncategorised'}</h3>
							<ul>
								{#each docs as d (d.id)}
									<li>
										<button
											class="hover:bg-hover flex w-full cursor-pointer flex-col px-4 py-1.5 text-left text-sm {selected === d.id ? 'bg-accent-soft text-accent' : ''}"
											aria-current={selected === d.id ? 'page' : undefined}
											onclick={() => {
												selected = d.id;
												showHistory = false;
											}}
										>
											<span class="truncate font-medium">{d.title}</span>
											<span class="text-muted text-xs">Updated {ago(d.updated_at)}{d.updated_by_name ? ` by ${d.updated_by_name}` : ''}</span>
										</button>
									</li>
								{/each}
							</ul>
						{/each}
					</div>
				{/if}
			{/snippet}
		</Async>
	</nav>

	<div class="min-w-0">
		{#if !selected}
			<div class="card">
				<EmptyState compact icon={FileText} title="Choose a page" description={list.data?.length ? 'Pick a page on the left to read it.' : 'Pages you add show up here.'} />
			</div>
		{:else}
			<Async res={doc}>
				{#snippet children(d)}
					{#if d}
						<article class="card" aria-labelledby="doc-title">
							<header class="border-border flex flex-wrap items-start justify-between gap-3 border-b px-5 py-3">
								<div class="min-w-0">
									<h3 id="doc-title" class="text-lg font-semibold break-words">{d.title}</h3>
									<p class="text-muted text-xs">
										{d.category || 'Uncategorised'} · updated {when(d.updated_at)}{d.updated_by_name ? ` by ${d.updated_by_name}` : ''}
									</p>
								</div>
								<div class="flex flex-wrap gap-2">
									<Button size="sm" icon={History} onclick={() => (showHistory = !showHistory)} aria-expanded={showHistory} disabled={!d.history.length}>
										History{d.history.length ? ` (${d.history.length})` : ''}
									</Button>
									{#if tech}
										<Button size="sm" icon={Pencil} onclick={() => edit(d)}>Edit</Button>
										<Button size="sm" variant="danger-ghost" icon={Trash2} onclick={() => remove(d)}>Delete</Button>
									{/if}
								</div>
							</header>
							{#if showHistory && d.history.length}
								<section class="border-border bg-sunken/50 border-b px-5 py-3" aria-labelledby="hist-h">
									<h4 id="hist-h" class="mb-1.5 text-sm font-semibold">Earlier versions <span class="text-muted font-normal">({plural(d.history.length, 'version')})</span></h4>
									<ul class="space-y-1 text-sm">
										{#each d.history as r (r.id)}
											<li>
												<button class="link cursor-pointer text-left" onclick={() => openRevision(r)}>{when(r.edited_at)}</button>
												<span class="text-muted text-xs"> · {r.edited_by ?? 'unknown'}{r.title !== d.title ? ` · “${r.title}”` : ''}</span>
											</li>
										{/each}
									</ul>
								</section>
							{/if}
							<div class="px-5 py-4">
								{#if d.body.trim()}
									<div class="text-sm leading-relaxed break-words whitespace-pre-wrap">{d.body}</div>
								{:else}
									<p class="text-muted text-sm">This page is empty.</p>
								{/if}
							</div>
						</article>
					{/if}
				{/snippet}
			</Async>
		{/if}
	</div>
</div>

{#if draft}
	<Modal title={draft.id ? `Edit ${draft.title}` : 'New page'} onclose={() => (draft = null)} size="xl">
		<form id="doc-form" class="space-y-4" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Title" id="doc-t" required><Input id="doc-t" bind:value={draft.title} maxlength={300} required /></Field>
				<Field label="Category" id="doc-c">
					<Input id="doc-c" bind:value={draft.category} maxlength={100} list="doc-cats" placeholder="Network, Accounts, Vendors…" />
					<datalist id="doc-cats">{#each categories as c (c)}<option value={c}></option>{/each}</datalist>
				</Field>
			</div>
			<Field label="Text" id="doc-b" hint="Plain text; line breaks are kept. Saving keeps the previous version in the history.">
				<Textarea id="doc-b" rows={18} class="font-mono text-[0.8125rem]" bind:value={draft.body} maxlength={200000} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (draft = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="doc-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if revision}
	<Modal title={revision.data?.title ?? revision.ref.title} description="Version from {when(revision.ref.edited_at)}{revision.ref.edited_by ? `, by ${revision.ref.edited_by}` : ''}" onclose={() => (revision = null)} size="lg">
		{#if revision.error}
			<p class="text-danger text-sm" role="alert">{revision.error}</p>
		{:else if !revision.data}
			<p class="text-muted text-sm" aria-busy="true">Loading…</p>
		{:else}
			<div class="text-sm leading-relaxed break-words whitespace-pre-wrap">{revision.data.body || 'This version was empty.'}</div>
		{/if}
		{#snippet footer()}
			<Button onclick={() => (revision = null)}>Close</Button>
			{#if tech && revision?.data && doc.data}
				<Button variant="primary" icon={RotateCcw} onclick={() => restore(doc.data!, revision!.data!)}>Restore this version</Button>
			{/if}
		{/snippet}
	</Modal>
{/if}
