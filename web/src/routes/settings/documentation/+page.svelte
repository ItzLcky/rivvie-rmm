<script lang="ts">
	import { ArrowDown, ArrowUp, Check, CopyPlus, FolderOpen, LayoutTemplate, Pencil, Plus, Trash2, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { DocCategory, DocTemplate } from '#lib/docs/types.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import DocEditor, { type DocDraft, type SaveResult } from '#lib/components/docs/DocEditor.svelte';

	/**
	 * Company settings → Documentation: the MSP-wide categories pages are filed under, and the
	 * templates new pages start from (`?template=<id>` or `new` edits one).
	 */
	const cats = resource(() => api.get<DocCategory[]>('/doc-categories'));
	const templates = resource(() => api.get<DocTemplate[]>('/doc-templates'));

	// --- categories ---------------------------------------------------------------------------
	let newName = $state('');
	let adding = $state(false);
	async function add(e: SubmitEvent) {
		e.preventDefault();
		const name = newName.trim();
		if (!name) return;
		adding = true;
		if (await attempt(() => api.post('/doc-categories', { name }), `${name} added.`)) {
			newName = '';
			cats.reload();
		}
		adding = false;
	}
	let renaming = $state<{ id: string; name: string } | null>(null);
	async function rename(e: SubmitEvent) {
		e.preventDefault();
		const r = renaming!;
		if (await attempt(() => api.put(`/doc-categories/${r.id}`, { name: r.name.trim() }), 'Renamed.')) {
			renaming = null;
			cats.reload();
			templates.reload();
		}
	}
	async function move(rows: DocCategory[], i: number, by: -1 | 1) {
		const ids = rows.map((c) => c.id);
		[ids[i], ids[i + by]] = [ids[i + by], ids[i]];
		// Show the new order straight away; the server answers with the saved list.
		cats.set(ids.map((id) => rows.find((c) => c.id === id)!));
		try {
			cats.set(await api.put<DocCategory[]>('/doc-categories/order', { ids }));
		} catch (err) {
			toast.error(err);
			cats.reload();
		}
		requestAnimationFrame(() => document.getElementById(`cat-${ids[i + by]}-${by < 0 ? 'up' : 'down'}`)?.focus());
	}
	async function removeCategory(c: DocCategory) {
		const ok = await confirmAction({
			title: `Delete ${c.name}?`,
			message:
				c.docs || c.templates
					? `${plural(c.docs, 'page')} and ${plural(c.templates, 'template')} in it become uncategorised. Nothing else is deleted.`
					: 'Nothing is filed under it.',
			confirmLabel: 'Delete category',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/doc-categories/${c.id}`), `${c.name} deleted.`))) {
			cats.reload();
			templates.reload();
		}
	}

	// --- templates ----------------------------------------------------------------------------
	const grouped = $derived.by(() => {
		const out: { key: string; name: string; rows: DocTemplate[] }[] = [];
		for (const t of templates.data ?? []) {
			const key = t.category_id ?? '';
			const g = out.find((x) => x.key === key);
			if (g) g.rows.push(t);
			else out.push({ key, name: t.category || 'Uncategorised', rows: [t] });
		}
		return out;
	});
	async function duplicate(t: DocTemplate) {
		const names = new Set((templates.data ?? []).map((x) => x.name.toLowerCase()));
		let name = `${t.name} (copy)`;
		for (let n = 2; names.has(name.toLowerCase()); n++) name = `${t.name} (copy ${n})`;
		const ok = await attempt(async () => {
			const full = await api.get<DocTemplate>(`/doc-templates/${t.id}`);
			await api.post('/doc-templates', { name, category_id: full.category_id, description: full.description, body: full.body ?? '' });
		}, `${name} added.`);
		if (ok) {
			templates.reload();
			cats.reload();
		}
	}
	async function removeTemplate(t: DocTemplate) {
		const ok = await confirmAction({ title: `Delete ${t.name}?`, message: 'Pages already started from it keep their text.', confirmLabel: 'Delete template', danger: true });
		if (ok && (await attempt(() => api.del(`/doc-templates/${t.id}`), `${t.name} deleted.`))) {
			templates.reload();
			cats.reload();
		}
	}

	// --- editing one (?template=) -------------------------------------------------------------
	const editing = $derived(param('template') || null);
	const current = resource(() => (editing && editing !== 'new' ? api.get<DocTemplate>(`/doc-templates/${editing}`) : Promise.resolve(null)), { keep: false });
	async function save(d: DocDraft): Promise<SaveResult> {
		const body = { name: d.title.trim(), category_id: d.category_id, description: d.description.trim(), body: d.body };
		const ok = await attempt(() => (editing === 'new' ? api.post('/doc-templates', body) : api.put(`/doc-templates/${editing}`, body)), `${body.name} saved.`);
		if (ok) {
			templates.reload();
			cats.reload();
		}
		return ok ? 'ok' : 'error';
	}
	const close = () => setParams({ template: null });
	const blank = `# Title\n\n_Last reviewed {{date}} by {{user.name}}._\n\n\`\`\`fields\nLabel:\n\`\`\`\n`;
</script>

{#if editing === 'new'}
	<DocEditor mode="template" heading="New template" initial={{ title: '', category_id: null, body: blank, description: '' }} categories={cats.data ?? []} onsave={save} ondone={close} />
{:else if editing}
	<Async res={current}>
		{#snippet children(t)}
			{#if t}
				<DocEditor
					mode="template"
					heading="Editing {t.name}"
					initial={{ title: t.name, category_id: t.category_id, body: t.body ?? '', description: t.description }}
					categories={cats.data ?? []}
					onsave={save}
					ondone={close}
				/>
			{/if}
		{/snippet}
	</Async>
{:else}
	<p class="text-muted mb-4 max-w-3xl text-sm">
		Every client’s pages are filed under these categories, and new pages can start from a template. In a template, <code class="font-mono text-xs">{'{{client.name}}'}</code>, <code class="font-mono text-xs">{'{{date}}'}</code> and
		<code class="font-mono text-xs">{'{{user.name}}'}</code> are filled in when a page is started, and a credential block with only a label is a slot to fill from that client’s vault.
	</p>
	<div class="grid items-start gap-5 xl:grid-cols-[24rem_minmax(0,1fr)]">
		<section class="card" aria-labelledby="cats-h">
			<header class="panel-head">
				<div>
					<h2 id="cats-h" class="panel-title">Categories</h2>
					<p class="text-muted text-xs">In this order on every client’s Docs tab.</p>
				</div>
			</header>
			<Async res={cats} compact>
				{#snippet children(rows)}
					{#if rows.length}
						<ol class="divide-border divide-y">
							{#each rows as c, i (c.id)}
								<li class="flex min-h-12 items-center gap-2 px-4 py-1.5">
									{#if renaming?.id === c.id}
										<form class="flex min-w-0 flex-1 items-center gap-1" onsubmit={rename}>
											<!-- svelte-ignore a11y_autofocus -->
											<Input bind:value={renaming.name} aria-label="New name for {c.name}" maxlength={100} required autofocus class="h-8" onkeydown={(e) => e.key === 'Escape' && (renaming = null)} />
											<IconButton icon={Check} size="sm" type="submit" label="Save name" />
											<IconButton icon={X} size="sm" label="Cancel" onclick={() => (renaming = null)} />
										</form>
									{:else}
										<div class="min-w-0 flex-1">
											<div class="truncate text-sm font-medium">{c.name}</div>
											<div class="text-muted text-xs">{plural(c.docs, 'page')} · {plural(c.templates, 'template')}</div>
										</div>
										<div class="flex shrink-0 items-center">
											<IconButton id="cat-{c.id}-up" icon={ArrowUp} size="sm" label="Move {c.name} up" disabled={i === 0} onclick={() => move(rows, i, -1)} />
											<IconButton id="cat-{c.id}-down" icon={ArrowDown} size="sm" label="Move {c.name} down" disabled={i === rows.length - 1} onclick={() => move(rows, i, 1)} />
											<IconButton icon={Pencil} size="sm" label="Rename {c.name}" onclick={() => (renaming = { id: c.id, name: c.name })} />
											<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {c.name}" onclick={() => removeCategory(c)} />
										</div>
									{/if}
								</li>
							{/each}
						</ol>
					{:else}
						<EmptyState compact icon={FolderOpen} title="No categories" description="Pages can still be written; they’re listed as uncategorised." />
					{/if}
				{/snippet}
			</Async>
			<form class="border-border flex gap-2 border-t px-4 py-3" onsubmit={add}>
				<Input bind:value={newName} placeholder="New category" aria-label="New category name" maxlength={100} class="h-8" />
				<Button type="submit" size="sm" icon={Plus} loading={adding} disabled={!newName.trim()}>Add</Button>
			</form>
		</section>

		<section class="card" aria-labelledby="tpl-h">
			<header class="panel-head">
				<div>
					<h2 id="tpl-h" class="panel-title">Templates</h2>
					<p class="text-muted text-xs">Changing a template doesn’t touch pages already started from it.</p>
				</div>
				<Button variant="primary" size="sm" icon={Plus} href="?template=new">New template</Button>
			</header>
			<Async res={templates} compact>
				{#snippet children(rows)}
					{#if rows.length}
						{#each grouped as g (g.key)}
							<h3 class="text-muted bg-sunken/60 border-border border-b px-4 py-1.5 font-sans text-xs font-medium">{g.name}</h3>
							<ul class="divide-border border-border divide-y border-b last:border-b-0">
								{#each g.rows as t (t.id)}
									<li class="flex items-center gap-3 px-4 py-2.5">
										<LayoutTemplate class="text-subtle size-4 shrink-0" aria-hidden="true" />
										<div class="min-w-0 flex-1">
											<a class="hover:text-accent text-sm font-medium" href="?template={t.id}">{t.name}</a>
											<p class="text-muted truncate text-xs">{t.description || 'No description'}</p>
										</div>
										<span class="text-muted hidden shrink-0 text-xs md:inline">Updated {ago(t.updated_at)}{t.updated_by_name ? ` by ${t.updated_by_name}` : ''}</span>
										<div class="flex shrink-0 items-center">
											<IconButton icon={Pencil} size="sm" label="Edit {t.name}" href="?template={t.id}" />
											<IconButton icon={CopyPlus} size="sm" label="Duplicate {t.name}" onclick={() => duplicate(t)} />
											<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {t.name}" onclick={() => removeTemplate(t)} />
										</div>
									</li>
								{/each}
							</ul>
						{/each}
					{:else}
						<EmptyState compact icon={LayoutTemplate} title="No templates" description="Write one for the pages every client needs: the network, the servers, backups.">
							{#snippet action()}<Button size="sm" icon={Plus} href="?template=new">New template</Button>{/snippet}
						</EmptyState>
					{/if}
				{/snippet}
			</Async>
		</section>
	</div>
{/if}
