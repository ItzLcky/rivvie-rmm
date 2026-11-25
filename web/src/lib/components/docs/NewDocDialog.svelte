<script lang="ts">
	import { Check, FilePlus2, FileUp, LayoutTemplate } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { fillPlaceholders, isoToday, parseFrontMatter } from '#lib/docs/markdown.js';
	import type { DocCategory, DocTemplate } from '#lib/docs/types.js';
	import { session } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import type { DocDraft } from './DocEditor.svelte';

	/**
	 * New page: a title, a category, and where to start: blank, one of the category's templates,
	 * or a `.md` file. Nothing is saved here; the editor opens with the draft.
	 */
	let {
		clientName,
		categories,
		templates,
		onstart,
		onclose
	}: { clientName: string; categories: DocCategory[]; templates: DocTemplate[] | undefined; onstart: (d: DocDraft) => void; onclose: () => void } = $props();

	let title = $state('');
	let category = $state<string | null>(null);
	let template = $state<string | null>(null);
	let busy = $state(false);
	let titleTouched = false;

	const shown = $derived((templates ?? []).filter((t) => category === null || t.category_id === category));
	const catName = (id: string | null) => categories.find((c) => c.id === id)?.name ?? '';

	function choose(t: DocTemplate | null) {
		template = t?.id ?? null;
		if (!t) return;
		// Choosing a template also files the page under its category.
		if (t.category_id) category = t.category_id;
		if (!titleTouched || !title.trim()) title = t.name;
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			let body = '';
			if (template) {
				const t = await api.get<DocTemplate>(`/doc-templates/${template}`);
				body = fillPlaceholders(t.body ?? '', { 'client.name': clientName, date: isoToday(), 'user.name': session.user?.name ?? '' });
			}
			onstart({ title: title.trim(), category_id: category, body, description: '' });
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}

	let file = $state<HTMLInputElement>();
	async function imported(e: Event) {
		const f = (e.currentTarget as HTMLInputElement).files?.[0];
		if (!f) return;
		if (f.size > 2_000_000) {
			toast.error(`${f.name} is too big for a page (pages hold up to 200,000 characters).`);
			return;
		}
		const { meta, body } = parseFrontMatter(await f.text());
		const name = meta.category?.trim();
		const cat = name ? categories.find((c) => c.name.toLowerCase() === name.toLowerCase()) : undefined;
		if (name && !cat) toast.info(`There’s no “${name}” category, so the page starts uncategorised.`);
		onstart({ title: (meta.title?.trim() || f.name.replace(/\.(md|markdown|txt)$/i, '')).slice(0, 300), category_id: cat?.id ?? category, body, description: '' });
	}
</script>

<Modal title="New page" description="Nothing is saved until you press Save in the editor." {onclose} size="lg">
	<form id="new-doc" class="space-y-5" onsubmit={submit}>
		<div class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_14rem]">
			<Field label="Title" id="new-doc-title" required>
				<!-- svelte-ignore a11y_autofocus -->
				<Input id="new-doc-title" bind:value={title} oninput={() => (titleTouched = true)} maxlength={300} required autofocus />
			</Field>
			<Field label="Category" id="new-doc-cat">
				<Select
					id="new-doc-cat"
					class="w-full"
					bind:value={category}
					onchange={() => {
						if (template && !shown.some((t) => t.id === template)) template = null;
					}}
					options={[{ value: null, label: 'No category' }, ...categories.map((c) => ({ value: c.id as string | null, label: c.name }))]}
				/>
			</Field>
		</div>
		<fieldset>
			<legend class="label">Start from</legend>
			<div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
				{#snippet card(t: DocTemplate | null)}
					{@const on = template === (t?.id ?? null)}
					<label
						class={cx(
							'border-border hover:border-border-strong flex min-h-20 cursor-pointer flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-[var(--focus)]',
							on && 'border-accent bg-accent-soft/60 hover:border-accent ring-accent/30 ring-2'
						)}
					>
						<input type="radio" name="new-doc-template" class="sr-only" checked={on} onchange={() => choose(t)} />
						<span class="flex w-full items-center gap-2">
							{#if t}<LayoutTemplate class="text-muted size-4 shrink-0" aria-hidden="true" />{:else}<FilePlus2 class="text-muted size-4 shrink-0" aria-hidden="true" />{/if}
							<span class="min-w-0 flex-1 truncate text-sm font-medium">{t?.name ?? 'Blank page'}</span>
							<Check class={cx('text-accent size-4 shrink-0', !on && 'invisible')} aria-hidden="true" />
						</span>
						<span class="text-muted line-clamp-2 text-xs">{t ? t.description || 'No description' : 'Start from nothing.'}</span>
						{#if t && category === null && t.category_id}<span class="text-muted text-xs">{catName(t.category_id)}</span>{/if}
					</label>
				{/snippet}
				{@render card(null)}
				{#if templates === undefined}
					{#each [0, 1] as i (i)}<div class="border-border space-y-2 rounded-lg border p-3"><Skeleton class="h-4 w-32" /><Skeleton class="h-3 w-full" /></div>{/each}
				{:else}
					{#each shown as t (t.id)}{@render card(t)}{/each}
				{/if}
			</div>
			{#if templates && !shown.length && category !== null}
				<p class="hint">No templates in {catName(category)} yet. Admins add them under Company settings → Documentation.</p>
			{/if}
		</fieldset>
	</form>
	{#snippet footer()}
		<Button class="mr-auto" icon={FileUp} onclick={() => file?.click()}>Import .md</Button>
		<input bind:this={file} type="file" accept=".md,.markdown,.txt,text/markdown,text/plain" class="hidden" onchange={imported} aria-label="Import a Markdown file" />
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="new-doc" loading={busy} disabled={!title.trim()}>Open in the editor</Button>
	{/snippet}
</Modal>
