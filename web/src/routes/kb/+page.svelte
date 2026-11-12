<script lang="ts">
	import { BookOpen, Globe, Lock, Plus, Search } from '@lucide/svelte';
	import { goto } from '$app/navigation';
	import { api, qs } from '#lib/api.js';
	import { ago } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { KbArticle } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import KbEditor from '#lib/components/KbEditor.svelte';

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	$effect(() => {
		loadClients();
	});
	const category = $derived(param('category'));
	const list = resource(() => api.get<KbArticle[]>(`/kb${qs({ q: param('q'), category })}`));
	const all = resource(() => api.get<KbArticle[]>('/kb'));
	const categories = $derived([...new Set((all.data ?? []).map((a) => a.category).filter(Boolean))].sort((a, b) => a.localeCompare(b)));
	let creating = $state(false);

	function grouped(rows: KbArticle[]) {
		const m = new Map<string, KbArticle[]>();
		for (const a of rows) m.set(a.category || 'Uncategorised', [...(m.get(a.category || 'Uncategorised') ?? []), a]);
		return [...m.entries()];
	}
</script>

<PageHeader title="Knowledge base" description="How-tos and runbooks. Articles shown in the client portal are marked Public.">
	{#snippet actions()}{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (creating = true)}>New article</Button>{/if}{/snippet}
</PageHeader>

<div class="mb-4 flex flex-wrap gap-2">
	<Input icon={Search} data-search placeholder="Search articles…" aria-label="Search articles" class="min-w-0 flex-1 sm:w-80 sm:flex-none" bind:value={q} />
	<Select aria-label="Category" class="w-full sm:w-auto" value={category} onchange={(e) => setParams({ category: e.currentTarget.value })} options={[{ value: '', label: 'Every category' }, ...categories.map((c) => ({ value: c, label: c }))]} />
</div>

<Async res={list}>
	{#snippet children(rows)}
		{#if rows.length}
			<div class="space-y-4">
				{#each grouped(rows) as [cat, items] (cat)}
					<section class="card" aria-label={cat}>
						<h2 class="border-border panel-title border-b px-4 py-3">{cat}</h2>
						<ul class="divide-border divide-y">
							{#each items as a (a.id)}
								<li>
									<a href="/kb/{a.id}" class="hover:bg-hover flex items-start gap-3 px-4 py-3 text-sm">
										<div class="min-w-0 flex-1">
											<div class="flex flex-wrap items-center gap-1.5 font-medium">
												{a.title}
												{#if a.public}<Badge tone="info" icon={Globe}>Public</Badge>{:else}<Badge icon={Lock}>Internal</Badge>{/if}
												{#if a.client_name}<Badge>{a.client_name}</Badge>{/if}
											</div>
											<p class="text-muted line-clamp-2 text-xs">{a.excerpt}</p>
										</div>
										<span class="text-muted shrink-0 text-xs">{ago(a.updated_at)}</span>
									</a>
								</li>
							{/each}
						</ul>
					</section>
				{/each}
			</div>
		{:else}
			<div class="card"><EmptyState icon={BookOpen} title={param('q') || category ? 'No matching articles' : 'No articles yet'} description="Write down fixes once; share the client-facing ones in the portal." /></div>
		{/if}
	{/snippet}
</Async>

{#if creating}<KbEditor article={null} {categories} onclose={() => (creating = false)} onsaved={(a) => goto(`/kb/${a.id}`)} />{/if}
