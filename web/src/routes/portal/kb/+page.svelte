<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { BookOpen, Search } from '@lucide/svelte';
	import { ago, datetime } from '#lib/format.js';
	import { portal, qs } from '#lib/portal/api.js';
	import type { KbSummary } from '#lib/portal/types.js';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	const q = $derived(page.url.searchParams.get('q') ?? '');
	let search = $state(page.url.searchParams.get('q') ?? '');
	let articles = $state<KbSummary[] | null>(null);
	let error = $state('');
	let seq = 0;

	async function load() {
		const n = ++seq;
		error = '';
		try {
			const rows = await portal.get<KbSummary[]>(`/kb${qs({ q })}`);
			if (n === seq) articles = rows;
		} catch (e) {
			if (n === seq) error = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		void q;
		articles = null;
		load();
	});

	let timer: ReturnType<typeof setTimeout> | undefined;
	function apply() {
		clearTimeout(timer);
		goto(`/portal/kb${qs({ q: search.trim() })}`, { replace: true, reset: false });
	}
	function oninput() {
		clearTimeout(timer);
		timer = setTimeout(apply, 300);
	}

	const groups = $derived.by(() => {
		const m = new Map<string, KbSummary[]>();
		for (const a of articles ?? []) {
			const c = a.category.trim() || 'General';
			if (!m.has(c)) m.set(c, []);
			m.get(c)!.push(a);
		}
		return [...m.entries()];
	});
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-medium">Knowledge base</h1>
		<p class="text-muted mt-1 text-sm">Guides and answers to common questions.</p>
	</div>

	<form role="search" class="max-w-lg" onsubmit={(e) => (e.preventDefault(), apply())}>
		<label for="kb-search" class="sr-only">Search articles</label>
		<Input id="kb-search" type="search" icon={Search} placeholder="Search articles" bind:value={search} {oninput} class="h-10" />
	</form>

	{#if error}
		<div class="card"><ErrorState {error} onretry={load} /></div>
	{:else if !articles}
		<div class="card p-4"><Skeleton lines={6} /></div>
	{:else if !articles.length}
		<div class="card">
			<EmptyState icon={BookOpen} title={q ? 'No matching articles' : 'No articles yet'} description={q ? 'Try different words, or send us a request.' : undefined} />
		</div>
	{:else}
		{#each groups as [category, list], gi (category)}
			<section class="card" aria-labelledby="cat-{gi}">
				<h2 id="cat-{gi}" class="panel-head panel-title">{category}</h2>
				<ul class="divide-border divide-y">
					{#each list as a (a.id)}
						<li>
							<a href="/portal/kb/{a.id}" class="hover:bg-hover focus-visible:bg-hover group block px-4 py-3 focus-visible:outline-none">
								<span class="text-accent font-medium group-hover:underline group-focus-visible:underline">{a.title}</span>
								{#if a.excerpt}<p class="text-muted mt-1 line-clamp-2 text-sm break-words">{a.excerpt}</p>{/if}
								<p class="text-muted mt-1 text-xs">Updated <time datetime={a.updated_at} title={datetime(a.updated_at)}>{ago(a.updated_at)}</time></p>
							</a>
						</li>
					{/each}
				</ul>
			</section>
		{/each}
	{/if}
</div>
