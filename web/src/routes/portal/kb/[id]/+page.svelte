<script lang="ts">
	import { page } from '$app/state';
	import { ArrowLeft, Plus } from '@lucide/svelte';
	import { datetime } from '#lib/format.js';
	import { portal, PortalError } from '#lib/portal/api.js';
	import type { KbArticle } from '#lib/portal/types.js';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	const id = $derived(page.params.id ?? '');
	let article = $state<KbArticle | null>(null);
	let error = $state('');
	let missing = $state(false);
	let seq = 0;

	async function load() {
		const n = ++seq;
		article = null;
		error = '';
		missing = false;
		try {
			const a = await portal.get<KbArticle>(`/kb/${id}`);
			if (n === seq) article = a;
		} catch (e) {
			if (n !== seq) return;
			if (e instanceof PortalError && (e.status === 404 || e.status === 400)) missing = true;
			else error = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		void id;
		load();
	});
</script>

<svelte:head>
	{#if article}<title>{article.title} · Support portal</title>{/if}
</svelte:head>

<div class="mx-auto max-w-3xl space-y-6">
	<a href="/portal/kb" class="text-muted hover:text-fg inline-flex items-center gap-1 text-sm"><ArrowLeft class="size-4" aria-hidden="true" />Knowledge base</a>

	{#if missing}
		<div class="card"><EmptyState title="Article not found" description="It may have been moved or removed." /></div>
	{:else if error}
		<div class="card"><ErrorState {error} onretry={load} /></div>
	{:else if !article}
		<div class="card p-6"><Skeleton lines={10} /></div>
	{:else}
		<article class="card p-5 sm:p-8">
			{#if article.category}<p class="text-muted text-xs font-medium tracking-wide uppercase">{article.category}</p>{/if}
			<h1 class="mt-1 text-2xl font-semibold tracking-tight break-words">{article.title}</h1>
			<p class="text-muted mt-1 text-xs">Updated <time datetime={article.updated_at}>{datetime(article.updated_at)}</time></p>
			<!-- Plain text: line breaks kept, nothing interpreted as markup. -->
			<div class="mt-6 text-[0.9375rem] leading-relaxed break-words whitespace-pre-wrap">{article.body}</div>
		</article>
		<div class="card flex flex-col items-start gap-3 p-4 sm:flex-row sm:items-center">
			<p class="flex-1 text-sm">Didn't solve it? Send us a request and we'll help.</p>
			<Button href="/portal/tickets/new" icon={Plus}>New request</Button>
		</div>
	{/if}
</div>
