<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Globe, Lock, Pencil, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { KbArticle } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import KbEditor from '#lib/components/KbEditor.svelte';

	const id = $derived(page.params.id!);
	const res = resource(() => api.get<KbArticle>(`/kb/${id}`), { keep: false });
	$effect(() => {
		loadClients();
	});
	let editing = $state(false);

	async function remove(a: KbArticle) {
		if (await confirmAction({ title: `Delete ${a.title}?`, confirmLabel: 'Delete article', danger: true })) {
			if (await attempt(() => api.del(`/kb/${a.id}`), 'Article deleted.')) goto('/kb');
		}
	}
</script>

<Async {res}>
	{#snippet children(a)}
		<PageHeader title={a.title} crumbs={[{ label: 'Knowledge base', href: '/kb' }, ...(a.category ? [{ label: a.category, href: `/kb?category=${encodeURIComponent(a.category)}` }] : [])]}>
			{#snippet subtitle()}
				{#if a.public}<Badge tone="info" icon={Globe}>Public in the portal</Badge>{:else}<Badge icon={Lock}>Internal</Badge>{/if}
				{#if a.client_name}<span>for {a.client_name}</span>{/if}
				<span>Updated {datetime(a.updated_at)}{#if a.updated_by_name}{` by ${a.updated_by_name}`}{/if}</span>
			{/snippet}
			{#snippet actions()}
				{#if can('technician')}
					<Button icon={Pencil} onclick={() => (editing = true)}>Edit</Button>
					<Button variant="danger-ghost" icon={Trash2} onclick={() => remove(a)}>Delete</Button>
				{/if}
			{/snippet}
		</PageHeader>
		<article class="card max-w-3xl p-6 text-sm leading-relaxed break-words whitespace-pre-wrap">{a.body || 'This article is empty.'}</article>
		{#if editing}<KbEditor article={a} onclose={() => (editing = false)} onsaved={() => res.reload()} />{/if}
	{/snippet}
</Async>
