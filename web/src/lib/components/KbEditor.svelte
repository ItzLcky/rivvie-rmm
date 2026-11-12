<script lang="ts">
	import { api } from '#lib/api.js';
	import { clients } from '#lib/scope.svelte.js';
	import { session } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { KbArticle } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Writes a new article, or edits `article` (which must include its body). */
	let { article, categories = [], onclose, onsaved }: { article: KbArticle | null; categories?: string[]; onclose: () => void; onsaved: (a: KbArticle) => void } = $props();

	// svelte-ignore state_referenced_locally
	const a = article;
	const everyone = session.user?.client_ids === null;
	let f = $state({
		title: a?.title ?? '',
		category: a?.category ?? '',
		body: a?.body ?? '',
		public: a?.public ?? false,
		client_id: a?.client_id ?? (everyone ? '' : (clients.list[0]?.id ?? ''))
	});
	let busy = $state(false);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const body = { ...f, client_id: f.client_id || null };
			const saved = a ? await api.put<KbArticle>(`/kb/${a.id}`, body) : await api.post<KbArticle>('/kb', body);
			toast.success(`${saved.title} saved.`);
			onsaved(saved);
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title={a ? `Edit ${a.title}` : 'New article'} {onclose} size="lg">
	<form id="kb-form" class="space-y-4" onsubmit={save}>
		<div class="grid gap-3 sm:grid-cols-[2fr_1fr]">
			<Field label="Title" id="kb-title" required>
				<!-- svelte-ignore a11y_autofocus -->
				<Input id="kb-title" bind:value={f.title} required maxlength={300} autofocus />
			</Field>
			<Field label="Category" id="kb-cat">
				<Input id="kb-cat" bind:value={f.category} maxlength={100} list="kb-categories" placeholder="Accounts" />
				<datalist id="kb-categories">{#each categories as c (c)}<option value={c}></option>{/each}</datalist>
			</Field>
		</div>
		<Field label="Article" id="kb-body" hint="Plain text; line breaks are kept.">
			<Textarea id="kb-body" rows={14} bind:value={f.body} />
		</Field>
		<div class="grid gap-3 sm:grid-cols-2 sm:items-end">
			<Field label="For" id="kb-client">
				<Select
					id="kb-client"
					class="w-full"
					bind:value={f.client_id}
					options={[...(everyone ? [{ value: '', label: 'Every client' }] : []), ...clients.list.map((c) => ({ value: c.id, label: c.name }))]}
				/>
			</Field>
			<Switch bind:checked={f.public}>Show in the client portal</Switch>
		</div>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="kb-form" loading={busy} disabled={!f.title.trim()}>Save</Button>
	{/snippet}
</Modal>
