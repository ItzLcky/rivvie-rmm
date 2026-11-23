<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Bookmark, BookmarkPlus, ChevronDown, Settings2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { SavedView } from '#lib/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu, { type MenuItem } from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/**
	 * Named list states: the filters and sort of the page's URL, and the columns it hides. A view is
	 * personal, or shared with the whole team (technicians may share). Choosing one just navigates, so
	 * everything it holds stays in the URL like any other state of the page.
	 */
	let { pageId, path, keys, columnTable, defaultHidden }: { pageId: string; path: string; keys: string[]; columnTable: string; defaultHidden: string[] } = $props();

	const views = resource(() => api.get<SavedView[]>(`/saved-views?page=${pageId}`));

	/** The URL's state, as a view would store it: only its own keys, in a stable order. */
	function currentQuery(): string {
		const u = new URLSearchParams();
		for (const k of keys) {
			const v = page.url.searchParams.get(k);
			if (v) u.set(k, v);
		}
		return u.toString();
	}
	const canon = (q: string) => [...new URLSearchParams(q).entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('&');
	const active = $derived(views.data?.find((v) => canon(v.query) === canon(currentQuery())));

	function apply(v: SavedView) {
		if (v.hidden_columns) setPref('columns', { ...prefs.columns, [columnTable]: v.hidden_columns });
		goto(v.query ? `${path}?${v.query}` : path);
	}

	let saving = $state(false);
	let managing = $state(false);
	let name = $state('');
	let shared = $state(false);
	let withColumns = $state(true);
	let busy = $state(false);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		const ok = await attempt(
			() => api.post('/saved-views', { page: pageId, name: name.trim(), query: currentQuery(), shared, hidden_columns: withColumns ? (prefs.columns?.[columnTable] ?? defaultHidden) : null }),
			`View ${name.trim()} saved.`
		);
		busy = false;
		if (ok) {
			saving = false;
			views.reload();
		}
	}
	async function remove(v: SavedView) {
		const ok = await confirmAction({ title: `Delete ${v.name}?`, message: v.shared ? 'It is shared: everyone loses it.' : undefined, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/saved-views/${v.id}`), `${v.name} deleted.`))) views.reload();
	}
	async function share(v: SavedView, on: boolean) {
		if (await attempt(() => api.put(`/saved-views/${v.id}`, { shared: on }))) views.reload();
	}
	/** Replaces the view's filters and columns with what the page shows now. */
	async function update(v: SavedView) {
		if (await attempt(() => api.put(`/saved-views/${v.id}`, { query: currentQuery(), hidden_columns: prefs.columns?.[columnTable] ?? defaultHidden }), `${v.name} updated.`)) views.reload();
	}

	const items = $derived.by<MenuItem[]>(() => {
		const all = views.data ?? [];
		const mine = all.filter((v) => !v.shared);
		const team = all.filter((v) => v.shared);
		const out: MenuItem[] = [];
		if (mine.length) out.push({ heading: 'My views' }, ...mine.map((v) => ({ label: v.name, onSelect: () => apply(v), hint: v.id === active?.id ? 'current' : undefined })));
		if (team.length) out.push({ heading: 'Shared views' }, ...team.map((v) => ({ label: v.name, onSelect: () => apply(v), hint: v.id === active?.id ? 'current' : v.owner_name })));
		if (!all.length) out.push({ heading: 'No saved views yet' });
		out.push({ separator: true }, { label: 'Save this view…', icon: BookmarkPlus, onSelect: () => ((name = ''), (shared = false), (withColumns = true), (saving = true)) });
		if (all.some((v) => v.can_edit)) out.push({ label: 'Manage views…', icon: Settings2, onSelect: () => (managing = true) });
		return out;
	});
</script>

<Menu {items} label="Saved views" align="start">
	{#snippet trigger(props)}
		<Button {...props} icon={Bookmark} iconRight={ChevronDown} class="max-w-48">
			<span class="truncate">{active ? active.name : 'Views'}</span>
		</Button>
	{/snippet}
</Menu>

{#if saving}
	<Modal title="Save this view" description="The filters and sort you have now, and the columns you show." onclose={() => (saving = false)} size="sm">
		<form id="save-view" class="space-y-4" onsubmit={save}>
			<Field label="Name" id="view-name"><Input id="view-name" bind:value={name} maxlength={60} required /></Field>
			<Checkbox bind:checked={withColumns}>Remember which columns are shown</Checkbox>
			{#if can('technician')}<div><Switch bind:checked={shared}>Share with everyone on the team</Switch></div>{/if}
		</form>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (saving = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="save-view" loading={busy} disabled={!name.trim()}>Save view</Button>
		{/snippet}
	</Modal>
{/if}

{#if managing}
	<Modal title="Manage views" onclose={() => (managing = false)} size="md">
		<ul class="divide-border divide-y" aria-label="Saved views">
			{#each (views.data ?? []).filter((v) => v.can_edit) as v (v.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5">
					<span class="min-w-0 flex-1"><span class="block truncate font-medium">{v.name}</span><span class="text-muted block truncate font-mono text-xs">{v.query || 'no filters'}</span></span>
					{#if can('technician')}<Switch checked={v.shared} label="Share {v.name}" onchange={(c) => share(v, c)} />{/if}
					<Button size="sm" onclick={() => update(v)} title="Replace it with what the page shows now">Update</Button>
					<Button size="sm" variant="danger-ghost" onclick={() => remove(v)}>Delete</Button>
				</li>
			{/each}
		</ul>
		{#snippet footer()}<Button onclick={() => (managing = false)}>Done</Button>{/snippet}
	</Modal>
{/if}
