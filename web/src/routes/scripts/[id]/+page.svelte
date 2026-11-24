<script lang="ts">
	import { beforeNavigate, goto } from '$app/navigation';
	import { untrack } from 'svelte';
	import { page } from '$app/state';
	import { Save, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { datetime, interpreters } from '#lib/format.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Interpreter, ParamSpec, Script } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import CodeEditor from '#lib/components/CodeEditor.svelte';
	import ParamsEditor from '#lib/components/scripts/ParamsEditor.svelte';

	/** The script editor; `/scripts/new` creates one. */
	type Draft = { name: string; description: string; interpreter: Interpreter; body: string; timeout_secs: number; client_id: string | null; params: ParamSpec[] };
	const isNew = $derived(page.params.id === 'new');
	let script = $state<Script | null>(null);
	let draft = $state<Draft | null>(null);
	let saved = $state('');
	let error = $state<Error | null>(null);
	let busy = $state(false);

	$effect(() => {
		untrack(() => loadClients());
		const id = page.params.id!;
		error = null;
		if (id === 'new') {
			script = null;
			// Built locally: reading `draft` back here would make the effect depend on itself.
			const d: Draft = { name: '', description: '', interpreter: 'powershell', body: '', timeout_secs: 300, client_id: can('admin') ? null : (untrack(() => clients.list[0]?.id) ?? null), params: [] };
			draft = d;
			saved = JSON.stringify(d);
			return;
		}
		draft = null;
		api.get<Script>(`/scripts/${id}`)
			.then((s) => {
				script = s;
				const d: Draft = { name: s.name, description: s.description, interpreter: s.interpreter, body: s.body, timeout_secs: s.timeout_secs, client_id: s.client_id, params: s.params ?? [] };
				draft = d;
				saved = JSON.stringify(d);
			})
			.catch((e) => (error = e));
	});

	// MSP-wide scripts run on every client, so only admins change them.
	const editable = $derived(draft ? (draft.client_id === null && !isNew ? can('admin') : can('technician')) && (script ? (script.client_id === null ? can('admin') : true) : true) : false);
	const dirty = $derived(!!draft && JSON.stringify(draft) !== saved);

	// Unsaved changes: ask before leaving. Closing the tab gets the browser's own prompt.
	let leaving = false;
	beforeNavigate(({ cancel, to, type }) => {
		if (!dirty || busy || leaving || !to) return;
		cancel();
		if (type === 'leave') return;
		confirmAction({ title: 'Discard changes?', message: 'Your edits to this script haven’t been saved.', confirmLabel: 'Discard', danger: true }).then((ok) => {
			if (!ok) return;
			leaving = true;
			goto(to.url);
		});
	});

	async function save(e?: SubmitEvent) {
		e?.preventDefault();
		if (!draft) return;
		busy = true;
		try {
			if (isNew) {
				const s = await api.post<Script>('/scripts', draft);
				saved = JSON.stringify(draft);
				toast.success(`${s.name} saved.`);
				await goto(`/scripts/${s.id}`, { replace: true });
			} else {
				script = await api.put<Script>(`/scripts/${script!.id}`, draft);
				saved = JSON.stringify(draft);
				toast.success('Saved.');
			}
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	async function remove() {
		const ok = await confirmAction({ title: `Delete ${script!.name}?`, message: 'Past jobs keep their copy of the script.', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/scripts/${script!.id}`), `${script!.name} deleted.`))) {
			saved = JSON.stringify(draft);
			await goto('/scripts');
		}
	}
	function onkeydown(e: KeyboardEvent) {
		if ((e.ctrlKey || e.metaKey) && e.key === 's' && editable) {
			e.preventDefault();
			save();
		}
	}
</script>

<svelte:window {onkeydown} />
<svelte:head><title>{isNew ? 'New script' : (script?.name ?? 'Script')}</title></svelte:head>

{#if error}
	<div class="card"><ErrorState {error} onretry={() => goto(page.url.pathname, { refreshAll: true })} /></div>
{:else if !draft}
	<div class="mb-4 space-y-2"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-64" /></div>
	<div class="card space-y-3 p-4"><Skeleton lines={3} /><Skeleton class="h-72 w-full" /></div>
{:else}
	<PageHeader
		title={isNew ? 'New script' : script!.name}
		crumbs={[{ label: 'Scripts', href: '/scripts' }, { label: isNew ? 'New' : script!.name }]}
		menu={!isNew && editable ? [{ label: 'Delete script…', icon: Trash2, danger: true, onSelect: remove }] : undefined}
	>
		{#snippet meta()}
			{#if dirty}<span class="text-warning text-xs font-medium">Unsaved changes</span>{:else if script}<span class="text-muted text-xs">Updated {datetime(script.updated_at)}</span>{/if}
		{/snippet}
		{#snippet actions()}
			{#if editable}<Button variant="primary" icon={Save} type="submit" form="script-form" loading={busy} disabled={!dirty || !draft?.name.trim()}>Save</Button>{/if}
		{/snippet}
	</PageHeader>
	{#if !editable}<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm">Read only: MSP-wide scripts can only be changed by admins.</p>{/if}

	<form id="script-form" class="grid gap-4 xl:grid-cols-[22rem_1fr]" onsubmit={save}>
		<div class="space-y-4 self-start">
		<fieldset class="card space-y-3 p-4" disabled={!editable}>
			<Field label="Name" id="s-name" required><Input id="s-name" bind:value={draft.name} required maxlength={200} /></Field>
			<Field label="Description" id="s-desc"><Input id="s-desc" bind:value={draft.description} placeholder="What it does, when to run it" /></Field>
			<div class="grid grid-cols-2 gap-3">
				<Field label="Interpreter" id="s-interp"><Select id="s-interp" bind:value={draft.interpreter} options={interpreters.map((i) => ({ value: i.value, label: i.label }))} /></Field>
				<Field label="Timeout (s)" id="s-timeout"><Input id="s-timeout" type="number" min="1" max="86400" bind:value={draft.timeout_secs} /></Field>
			</div>
			<Field label="Scope" id="s-scope" hint={draft.client_id ? 'Runs only on this client’s agents; its technicians can edit it.' : 'Runs on every client’s agents; only admins can edit it.'}>
				<Select
					id="s-scope"
					bind:value={draft.client_id}
					options={[...(can('admin') ? [{ value: null, label: 'All clients (MSP-wide)' }] : []), ...clients.list.map((c) => ({ value: c.id, label: `${c.name} only` }))]}
				/>
			</Field>
			<p class="text-muted text-xs">Arguments and parameter values are given when you run it. <kbd class="kbd">{navigator.platform.includes('Mac') ? '⌘' : 'Ctrl'}</kbd> <kbd class="kbd">S</kbd> saves.</p>
		</fieldset>
		<ParamsEditor bind:params={draft.params} disabled={!editable} />
		</div>
		<div class="min-w-0">
			<label class="label" for="s-body">Script</label>
			<CodeEditor id="s-body" bind:value={draft.body} interpreter={draft.interpreter} minHeight="min(60vh, 32rem)" readonly={!editable} />
		</div>
	</form>
{/if}
