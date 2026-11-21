<script lang="ts" module>
	export interface DocDraft {
		title: string;
		category_id: string | null;
		body: string;
		/** Templates only. */
		description: string;
	}
	export type SaveResult = 'ok' | 'conflict' | 'error';
</script>

<script lang="ts">
	import { beforeNavigate, goto } from '$app/navigation';
	import { SvelteMap } from 'svelte/reactivity';
	import type { Snippet } from 'svelte';
	import {
		Bold,
		ChevronDown,
		Code,
		Heading,
		Italic,
		Link,
		List,
		ListChecks,
		ListOrdered,
		Plus,
		Save,
		Table,
		TextQuote,
		TriangleAlert
	} from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { cx } from '#lib/format.js';
	import { BLOCKS, type BlockSegment, type DocContext } from '#lib/docs/blocks.js';
	import { credentialFence, replaceLines } from '#lib/docs/markdown.js';
	import type { DocCategory, VaultItem } from '#lib/docs/types.js';
	import { vaultAccess, vaultProblem, type VaultProblem } from '#lib/docs/vault.js';
	import type { AgentSummary, Page } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Kbd from '#lib/ui/Kbd.svelte';
	import Menu, { type MenuItem } from '#lib/ui/Menu.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import VaultPicker from '#lib/components/vault/VaultPicker.svelte';
	import DocView from './DocView.svelte';
	import MarkdownEditor from './MarkdownEditor.svelte';
	import CalloutForm from './insert/CalloutForm.svelte';
	import DevicePicker from './insert/DevicePicker.svelte';
	import SlotForm from './insert/SlotForm.svelte';

	/**
	 * Edits a page (or, under Company settings, a template) in place: title and category, a
	 * formatting toolbar, Markdown source beside a live preview (a Write / Preview switch below
	 * `lg`). Leaving with unsaved changes asks first. The caller saves; a stale save comes back
	 * as `conflict` and is offered again as an overwrite.
	 */
	let {
		mode = 'doc',
		heading,
		initial,
		categories,
		clientId = null,
		credentials = [],
		onsave,
		ondone,
		actions
	}: {
		mode?: 'doc' | 'template';
		heading: string;
		initial: DocDraft;
		categories: DocCategory[];
		clientId?: string | null;
		/** Vault items the page already links to. */
		credentials?: VaultItem[];
		/** Saves the draft; `force` skips the check for someone else's newer save. */
		onsave: (d: DocDraft, force: boolean) => Promise<SaveResult>;
		/** Saved or cancelled: close the editor. */
		ondone: (saved: boolean) => void;
		/** More buttons in the header (e.g. Import). */
		actions?: Snippet;
	} = $props();

	// svelte-ignore state_referenced_locally
	let draft = $state<DocDraft>({ ...initial });
	// svelte-ignore state_referenced_locally
	let clean = $state(JSON.stringify(initial));
	const dirty = $derived(JSON.stringify(draft) !== clean);
	let saving = $state(false);
	let conflict = $state(false);
	let leaving = false;
	let pane = $state<'write' | 'preview'>('write');
	let editor = $state<MarkdownEditor>();
	const isTemplate = $derived(mode === 'template');

	// --- what the preview's blocks can show -----------------------------------------------------
	// svelte-ignore state_referenced_locally
	const known = new SvelteMap<string, VaultItem>(credentials.map((c) => [c.id, c]));
	let problem = $state<VaultProblem | null>(null);
	// svelte-ignore state_referenced_locally
	if (clientId && vaultAccess() === 'ok') {
		api.get<VaultItem[]>(`/clients/${clientId}/vault`).then(
			(rows) => rows.forEach((r) => known.set(r.id, r)),
			(e) => (problem = vaultProblem(e))
		);
	}
	let agentList: Promise<Map<string, AgentSummary>> | null = null;
	const agents = () =>
		(agentList ??= api
			.get<Page<AgentSummary>>(`/agents?client_id=${clientId}&limit=500`)
			.then((p) => new Map(p.items.map((a) => [a.id, a])))
			.catch((e) => {
				agentList = null;
				throw e;
			}));
	const ctx = $derived<DocContext>({
		clientId,
		credentials: known,
		credentialsHidden: false,
		vaultProblem: problem,
		agents,
		chooseCredential: clientId ? (seg, label) => (picking = { seg, label }) : undefined
	});

	// --- credentials: filling a slot, or Insert block → Credential --------------------------------
	let picking = $state<{ seg: BlockSegment | null; label: string } | null>(null);
	function picked(item: VaultItem) {
		known.set(item.id, item);
		const p = picking!;
		picking = null;
		const block = credentialFence(item.id, p.label || undefined);
		if (p.seg) draft.body = replaceLines(draft.body, p.seg.from, p.seg.to, block);
		else editor?.insertBlock(block);
	}

	// --- Insert block -------------------------------------------------------------------------
	let form = $state<'callout' | 'device' | 'slot' | null>(null);
	let selectedText = $state('');
	const insertItems = $derived<MenuItem[]>(
		Object.values(BLOCKS).map((b) => {
			const off = b.needsClient && !clientId;
			return {
				label: b.label + (b.form && !off ? '…' : ''),
				icon: b.icon,
				hint: b.name === 'credential' && isTemplate ? 'slot' : undefined,
				disabled: off,
				title: off ? 'Add it on the page itself: a template has no client.' : b.description,
				onSelect: () => {
					if (b.form === 'credential') {
						if (clientId) picking = { seg: null, label: '' };
						else form = 'slot';
					} else if (b.form === 'callout') {
						selectedText = editor?.selected() ?? '';
						form = 'callout';
					} else if (b.form === 'device') form = 'device';
					else editor?.insertBlock(b.insert(), 'Label: value');
				}
			};
		})
	);
	function inserted(md: string) {
		form = null;
		editor?.insertBlock(md);
	}

	const tableMd = '| Column | Column | Column |\n|---|---|---|\n|  |  |  |\n|  |  |  |';
	const tools = [
		{ label: 'Bold', key: 'B', icon: Bold, run: () => editor?.wrap('**', '**', 'bold text') },
		{ label: 'Italic', key: 'I', icon: Italic, run: () => editor?.wrap('_', '_', 'italic text') },
		{ label: 'Heading', icon: Heading, run: () => editor?.prefixLines('## ', /^#{1,6}\s+/) },
		{ label: 'Bulleted list', icon: List, run: () => editor?.prefixLines('- ', /^\s*[-*+]\s+(?!\[[ xX]\])/) },
		{ label: 'Numbered list', icon: ListOrdered, run: () => editor?.prefixLines((i) => `${i + 1}. `, /^\s*\d+[.)]\s+/) },
		{ label: 'Checklist', icon: ListChecks, run: () => editor?.prefixLines('- [ ] ', /^\s*[-*+]\s+\[[ xX]\]\s+/) },
		{ label: 'Quote', icon: TextQuote, run: () => editor?.prefixLines('> ', /^>\s?/) },
		{ label: 'Link', key: 'K', icon: Link, run: () => editor?.wrap('[', '](https://)', 'link text') },
		{ label: 'Code', icon: Code, run: () => ((editor?.selected() ?? '').includes('\n') ? editor?.wrap('```\n', '\n```', 'code') : editor?.wrap('`', '`', 'code')) },
		{ label: 'Table', icon: Table, run: () => editor?.insertBlock(tableMd, 'Column') }
	];
	const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

	// --- saving and leaving -------------------------------------------------------------------
	async function save(force = false) {
		if (saving) return;
		if (!draft.title.trim()) {
			document.getElementById('doc-title-input')?.focus();
			return;
		}
		saving = true;
		const r = await onsave($state.snapshot(draft), force);
		saving = false;
		if (r === 'conflict') conflict = true;
		if (r !== 'ok') return;
		conflict = false;
		clean = JSON.stringify(draft);
		leaving = true;
		ondone(true);
	}
	async function cancel() {
		if (dirty && !(await confirmAction({ title: 'Discard changes?', message: 'Your edits haven’t been saved.', confirmLabel: 'Discard', danger: true }))) return;
		leaving = true;
		ondone(false);
	}
	beforeNavigate(({ cancel: stop, to, type }) => {
		if (!dirty || saving || leaving || !to) return;
		stop();
		if (type === 'leave') return;
		confirmAction({ title: 'Discard changes?', message: 'Your edits haven’t been saved.', confirmLabel: 'Discard', danger: true }).then((ok) => {
			if (!ok) return;
			leaving = true;
			ondone(false);
			goto(to.url);
		});
	});
	$effect(() => {
		if (!dirty) return;
		const warn = (e: BeforeUnloadEvent) => e.preventDefault();
		addEventListener('beforeunload', warn);
		return () => removeEventListener('beforeunload', warn);
	});
	function onkeydown(e: KeyboardEvent) {
		if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
			e.preventDefault();
			save();
		}
	}
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions (Ctrl+S anywhere in the editor) -->
<section class="card flex min-w-0 flex-col" aria-labelledby="doc-editor-h" {onkeydown}>
	<header class="panel-head flex-wrap">
		<div class="min-w-0">
			<h2 id="doc-editor-h" class="panel-title truncate">{heading}</h2>
			<p class="text-muted text-xs" aria-live="polite">{saving ? 'Saving…' : dirty ? 'Unsaved changes' : isTemplate ? 'Pages started from it later get a copy' : 'Saving keeps the previous version in the history'}</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			{@render actions?.()}
			<Button onclick={cancel}>Cancel</Button>
			<Button variant="primary" icon={Save} loading={saving} onclick={() => save()} title="{mac ? '⌘' : 'Ctrl'}+S">Save</Button>
		</div>
	</header>

	{#if conflict}
		<div class="border-warning/40 bg-warning-soft flex flex-wrap items-center gap-x-4 gap-y-2 border-b px-4 py-2.5 text-sm" role="alert">
			<TriangleAlert class="text-warning size-4 shrink-0" aria-hidden="true" />
			<p class="min-w-0 flex-1"><span class="font-medium">Someone else saved this page since you opened it.</span> <span class="text-muted">Saving anyway replaces their version; it stays in the history.</span></p>
			<div class="flex gap-2">
				<Button size="sm" onclick={() => ((leaving = true), ondone(false))}>Discard mine</Button>
				<Button size="sm" variant="primary" loading={saving} onclick={() => save(true)}>Save anyway</Button>
			</div>
		</div>
	{/if}

	<div class={cx('grid gap-3 px-4 py-3', isTemplate ? 'sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]' : 'sm:grid-cols-[minmax(0,1fr)_16rem]')}>
		<Field label={isTemplate ? 'Name' : 'Title'} id="doc-title-input" required>
			<Input id="doc-title-input" bind:value={draft.title} maxlength={isTemplate ? 200 : 300} required invalid={!draft.title.trim() && dirty} />
		</Field>
		<Field label="Category" id="doc-category">
			<Select
				id="doc-category"
				class="w-full"
				bind:value={draft.category_id}
				options={[{ value: null, label: 'No category' }, ...categories.map((c) => ({ value: c.id as string | null, label: c.name }))]}
			/>
		</Field>
		{#if isTemplate}
			<Field label="Description" id="doc-description" class="sm:col-span-2" hint="Shown on the template’s card when someone starts a page.">
				<Input id="doc-description" bind:value={draft.description} maxlength={500} />
			</Field>
		{/if}
	</div>

	<div class="border-border bg-sunken/50 flex flex-wrap items-center gap-1 border-y px-2 py-1.5">
		<div class="flex flex-wrap items-center gap-0.5" role="group" aria-label="Formatting">
			{#each tools as t (t.label)}
				<IconButton icon={t.icon} size="sm" label={t.key ? `${t.label} (${mac ? '⌘' : 'Ctrl'}+${t.key})` : t.label} onclick={t.run} />
			{/each}
		</div>
		<span class="bg-border mx-1 h-5 w-px" aria-hidden="true"></span>
		<Menu items={insertItems} label="Insert block" align="start">
			{#snippet trigger(props)}
				<Button {...props} size="sm" variant="ghost" icon={Plus} iconRight={ChevronDown} class="text-fg">Insert block</Button>
			{/snippet}
		</Menu>
		<span class="text-muted ml-auto hidden items-center gap-1 px-2 text-xs xl:inline-flex">Markdown · <Kbd keys={[mac ? '⌘' : 'Ctrl', 'S']} /> saves</span>
		<div class="ml-auto lg:hidden">
			<Segmented label="Show" value={pane} onchange={(v) => (pane = v)} options={[{ value: 'write', label: 'Write' }, { value: 'preview', label: 'Preview' }]} />
		</div>
	</div>

	<div class="grid min-h-0 lg:grid-cols-2">
		<div class={cx('border-border h-[65dvh] min-h-[22rem] lg:h-[calc(100dvh-17rem)] lg:min-h-[28rem] lg:border-r', pane === 'preview' && 'hidden lg:block')}>
			<MarkdownEditor bind:this={editor} bind:value={draft.body} id="doc-body" label={isTemplate ? 'Template text' : 'Page text'} onsave={() => save()} />
		</div>
		<!-- svelte-ignore a11y_no_noninteractive_tabindex (a scrolling region must be reachable by keyboard) -->
		<div
			class={cx('relative h-[65dvh] min-h-[22rem] overflow-y-auto px-5 py-4 lg:h-[calc(100dvh-17rem)] lg:min-h-[28rem]', pane === 'write' && 'hidden lg:block')}
			role="region"
			aria-label="Preview"
			tabindex="0"
		>
			<p class="eyebrow mb-3 hidden lg:block" aria-hidden="true">Preview</p>
			<DocView source={draft.body} {ctx} empty="Nothing to preview yet." class="max-w-[48rem]" />
		</div>
	</div>
</section>

{#if picking && clientId}
	<VaultPicker {clientId} label={picking.label} onpick={picked} onclose={() => (picking = null)} />
{/if}
{#if form === 'callout'}
	<CalloutForm text={selectedText} oninsert={inserted} onclose={() => (form = null)} />
{:else if form === 'device'}
	<DevicePicker {agents} oninsert={inserted} onclose={() => (form = null)} />
{:else if form === 'slot'}
	<SlotForm oninsert={inserted} onclose={() => (form = null)} />
{/if}
