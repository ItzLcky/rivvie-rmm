<script lang="ts">
	import { ArrowUp, Download, File, Folder, HardDrive, Link2, RefreshCw, Upload } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentDetail, DirEntry, DirListing } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';

	/**
	 * Browse the agent's file system, download files and upload into the open folder. The
	 * folder lives in the URL (`?path=`). Transfers go over the agent's socket in pieces.
	 */
	let { agent }: { agent: AgentDetail } = $props();
	const capable = $derived(agent.capabilities?.includes('tools'));
	const path = $derived(param('path'));
	const res = resource(() =>
		agent.online && capable ? api.get<DirListing>(`/agents/${agent.id}/files?path=${encodeURIComponent(path)}`) : Promise.resolve(null)
	);

	let typed = $state('');
	$effect(() => {
		typed = res.data?.path ?? path;
	});
	const sep = $derived(agent.os_family === 'windows' ? '\\' : '/');
	const open = (p: string) => setParams({ path: p || null }, { push: true });
	const downloadHref = (e: DirEntry) => `/api/agents/${agent.id}/files/download?path=${encodeURIComponent(e.path)}`;

	/** Breadcrumbs for the open folder. */
	const crumbs = $derived.by(() => {
		const p = res.data?.path ?? '';
		if (!p) return [];
		const out: { label: string; path: string }[] = [];
		if (agent.os_family === 'windows') {
			const parts = p.split('\\').filter(Boolean);
			let acc = '';
			for (const [i, part] of parts.entries()) {
				acc = i === 0 ? `${part}\\` : `${acc}${acc.endsWith('\\') ? '' : '\\'}${part}`;
				out.push({ label: part, path: acc });
			}
		} else {
			out.push({ label: '/', path: '/' });
			let acc = '';
			for (const part of p.split('/').filter(Boolean)) {
				acc += `/${part}`;
				out.push({ label: part, path: acc });
			}
		}
		return out;
	});

	// Uploads: one at a time, with progress.
	let input = $state<HTMLInputElement>();
	let uploading = $state<{ name: string; sent: number; total: number } | null>(null);
	function put(url: string, file: globalThis.File): Promise<void> {
		return new Promise((resolve, reject) => {
			const xhr = new XMLHttpRequest();
			xhr.open('PUT', url);
			xhr.withCredentials = true;
			xhr.upload.onprogress = (e) => uploading && (uploading.sent = e.loaded);
			xhr.onload = () => {
				if (xhr.status >= 200 && xhr.status < 300) return resolve();
				let msg = xhr.statusText;
				try {
					msg = JSON.parse(xhr.responseText).error ?? msg;
				} catch {
					/* not JSON */
				}
				reject(Object.assign(new Error(msg), { status: xhr.status }));
			};
			xhr.onerror = () => reject(new Error('the upload was interrupted'));
			xhr.send(file);
		});
	}
	async function upload(files: FileList | null) {
		const dir = res.data?.path;
		if (!files?.length || !dir) return;
		for (const f of Array.from(files)) {
			const target = `${dir}${dir.endsWith(sep) ? '' : sep}${f.name}`;
			const exists = res.data?.entries.some((e) => e.name === f.name);
			if (exists) {
				const ok = await confirmAction({
					title: `Replace ${f.name}?`,
					message: `${target} already exists on ${agent.hostname}. The new file replaces it once it has arrived completely.`,
					confirmLabel: 'Replace',
					danger: true
				});
				if (!ok) continue;
			}
			uploading = { name: f.name, sent: 0, total: f.size };
			try {
				await put(`/api/agents/${agent.id}/files/upload?path=${encodeURIComponent(target)}&overwrite=${exists ? 'true' : 'false'}`, f);
				toast.success(`Uploaded ${f.name} (${bytes(f.size)}).`);
			} catch (e) {
				toast.error(e);
			}
		}
		uploading = null;
		if (input) input.value = '';
		res.reload();
	}
</script>

{#snippet nameCell(e: DirEntry)}
	<div class="flex min-w-0 items-center gap-2">
		{#if !path}<HardDrive class="text-muted size-4 shrink-0" />{:else if e.dir}<Folder class="text-accent size-4 shrink-0" />{:else}<File class="text-muted size-4 shrink-0" />{/if}
		{#if e.dir}
			<a class="hover:text-accent truncate font-medium" href="?tab=files&path={encodeURIComponent(e.path)}" onclick={(ev) => { ev.preventDefault(); open(e.path); }}>{e.name}</a>
		{:else}
			<span class="truncate">{e.name}</span>
		{/if}
		{#if e.symlink}<Link2 class="text-subtle size-3.5 shrink-0" aria-label="link" />{/if}
	</div>
	{#if e.error}<div class="text-danger text-xs">{e.error}</div>{/if}
{/snippet}
{#snippet sizeCell(e: DirEntry)}{#if !e.dir && !e.error}<span class="tabular">{bytes(e.size)}</span>{/if}{/snippet}
{#snippet modCell(e: DirEntry)}{#if e.modified}<span class="text-muted whitespace-nowrap" title={datetime(e.modified)}>{ago(e.modified)}</span>{/if}{/snippet}
{#snippet actionCell(e: DirEntry)}
	{#if !e.dir && !e.error}<Button size="sm" variant="ghost" icon={Download} href={downloadHref(e)} download={e.name} aria-label="Download {e.name}" />{/if}
{/snippet}

{#if !capable}
	<div class="card"><EmptyState title="The file browser needs a newer agent" description="This agent's version (v{agent.agent_version}) can't transfer files. Update the agent, then reopen this page." /></div>
{:else if !agent.online}
	<div class="card"><EmptyState title="The agent is offline" description="Files are read live from the machine; they show once it reconnects." /></div>
{:else}
	<form
		class="mb-3 flex flex-wrap items-center gap-2"
		onsubmit={(e) => {
			e.preventDefault();
			open(typed.trim());
		}}
	>
		<Button size="sm" icon={ArrowUp} disabled={res.data?.parent == null} onclick={() => open(res.data?.parent ?? '')} aria-label="Up one folder" />
		<Input class="min-w-0 flex-1 font-mono text-[13px]" aria-label="Folder" bind:value={typed} placeholder={agent.os_family === 'windows' ? 'C:\\Users' : '/var/log'} />
		<Button size="sm" type="submit">Go</Button>
		<Button size="sm" icon={RefreshCw} loading={res.busy} onclick={() => res.reload()} aria-label="Refresh" />
		<input bind:this={input} type="file" multiple class="sr-only" tabindex="-1" aria-hidden="true" onchange={(e) => upload(e.currentTarget.files)} />
		<Button size="sm" variant="primary" icon={Upload} disabled={!res.data?.path || !!uploading} onclick={() => input?.click()} title={res.data?.path ? undefined : 'Open a folder first'}>Upload</Button>
	</form>
	{#if crumbs.length}
		<nav aria-label="Folder path" class="text-muted mb-3 flex flex-wrap items-center gap-1 font-mono text-xs">
			{#if agent.os_family === 'windows'}
				<a class="hover:text-fg" href="?tab=files" onclick={(e) => { e.preventDefault(); open(''); }}>Drives</a>
			{/if}
			{#each crumbs as c, i (c.path)}
				{#if i > 0 || agent.os_family === 'windows'}<span aria-hidden="true">›</span>{/if}
				<a class="hover:text-fg" href="?tab=files&path={encodeURIComponent(c.path)}" onclick={(e) => { e.preventDefault(); open(c.path); }}>{c.label}</a>
			{/each}
		</nav>
	{/if}
	{#if uploading}
		<div class="card mb-3 flex items-center gap-3 px-4 py-2 text-sm" role="status">
			<span class="min-w-0 flex-1 truncate">Uploading {uploading.name}…</span>
			<progress class="w-40" max={uploading.total || 1} value={uploading.sent}></progress>
			<span class="text-muted tabular text-xs">{bytes(uploading.sent)} / {bytes(uploading.total)}</span>
		</div>
	{/if}
	{#if res.error && !res.data}
		<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
	{:else}
		<DataTable
			id="agent-files"
			caption={res.data?.path ? `Files in ${res.data.path}` : 'Drives'}
			rows={res.data?.entries ?? []}
			key={(e) => e.path}
			loading={res.loading}
			busy={res.busy}
			rowHref={(e) => `?tab=files&path=${encodeURIComponent(e.dir ? e.path : path)}`}
			columns={[
				{ id: 'name', label: 'Name', cell: nameCell, hideable: false },
				{ id: 'size', label: 'Size', cell: sizeCell, align: 'right', from: 'sm' },
				{ id: 'modified', label: 'Modified', cell: modCell, align: 'right', from: 'md' },
				{ id: 'actions', label: '', cell: actionCell, hideable: false, align: 'right', class: 'w-12' }
			] satisfies Column<DirEntry>[]}
		>
			{#snippet empty()}<EmptyState compact title="This folder is empty" />{/snippet}
			{#snippet footer()}
				{#if res.data}<p class="text-muted px-3 py-2 text-xs">{num(res.data.entries.length)} items{res.data.truncated ? ' (the first 10,000)' : ''}. Downloads and uploads are recorded in the audit log.</p>{/if}
			{/snippet}
		</DataTable>
	{/if}
{/if}
