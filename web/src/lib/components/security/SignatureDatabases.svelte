<script lang="ts">
	import { ArrowUpCircle, Undo2, Upload } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, bytes, datetime, num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { stageHelp, stageLabels, stageTone } from '#lib/security.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { DatabaseOverview, SignatureDatabase } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/**
	 * Signature databases (hashes and YARA rules from `rmm-sign build-db`): the versions, their
	 * rollout stage, and uploading a new one. Same stages and soak as detection content.
	 */
	let { canManage }: { canManage: boolean } = $props();

	const res = resource(() => api.get<DatabaseOverview>('/security/databases'));
	const sourceKinds: Record<string, string> = { 'sha256-list': 'hash list', yara: 'YARA', 'clamav-hdb': 'ClamAV .hdb', 'clamav-hsb': 'ClamAV .hsb' };

	/** What agents fall back to when the general version is rolled back: the newest retired one still stored. */
	const fallback = $derived((res.data?.versions ?? []).find((v) => v.stage === 'retired' && v.stored) ?? null);

	// --- Promote / roll back ---------------------------------------------------------------------
	let staging = $state<{ v: SignatureDatabase; to: 'promote' | 'rollback' } | null>(null);
	let reason = $state('');
	let busy = $state(false);
	async function stage(e: SubmitEvent) {
		e.preventDefault();
		const s = staging!;
		busy = true;
		try {
			await api.post(`/security/databases/${s.v.id}/${s.to}`, { reason: reason.trim() });
			toast.success(
				s.to === 'promote'
					? `${s.v.version} now goes to every agent running the sensor.`
					: s.v.stage === 'general' && fallback
						? `${s.v.version} rolled back; agents return to ${fallback.version}.`
						: `${s.v.version} rolled back.`
			);
			staging = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	function rollbackText(v: SignatureDatabase): string {
		if (v.stage === 'canary') return 'Canary agents stop using it and go back to the general version within a few minutes. Use this when a version misfires or slows machines down.';
		return fallback
			? `Agents go back to ${fallback.version} (built ${ago(fallback.built_at)}), which they kept and don’t download again. It becomes the general version.`
			: 'No earlier version is still stored, so agents unload this database and run without one (behaviour rules and the content bundle keep working) until a new one is uploaded.';
	}

	// --- Upload ----------------------------------------------------------------------------------
	let uploading = $state(false);
	let file = $state<File | null>(null);
	let sent = $state<number | null>(null);
	function pick(e: Event & { currentTarget: HTMLInputElement }) {
		file = e.currentTarget.files?.[0] ?? null;
	}
	function post(f: File): Promise<{ version: string; size: number }> {
		return new Promise((resolve, reject) => {
			const xhr = new XMLHttpRequest();
			xhr.open('POST', '/api/security/databases');
			xhr.withCredentials = true;
			xhr.setRequestHeader('content-type', 'application/octet-stream');
			xhr.upload.onprogress = (e) => (sent = e.loaded);
			xhr.onload = () => {
				let body: Record<string, unknown> = {};
				try {
					body = JSON.parse(xhr.responseText);
				} catch {
					/* not JSON */
				}
				if (xhr.status >= 200 && xhr.status < 300) resolve(body as { version: string; size: number });
				else reject(new Error(typeof body.error === 'string' ? body.error : xhr.statusText));
			};
			xhr.onerror = () => reject(new Error('the upload was interrupted'));
			xhr.send(f);
		});
	}
	async function upload(e: SubmitEvent) {
		e.preventDefault();
		if (!file) return;
		busy = true;
		sent = 0;
		try {
			const r = await post(file);
			toast.success(`${r.version} uploaded (${bytes(r.size)}). It goes to canary clients first.`);
			uploading = false;
			file = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
			sent = null;
		}
	}
</script>

<section class="card" aria-labelledby="db-h">
	<header class="border-border flex flex-wrap items-center gap-x-3 gap-y-2 min-h-12 border-b px-4 py-3">
		<div class="min-w-0 flex-1">
			<h2 id="db-h" class="panel-title">Signature databases</h2>
			<p class="text-muted text-xs">Known-bad hashes and YARA rules our sensor scans with, built and signed offline. Rolled out like content: canary clients first, then everyone after the soak.</p>
		</div>
		{#if canManage}<Button size="sm" icon={Upload} onclick={() => ((uploading = true), (file = null))}>Upload database</Button>{/if}
	</header>
	<Async {res} compact>
		{#snippet children(c)}
			{#if c.versions.length}
				<ul class="divide-border divide-y">
					{#each c.versions as v (v.id)}
						<li class="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-x-2 gap-y-1">
									<span class="font-mono text-sm font-medium">{v.version}</span>
									{#if v.stage === 'retired'}<span class="text-muted text-xs" title={stageHelp.retired}>Retired</span>{:else}<Badge tone={stageTone[v.stage]} title={stageHelp[v.stage]}>{stageLabels[v.stage]}</Badge>{/if}
									{#if !v.stored}<Badge title="The file was pruned from storage; upload it again to roll it out">Pruned</Badge>{/if}
									<span class="text-muted text-xs tabular">{plural(v.hashes, 'hash', 'hashes')} · {plural(v.yara_rules, 'YARA rule')} · {bytes(v.size)} · {plural(v.agents, 'agent')} running it</span>
								</div>
								{#if v.description}<p class="mt-0.5 text-sm break-words">{v.description}</p>{/if}
								{#if v.sources.length}
									<p class="text-muted mt-0.5 text-xs break-words">
										From {#each v.sources as s, i (s.name + i)}{i ? ', ' : ''}<span class="text-fg">{s.name}</span> ({sourceKinds[s.kind] ?? s.kind}, {num(s.entries)}){/each}
									</p>
								{/if}
								<p class="text-muted mt-0.5 text-xs">
									Built <span title={datetime(v.built_at)}>{ago(v.built_at)}</span> · uploaded <span title={datetime(v.uploaded_at)}>{ago(v.uploaded_at)}</span>{v.uploaded_by_name ? ` by ${v.uploaded_by_name}` : ''}
									{#if v.stage_changed_at !== v.uploaded_at}· {stageLabels[v.stage].toLowerCase()} <span title={datetime(v.stage_changed_at)}>{ago(v.stage_changed_at)}</span>{/if}{#if v.stage_reason}: {v.stage_reason}{/if}
								</p>
								<p class="text-muted font-mono text-[11px] break-all">SHA-256 {v.sha256}</p>
							</div>
							{#if canManage}
								<div class="flex flex-wrap gap-1.5">
									{#if v.stage === 'canary' || v.stage === 'rolled_back'}
										<Button
											size="sm"
											icon={ArrowUpCircle}
											disabled={!v.stored}
											title={v.stored ? undefined : 'Pruned from storage: upload it again'}
											onclick={() => ((staging = { v, to: 'promote' }), (reason = ''))}>{v.stage === 'canary' ? 'Promote now' : 'Promote again'}</Button
										>
									{/if}
									{#if v.stage === 'canary' || v.stage === 'general'}
										<Button size="sm" variant="danger-ghost" icon={Undo2} onclick={() => ((staging = { v, to: 'rollback' }), (reason = ''))}>Roll back</Button>
									{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState title="No signature database yet" description="Our sensor matches the content bundle’s few hashes and rules until a database is uploaded here." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if staging}
	{@const s = staging}
	<Modal title={s.to === 'promote' ? `Promote ${s.v.version} to every agent?` : `Roll back ${s.v.version}?`} onclose={() => (staging = null)}>
		<form id="db-stage" class="space-y-3" onsubmit={stage}>
			<p class="text-sm">
				{s.to === 'promote'
					? `It skips the rest of the soak: every agent running the sensor downloads it (${bytes(s.v.size)} each) within a few minutes, and the current general version is retired.`
					: rollbackText(s.v)}
			</p>
			<Field label="Reason" id="db-stage-reason" hint="Shown with the version and kept in the audit log.">
				<Textarea id="db-stage-reason" rows={2} bind:value={reason} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (staging = null)}>Cancel</Button>
			<Button variant={s.to === 'promote' ? 'primary' : 'danger'} type="submit" form="db-stage" loading={busy}>{s.to === 'promote' ? 'Promote' : 'Roll back'}</Button>
		{/snippet}
	</Modal>
{/if}

{#if uploading}
	<Modal title="Upload a signature database" onclose={() => !busy && (uploading = false)} size="md">
		<form id="db-upload" class="space-y-4" onsubmit={upload}>
			<div class="text-muted space-y-2 text-sm">
				<p>A database is one <code class="text-fg text-xs">.rmmdb</code> file with its signature inside, built on the machine that holds the release key:</p>
				<ol class="list-decimal space-y-1 pl-5">
					<li><code class="text-fg text-xs break-all">rmm-sign build-db --key release.key --version 2026.06.15.1 --rules content/yara --sha256 hashes.txt --benign /usr/bin --out sigs.rmmdb</code> imports the feeds, runs every rule’s samples and the benign files, and refuses on a failure.</li>
					<li><code class="text-fg text-xs">rmm-sign inspect-db --pubkey &lt;hex&gt; sigs.rmmdb</code> shows what’s in it.</li>
				</ol>
				<p>Upload the file unchanged. The server checks the signature as it arrives{res.data?.verifies_signatures === false ? ' only if it has the release public key; this one doesn’t, so only the agents check it' : ''}.</p>
			</div>
			<Field label="Database file" id="db-file" required hint={file ? `${file.name}, ${bytes(file.size)}` : 'The .rmmdb file build-db wrote'}>
				<input id="db-file" type="file" accept=".rmmdb,application/octet-stream" class="control file:text-fg h-auto py-1 file:mr-3 file:border-0 file:bg-transparent file:font-medium" onchange={pick} disabled={busy} />
			</Field>
			{#if sent !== null && file}
				<div>
					<progress class="w-full" max={file.size} value={sent} aria-label="Upload progress"></progress>
					<p class="text-muted text-xs tabular">{bytes(sent)} of {bytes(file.size)}</p>
				</div>
			{/if}
		</form>
		{#snippet footer()}
			<Button onclick={() => (uploading = false)} disabled={busy}>Cancel</Button>
			<Button variant="primary" type="submit" form="db-upload" icon={Upload} loading={busy} disabled={!file}>Upload to canaries</Button>
		{/snippet}
	</Modal>
{/if}
