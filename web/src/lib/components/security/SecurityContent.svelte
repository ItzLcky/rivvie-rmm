<script lang="ts">
	import { ArrowUpCircle, TriangleAlert, Undo2, Upload } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { withClient } from '#lib/scope.svelte.js';
	import { stageHelp, stageLabels, stageTone } from '#lib/security.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { ContentOverview, ContentVersion } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Signed detection content: the versions, their rollout stage, and uploading a new one. */
	let { canManage }: { canManage: boolean } = $props();

	const res = resource(() => api.get<ContentOverview>('/security/content'));
	const soak = (m: number) => (m % 1440 === 0 ? plural(m / 1440, 'day') : m % 60 === 0 ? plural(m / 60, 'hour') : plural(m, 'minute'));

	// --- Promote / roll back ---------------------------------------------------------------------
	let staging = $state<{ v: ContentVersion; to: 'promote' | 'rollback' } | null>(null);
	let reason = $state('');
	let busy = $state(false);
	async function stage(e: SubmitEvent) {
		e.preventDefault();
		const s = staging!;
		busy = true;
		try {
			await api.post(`/security/content/${s.v.id}/${s.to}`, { reason: reason.trim() });
			toast.success(s.to === 'promote' ? `${s.v.version} now goes to every agent.` : `${s.v.version} rolled back; agents return to the previous general version.`);
			staging = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}

	// --- Upload ----------------------------------------------------------------------------------
	let uploading = $state(false);
	let bundle = $state<{ name: string; text: string } | null>(null);
	let sig = $state<{ name: string; value: { version: string; sha256: string; signature: string } } | null>(null);
	let fileError = $state('');
	function read(file: File): Promise<string> {
		return new Promise((resolve, reject) => {
			const r = new FileReader();
			r.onload = () => resolve(String(r.result));
			r.onerror = () => reject(r.error ?? new Error('could not read the file'));
			r.readAsText(file);
		});
	}
	async function pickBundle(e: Event & { currentTarget: HTMLInputElement }) {
		const f = e.currentTarget.files?.[0];
		fileError = '';
		bundle = null;
		if (!f) return;
		const text = await read(f);
		try {
			JSON.parse(text);
		} catch {
			fileError = `${f.name} isn’t JSON`;
			return;
		}
		// Sent exactly as read: the signature covers these bytes.
		bundle = { name: f.name, text };
	}
	async function pickSig(e: Event & { currentTarget: HTMLInputElement }) {
		const f = e.currentTarget.files?.[0];
		fileError = '';
		sig = null;
		if (!f) return;
		try {
			const v = JSON.parse(await read(f));
			if (typeof v?.version !== 'string' || typeof v?.sha256 !== 'string' || typeof v?.signature !== 'string') throw new Error();
			sig = { name: f.name, value: { version: v.version, sha256: v.sha256, signature: v.signature } };
		} catch {
			fileError = `${f.name} isn’t a signature file from rmm-sign sign-content`;
		}
	}
	async function upload(e: SubmitEvent) {
		e.preventDefault();
		if (!bundle || !sig) return;
		busy = true;
		try {
			const r = await api.post<{ version: string }>('/security/content', { bundle: bundle.text, signature: sig.value });
			toast.success(`${r.version} uploaded. It goes to canary clients first.`);
			uploading = false;
			bundle = null;
			sig = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	function openUpload() {
		bundle = null;
		sig = null;
		fileError = '';
		uploading = true;
	}
</script>

<Async {res}>
	{#snippet children(c)}
		{#if !c.verifies_signatures}
			<div class="border-warning/40 bg-warning-soft mb-4 flex gap-2 rounded-md border px-3 py-2 text-sm" role="status">
				<TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
				<p>
					<span class="text-warning font-semibold">This server doesn’t check signatures.</span>
					<span>Without the release public key (RMM_UPDATE_PUBKEY) it accepts any upload; only the agents verify content, and they refuse anything not signed by the release key.</span>
				</p>
			</div>
		{/if}

		<div class="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
			<p class="text-muted min-w-0 flex-1 text-sm">
				New content goes to {plural(c.canary_clients, 'canary client')} first and reaches everyone after soaking {soak(c.soak_minutes)} without trouble.
				{#if canManage}<a class="link" href={withClient('/security?tab=settings')}>Choose canary clients</a>{/if}
			</p>
			{#if canManage}<Button variant="primary" icon={Upload} onclick={openUpload}>Upload content</Button>{/if}
		</div>
		{#if c.canary_clients === 0}
			<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm">No client is a canary, so new content waits the soak time and then goes to every agent at once.</p>
		{/if}

		<section class="card" aria-labelledby="versions-h">
			<header class="border-border min-h-12 border-b px-4 py-3"><h2 id="versions-h" class="panel-title">Versions</h2></header>
			{#if c.versions.length}
				<ul class="divide-border divide-y">
					{#each c.versions as v (v.id)}
						<li class="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-x-2 gap-y-1">
									<span class="font-mono text-sm font-medium">{v.version}</span>
									{#if v.stage === 'retired'}<span class="text-muted text-xs" title={stageHelp.retired}>Retired</span>{:else}<Badge tone={stageTone[v.stage]} title={stageHelp[v.stage]}>{stageLabels[v.stage]}</Badge>{/if}
									<span class="text-muted text-xs">{plural(v.rule_count, 'rule')} · {plural(v.hashes, 'hash', 'hashes')} · {plural(v.agents, 'agent')} running it</span>
								</div>
								{#if v.description}<p class="mt-0.5 text-sm break-words">{v.description}</p>{/if}
								<p class="text-muted mt-0.5 text-xs">
									Uploaded <span title={datetime(v.uploaded_at)}>{ago(v.uploaded_at)}</span>{v.uploaded_by_name ? ` by ${v.uploaded_by_name}` : ''}
									{#if v.stage_changed_at !== v.uploaded_at}· {stageLabels[v.stage].toLowerCase()} <span title={datetime(v.stage_changed_at)}>{ago(v.stage_changed_at)}</span>{/if}{#if v.stage_reason}: {v.stage_reason}{/if}
								</p>
								<p class="text-muted font-mono text-[11px] break-all">SHA-256 {v.sha256}</p>
							</div>
							{#if canManage}
								<div class="flex flex-wrap gap-1.5">
									{#if v.stage === 'canary' || v.stage === 'rolled_back'}
										<Button size="sm" icon={ArrowUpCircle} onclick={() => ((staging = { v, to: 'promote' }), (reason = ''))}>{v.stage === 'canary' ? 'Promote now' : 'Promote again'}</Button>
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
				<EmptyState title="No content yet" description="Agents run our sensor without rules until a signed bundle is uploaded here." />
			{/if}
		</section>
		<p class="text-muted mt-2 text-xs">{num(c.versions.reduce((n, v) => n + v.agents, 0))} agents report a content version.</p>
	{/snippet}
</Async>

{#if staging}
	{@const s = staging}
	<Modal
		title={s.to === 'promote' ? `Promote ${s.v.version} to every agent?` : `Roll back ${s.v.version}?`}
		onclose={() => (staging = null)}
	>
		<form id="stage" class="space-y-3" onsubmit={stage}>
			<p class="text-sm">
				{s.to === 'promote'
					? 'It skips the rest of the soak: every agent downloads it within a few minutes, and the current general version is retired.'
					: 'Agents stop using it and go back to the previous general version within a few minutes. Use this when a version misfires or slows machines down.'}
			</p>
			<Field label="Reason" id="stage-reason" hint="Shown with the version and kept in the audit log.">
				<Textarea id="stage-reason" rows={2} bind:value={reason} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (staging = null)}>Cancel</Button>
			<Button variant={s.to === 'promote' ? 'primary' : 'danger'} type="submit" form="stage" loading={busy}>{s.to === 'promote' ? 'Promote' : 'Roll back'}</Button>
		{/snippet}
	</Modal>
{/if}

{#if uploading}
	<Modal title="Upload detection content" onclose={() => (uploading = false)} size="md">
		<form id="upload" class="space-y-4" onsubmit={upload}>
			<div class="text-muted space-y-2 text-sm">
				<p>Content is a JSON bundle of rules and hashes, signed with the release key. On the machine that holds the key:</p>
				<ol class="list-decimal space-y-1 pl-5">
					<li><code class="text-fg text-xs">rmm-sign test-content bundle.json</code> runs each rule’s tests and the benign corpus.</li>
					<li><code class="text-fg text-xs">rmm-sign sign-content --key release.key bundle.json</code> tests again and writes <code class="text-fg text-xs">bundle.json.sig</code>.</li>
				</ol>
				<p>Upload both files unchanged: the signature covers the bundle’s exact bytes.</p>
			</div>
			<Field label="Bundle" id="up-bundle" required hint={bundle ? `${bundle.name}, ${num(bundle.text.length)} characters` : 'The .json file'}>
				<input id="up-bundle" type="file" accept=".json,application/json" class="control file:text-fg h-auto py-1 file:mr-3 file:border-0 file:bg-transparent file:font-medium" onchange={pickBundle} />
			</Field>
			<Field label="Signature" id="up-sig" required hint={sig ? `${sig.name}: version ${sig.value.version}` : 'The .sig file sign-content wrote'}>
				<input id="up-sig" type="file" accept=".sig,.json,application/json" class="control file:text-fg h-auto py-1 file:mr-3 file:border-0 file:bg-transparent file:font-medium" onchange={pickSig} />
			</Field>
			{#if fileError}<p class="text-danger text-sm" role="alert">{fileError}</p>{/if}
		</form>
		{#snippet footer()}
			<Button onclick={() => (uploading = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="upload" icon={Upload} loading={busy} disabled={!bundle || !sig}>Upload to canaries</Button>
		{/snippet}
	</Modal>
{/if}
