<script lang="ts">
	import { Plus, Trash2, Upload } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime, num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { reputationSourceLabel, severityLabels } from '#lib/security.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { ReputationSource, ThreatSeverity } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	/**
	 * The server's reputation set: the newest database's hashes (automatic) and hash lists
	 * uploaded for the server only, which agents ask about but never download.
	 */
	let { canManage }: { canManage: boolean } = $props();

	const res = resource(() => api.get<{ sources: ReputationSource[] }>('/security/reputation'));
	const severities: ThreatSeverity[] = ['severe', 'high', 'moderate', 'low'];

	let adding = $state<{ replace: string | null } | null>(null);
	let name = $state('');
	let severity = $state<ThreatSeverity>('high');
	let file = $state<File | null>(null);
	let nameError = $state('');
	let busy = $state(false);
	function open(replace: string | null) {
		name = replace ?? '';
		severity = 'high';
		file = null;
		nameError = '';
		adding = { replace };
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const n = name.trim();
		if (!/^[A-Za-z0-9._-]{1,64}$/.test(n)) {
			nameError = 'Letters, digits, dots, dashes and underscores, up to 64';
			return;
		}
		if (!file) return;
		nameError = '';
		busy = true;
		try {
			const r = await fetch(`/api/security/reputation/lists/${encodeURIComponent(n)}?severity=${severity}`, {
				method: 'PUT',
				credentials: 'same-origin',
				headers: { 'content-type': 'text/plain' },
				body: await file.text()
			});
			const body = await r.json().catch(() => ({}));
			if (!r.ok) throw new Error(body.error ?? r.statusText);
			toast.success(`${n}: ${plural(body.hashes ?? 0, 'hash', 'hashes')} in the server’s reputation set.`);
			adding = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	async function remove(s: ReputationSource) {
		const n = s.source.slice(5);
		const ok = await confirmAction({
			title: `Delete the hash list ${n}?`,
			message: `Its ${plural(s.hashes, 'hash', 'hashes')} stop being reported by the reputation lookup. Detections it already raised stay.`,
			confirmLabel: 'Delete list',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/security/reputation/lists/${encodeURIComponent(n)}`), `${n} deleted.`))) res.reload();
	}
</script>

<section class="card" aria-labelledby="rep-h">
	<header class="border-border flex flex-wrap items-center gap-x-3 gap-y-2 min-h-12 border-b px-4 py-3">
		<div class="min-w-0 flex-1">
			<h2 id="rep-h" class="panel-title">Reputation hash lists</h2>
			<p class="text-muted text-xs">
				Agents ask the server about programs their own database doesn’t know. A match raises an alert (never a block or quarantine: the answer isn’t signed). Lists here stay on the server, so they can be far bigger than what agents download.
			</p>
		</div>
		{#if canManage}<Button size="sm" icon={Plus} onclick={() => open(null)}>Add list</Button>{/if}
	</header>
	<Async {res} compact>
		{#snippet children(r)}
			{#if r.sources.length}
				<ul class="divide-border divide-y">
					{#each r.sources as s (s.source)}
						{@const list = s.source.startsWith('list:')}
						<li class="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5">
							<div class="min-w-0 flex-1">
								<span class="text-sm font-medium break-all {list ? '' : 'font-mono'}">{reputationSourceLabel(s.source)}</span>
								<span class="text-muted text-xs">{' · '}{list ? 'uploaded list' : 'from the newest database, kept in step automatically'}</span>
								<div class="text-muted text-xs tabular">{plural(s.hashes, 'hash', 'hashes')} · updated <span title={datetime(s.added_at)}>{ago(s.added_at)}</span></div>
							</div>
							{#if canManage && list}
								<div class="flex gap-1">
									<Button size="sm" icon={Upload} onclick={() => open(s.source.slice(5))}>Replace</Button>
									<IconButton icon={Trash2} size="sm" label="Delete list {s.source.slice(5)}" onclick={() => remove(s)} />
								</div>
							{/if}
						</li>
					{/each}
				</ul>
				<p class="text-muted border-border border-t px-4 py-2 text-xs">{num(r.sources.reduce((n, s) => n + s.hashes, 0))} hashes in all.</p>
			{:else}
				<EmptyState compact title="Nothing in the reputation set" description="It fills from the newest signature database, plus any lists added here." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if adding}
	{@const replacing = adding.replace}
	<Modal title={replacing ? `Replace the list ${replacing}` : 'Add a reputation hash list'} onclose={() => !busy && (adding = null)} size="md">
		<form id="rep-list" class="space-y-4" onsubmit={save}>
			<p class="text-muted text-sm">A text file with one SHA-256 per line, optionally followed by a name (<code class="text-fg text-xs">e3b0c442…b855 Trojan.Example</code>). Lines starting with # are ignored. Uploading under an existing name replaces that list.</p>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="rep-name" required error={nameError}>
					<Input id="rep-name" class="font-mono" spellcheck={false} bind:value={name} invalid={!!nameError} disabled={!!replacing} placeholder="malwarebazaar" />
				</Field>
				<Field label="Severity of a match" id="rep-sev">
					<Select id="rep-sev" class="w-full" bind:value={severity} options={severities.map((s) => ({ value: s, label: severityLabels[s] }))} />
				</Field>
			</div>
			<Field label="Hash list" id="rep-file" required hint={file ? `${file.name}, ${bytes(file.size)}` : 'A .txt file'}>
				<input id="rep-file" type="file" accept=".txt,.csv,text/plain" class="control file:text-fg h-auto py-1 file:mr-3 file:border-0 file:bg-transparent file:font-medium" onchange={(e) => (file = e.currentTarget.files?.[0] ?? null)} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (adding = null)} disabled={busy}>Cancel</Button>
			<Button variant="primary" type="submit" form="rep-list" icon={Upload} loading={busy} disabled={!file}>{replacing ? 'Replace list' : 'Add list'}</Button>
		{/snippet}
	</Modal>
{/if}
