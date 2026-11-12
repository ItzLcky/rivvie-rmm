<script lang="ts">
	import { Download, KeyRound, Package, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Client, Site } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	interface Token { id: string; label: string; max_uses: number | null; uses: number; expires_at: string | null; created_at: string }
	interface AgentDownload { id: string; label: string; file_name: string; size: number; sha256: string; url: string }
	interface NewToken {
		token: string; expires_at: string | null; max_uses: number | null; install: { linux: string; windows: string };
		packages: { deb: string; rpm: string; install_deb: string; install_rpm: string } | null;
		windows_packages: { msi: string; install_msi: string } | null;
	}

	let { client, site, onclose }: { client: Client; site: Site; onclose: () => void } = $props();

	const tokens = resource(() => api.get<Token[]>(`/sites/${site.id}/enrollment-tokens`));
	const downloads = resource(() => api.get<AgentDownload[]>('/agent-downloads').catch(() => [] as AgentDownload[]));
	let created = $state<NewToken | null>(null);
	let label = $state('');
	let maxUses = $state<number | null>(null);
	let expiresHours = $state(168);
	let busy = $state<'' | 'token' | 'package'>('');

	async function create(purpose: 'package' | null) {
		busy = purpose ?? 'token';
		try {
			created = await api.post<NewToken>(
				`/sites/${site.id}/enrollment-tokens`,
				purpose
					? { label: label || 'Agent package', purpose, max_uses: maxUses || null, expires_in_hours: expiresHours || null }
					: { label, max_uses: maxUses || null, expires_in_hours: expiresHours }
			);
			await tokens.reload();
		} catch (e) {
			toast.error(e);
		} finally {
			busy = '';
		}
	}
	async function revoke(t: Token) {
		const ok = await confirmAction({
			title: 'Revoke this token?',
			message: `${t.label || 'This token'} stops working for new enrollments. Agents already enrolled with it are not affected.`,
			confirmLabel: 'Revoke',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/enrollment-tokens/${t.id}`), 'Token revoked.'))) tokens.update((list) => list.filter((x) => x.id !== t.id));
	}
</script>

<Modal title="Enroll agents" description="Into {client.name} › {site.name}" {onclose} size="lg">
	<div class="space-y-6">
		{#if created}
			<section class="border-success/40 bg-success-soft/40 space-y-3 rounded-lg border p-4" aria-live="polite">
				<p class="text-success text-sm font-medium">Token created. Copy the commands now: the token isn't shown again.</p>
				<CodeBlock label="Linux (as root)" code={created.install.linux} />
				<CodeBlock label="Windows (elevated PowerShell)" code={created.install.windows} />
				{#if created.packages || created.windows_packages}
					<div class="border-border space-y-3 border-t pt-3">
						<p class="text-sm">Packages with this token baked in: installing one enrolls and starts the agent.</p>
						<div class="flex flex-wrap gap-2">
							{#if created.windows_packages}
								<Button size="sm" icon={Download} href={created.windows_packages.msi}>.msi</Button>
							{/if}
							{#if created.packages}
								<Button size="sm" icon={Download} href={created.packages.deb}>.deb</Button>
								<Button size="sm" icon={Download} href={created.packages.rpm}>.rpm</Button>
							{/if}
						</div>
						{#if created.windows_packages}
							<CodeBlock label="Windows (elevated PowerShell)" code={created.windows_packages.install_msi} />
							<p class="text-muted text-xs">The MSI installs silently with <code>/qn</code>, so it also works from Group Policy, Intune or another RMM.</p>
						{/if}
						{#if created.packages}
							<CodeBlock label="Debian / Ubuntu" code={created.packages.install_deb} />
							<CodeBlock label="RHEL / Fedora" code={created.packages.install_rpm} />
						{/if}
						<p class="text-muted text-xs">
							Anyone with the package can enroll machines into this site until the token expires or runs out of uses{created.max_uses ? ` (${created.max_uses})` : ''}. Push it with your configuration management, then revoke the token.
						</p>
					</div>
				{/if}
			</section>
		{/if}

		<section>
			<h3 class="mb-2 text-sm font-semibold">New enrollment token</h3>
			<div class="grid gap-3 sm:grid-cols-3">
				<Field label="Label" id="tok-label"><Input id="tok-label" bind:value={label} placeholder="e.g. Office rollout" /></Field>
				<Field label="Max uses" id="tok-uses"><Input id="tok-uses" type="number" min="1" bind:value={maxUses} placeholder="Unlimited" /></Field>
				<Field label="Expires" id="tok-exp">
					<Select
						id="tok-exp"
						bind:value={expiresHours}
						options={[
							{ value: 1, label: 'In 1 hour' },
							{ value: 24, label: 'In 1 day' },
							{ value: 168, label: 'In 7 days' },
							{ value: 720, label: 'In 30 days' },
							{ value: 0, label: 'Never' }
						]}
					/>
				</Field>
			</div>
			<div class="mt-3 flex flex-wrap gap-2">
				<Button variant="primary" icon={KeyRound} loading={busy === 'token'} onclick={() => create(null)}>Create token</Button>
				<Button icon={Package} loading={busy === 'package'} onclick={() => create('package')} title="Limited to 50 uses and 30 days unless set above, with .msi, .deb and .rpm downloads">Create package</Button>
			</div>
		</section>

		<section>
			<h3 class="mb-2 text-sm font-semibold">Agent downloads</h3>
			{#if downloads.loading}
				<Skeleton class="h-8 w-64" />
			{:else if downloads.data?.length}
				<div class="flex flex-wrap gap-2">
					{#each downloads.data as d (d.id)}
						<Button size="sm" icon={Download} href={d.url} download={d.file_name} title="SHA-256 {d.sha256}">{d.label} <span class="text-muted">{bytes(d.size)}</span></Button>
					{/each}
				</div>
				<p class="hint">The install commands above download the agent themselves; these are for manual installs.</p>
			{:else}
				<p class="text-muted text-sm">This server has no agent binaries. Put them in <code>RMM_AGENT_DIR</code> (the server image includes them).</p>
			{/if}
		</section>

		<section>
			<h3 class="mb-2 text-sm font-semibold">Active tokens</h3>
			{#if tokens.data?.length}
				<div class="border-border overflow-x-auto rounded-lg border">
					<table class="table">
						<thead><tr><th>Label</th><th>Uses</th><th>Expires</th><th>Created</th><th></th></tr></thead>
						<tbody>
							{#each tokens.data as t (t.id)}
								<tr>
									<td>{t.label || '–'}</td>
									<td class="tabular">{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ''}</td>
									<td class="text-muted text-xs">{t.expires_at ? datetime(t.expires_at) : 'never'}</td>
									<td class="text-muted text-xs">{ago(t.created_at)}</td>
									<td class="text-right"><IconButton icon={Trash2} label="Revoke {t.label || 'token'}" variant="danger-ghost" size="sm" onclick={() => revoke(t)} /></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else if tokens.loading}
				<Skeleton lines={2} />
			{:else}
				<EmptyState compact icon={KeyRound} title="No active tokens" />
			{/if}
		</section>
	</div>
</Modal>
