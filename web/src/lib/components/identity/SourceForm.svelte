<script lang="ts">
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { kindLabel, type IdentitySource, type SourceKind } from '#lib/identity.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Page } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Add a client's directory, or change one (admins). */
	let { clientId, source = null, onclose, ondone }: { clientId: string; source?: IdentitySource | null; onclose: () => void; ondone: () => void } = $props();

	// svelte-ignore state_referenced_locally
	const s = source;
	let open = $state(true);
	let kind = $state<SourceKind>(s?.kind ?? 'entra');
	let name = $state(s?.name ?? '');
	let agent = $state(s?.agent_id ?? '');
	let tenant = $state(s?.tenant_id ?? '');
	let app = $state(s?.app_client_id ?? '');
	let secret = $state('');
	let devices = $state(s?.sync_devices ?? false);
	let minutes = $state(s?.sync_minutes ?? 60);
	let enabled = $state(s?.enabled ?? true);
	let saving = $state(false);
	const agents = resource(() => api.get<Page<AgentSummary>>(`/agents?client_id=${clientId}&os=windows&limit=500&sort=hostname`));

	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			const body = { kind, name, agent_id: kind === 'ad' ? agent || null : null, tenant_id: tenant, app_client_id: app, secret: secret || null, sync_devices: devices, sync_minutes: Number(minutes), enabled };
			if (s) await api.put(`/identity-sources/${s.id}`, body);
			else await api.post(`/clients/${clientId}/identity-sources`, body);
			toast.success(`${name} saved. Sync it to read its users.`);
			open = false;
			ondone();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Drawer bind:open title={s ? `Edit ${s.name}` : 'Add a directory'} side="right" width="w-[34rem]" {onclose}>
	<form class="space-y-4 px-4 pb-6" onsubmit={save}>
		<h2 class="text-base font-semibold">{s ? `Edit ${s.name}` : 'Add a directory'}</h2>
		{#if !s}
			<div role="radiogroup" aria-label="Kind of directory" class="grid gap-1.5 sm:grid-cols-2">
				{#each [{ v: 'entra', hint: 'Microsoft 365 through Graph, with an app registration in the client’s tenant.' }, { v: 'ad', hint: 'On-premises, through our agent on one of its domain controllers.' }] as k (k.v)}
					{@const on = kind === k.v}
					<button type="button" role="radio" aria-checked={on} class={cx('rounded-md border px-3 py-2 text-left text-sm', on ? 'border-accent bg-accent-soft' : 'border-border hover:bg-hover')} onclick={() => (kind = k.v as SourceKind)}>
						<span class={cx('block font-medium', on && 'text-accent')}>{kindLabel[k.v as SourceKind]}</span>
						<span class="text-muted block text-xs">{k.hint}</span>
					</button>
				{/each}
			</div>
		{/if}
		<Field label="Name" id="is-name" required><Input id="is-name" required maxlength={100} bind:value={name} placeholder={kind === 'ad' ? 'corp.example' : 'Microsoft 365'} /></Field>
		{#if kind === 'ad'}
			<Field label="Domain controller" id="is-agent" required hint="A Windows agent of this client on a domain controller. Directory operations go to it over the agent connection, never as scripts.">
				<Select id="is-agent" class="w-full" required bind:value={agent} options={[{ value: '', label: 'Choose an agent…', disabled: true }, ...(agents.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.hostname} · ${a.site_name}${a.online ? '' : ' (offline)'}` }))]} />
			</Field>
		{:else}
			<Field label="Tenant" id="is-tenant" required hint="The directory (tenant) id, or its .onmicrosoft.com domain.">
				<Input id="is-tenant" required class="font-mono text-[13px]" bind:value={tenant} placeholder="contoso.onmicrosoft.com" />
			</Field>
			<Field label="Application (client) id" id="is-app" required><Input id="is-app" required class="font-mono text-[13px]" bind:value={app} placeholder="00000000-0000-0000-0000-000000000000" /></Field>
			<Field label="Client secret" id="is-secret" required={!s} hint={s?.has_secret ? 'Leave empty to keep the stored secret.' : 'Stored encrypted; never shown again.'}>
				<Input id="is-secret" type="password" autocomplete="off" required={!s} bind:value={secret} />
			</Field>
			<p class="hint">Application permissions: <code>User.Read.All</code> and <code>Group.Read.All</code> to read; <code>User.ReadWrite.All</code> and <code>GroupMember.ReadWrite.All</code>, and the <em>User Administrator</em> role on the app, for actions. Optional: <code>RoleManagement.Read.Directory</code> (privileged accounts), <code>AuditLog.Read.All</code> (MFA registration).</p>
			<Switch bind:checked={devices}>Also read Intune devices (needs <code>DeviceManagementManagedDevices.Read.All</code>)</Switch>
		{/if}
		<Field label="Sync every (minutes)" id="is-min" hint="5 to 1440."><Input id="is-min" type="number" min="5" max="1440" bind:value={minutes} /></Field>
		<Switch bind:checked={enabled}>Sync on schedule</Switch>
		<div class="flex justify-end gap-2 pt-2">
			<Button variant="ghost" onclick={() => ((open = false), onclose())}>Cancel</Button>
			<Button variant="primary" type="submit" loading={saving} disabled={!name.trim() || (kind === 'ad' && !agent)}>{s ? 'Save' : 'Add directory'}</Button>
		</div>
	</form>
</Drawer>
