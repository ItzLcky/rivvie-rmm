<script lang="ts">
	import { goto } from '$app/navigation';
	import { Ban, CircleCheck, KeyRound, ListChecks, LockOpen, LogOut, ShieldAlert, Users, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { kindLabel, unavailable, type DirUserDetail, type IdentityAction, type TicketTemplate } from '#lib/identity.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Select from '#lib/ui/Select.svelte';
	import { can } from '#lib/session.svelte.js';
	import ResetDialog from './ResetDialog.svelte';

	/** One directory account: what the directory says about it, and the actions on it. */
	let { id, onclose, onchange }: { id: string; onclose: () => void; onchange?: () => void } = $props();

	let open = $state(true);
	const user = resource(() => api.get<DirUserDetail>(`/identity/users/${id}`));
	let resetting = $state(false);
	let busy = $state<IdentityAction | null>(null);
	const templates = resource(() => (can('technician') ? api.get<TicketTemplate[]>('/ticket-templates') : Promise.resolve([] as TicketTemplate[])));
	let template = $state('');
	let opening = $state(false);

	async function openTicket(u: DirUserDetail) {
		opening = true;
		try {
			const t = await api.post<{ id: string; number: number }>('/tickets/from-template', { template_id: template, client_id: u.client_id, identity_user_id: u.id, contact_id: u.contact_id });
			open = false;
			await goto(`/tickets/${t.id}`);
		} catch (e) {
			toast.error(e);
		} finally {
			opening = false;
		}
	}

	async function run(u: DirUserDetail, action: IdentityAction, opts: { confirm?: string; done: string; body?: unknown }) {
		if (opts.confirm && !(await confirmAction({ title: opts.confirm, confirmLabel: 'Yes, go ahead', danger: action !== 'unlock' && action !== 'enable' }))) return;
		busy = action;
		const ok = await attempt(() => api.post(`/identity/users/${u.id}/${action}`, opts.body ?? {}), opts.done);
		busy = null;
		if (ok) {
			user.reload();
			onchange?.();
		}
	}

	function why(u: DirUserDetail, a: IdentityAction): string | null {
		if (!u.can_manage) return u.privileged ? 'A privileged account: only an admin can change it.' : 'Needs the identity.manage permission and two-factor authentication.';
		return unavailable(u, a);
	}
</script>

<Drawer bind:open title="Directory account" side="right" width="w-[32rem]" {onclose}>
	<Async res={user}>
		{#snippet children(u)}
			{@const who = u.display_name || u.username}
			<div class="space-y-5 px-4 pb-6">
				<div>
					<h2 class="text-base font-semibold">{who}</h2>
					<p class="text-muted text-sm">{u.upn || u.username} · {kindLabel[u.kind]} “{u.source_name}”</p>
					<div class="mt-2 flex flex-wrap gap-1.5">
						{#if u.deleted_at}<Badge tone="neutral">Gone from the directory</Badge>{/if}
						{#if !u.enabled}<Badge tone="neutral">Disabled</Badge>{:else}<Badge tone="success">Enabled</Badge>{/if}
						{#if u.locked}<Badge tone="danger">Locked out</Badge>{/if}
						{#if u.privileged}<Badge tone="warning"><ShieldAlert class="size-3" /> Privileged</Badge>{/if}
						{#if u.synced_from_ad}<Badge tone="info">Synced from AD</Badge>{/if}
						{#if u.mfa_registered === false}<Badge tone="warning">No MFA</Badge>{:else if u.mfa_registered}<Badge tone="success">MFA</Badge>{/if}
					</div>
				</div>

				<dl class="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5 text-sm">
					<dt class="text-muted">Email</dt><dd class="truncate">{u.email || '–'}</dd>
					<dt class="text-muted">Contact</dt><dd>{u.contact_name ?? 'Not matched'}</dd>
					<dt class="text-muted">Department</dt><dd>{u.department || '–'}{u.title ? ` · ${u.title}` : ''}</dd>
					<dt class="text-muted">Last sign-in</dt><dd title={datetime(u.last_logon_at)}>{u.last_logon_at ? ago(u.last_logon_at) : u.kind === 'entra' ? 'Not read from Entra ID' : 'Never'}</dd>
					<dt class="text-muted">Password set</dt><dd title={datetime(u.password_last_set)}>{u.password_last_set ? ago(u.password_last_set) : '–'}</dd>
					{#if u.password_expires_at}<dt class="text-muted">Password expires</dt><dd>{datetime(u.password_expires_at)}</dd>{/if}
					{#if u.vault_item_id}<dt class="text-muted">Vault</dt><dd><a class="link" href="/clients/{u.client_id}?tab=passwords">A reset password is saved</a></dd>{/if}
					<dt class="text-muted">Synced</dt><dd>{ago(u.synced_at)}</dd>
				</dl>

				{#if u.synced_from_ad}
					<p class="border-info/40 bg-info-soft text-info rounded-md border px-3 py-2 text-xs">This account comes from the client’s on-premises Active Directory. Change it there (add that directory with an agent on a domain controller); the change syncs up to Entra ID.</p>
				{/if}

				<section aria-labelledby="ud-actions">
					<h3 id="ud-actions" class="mb-2 text-sm font-semibold">Actions</h3>
					<div class="flex flex-wrap gap-2">
						{#snippet act(a: IdentityAction, label: string, icon: typeof Ban, onclick: () => void)}
							{@const reason = why(u, a)}
							<Button size="sm" {icon} disabled={!!reason || !!busy} loading={busy === a} title={reason ?? undefined} {onclick}>{label}</Button>
						{/snippet}
						{@render act('unlock', 'Unlock', LockOpen, () => run(u, 'unlock', { done: `${who} unlocked.` }))}
						{@render act('reset-password', 'Reset password', KeyRound, () => (resetting = true))}
						{#if u.enabled}
							{@render act('disable', 'Disable', Ban, () => run(u, 'disable', { confirm: `Disable ${who}?`, done: `${who} disabled.` }))}
						{:else}
							{@render act('enable', 'Enable', CircleCheck, () => run(u, 'enable', { done: `${who} enabled.` }))}
						{/if}
						{@render act('revoke-sessions', 'Sign out everywhere', LogOut, () => run(u, 'revoke-sessions', { confirm: `Sign ${who} out of every session?`, done: `${who}’s sessions were revoked.` }))}
					</div>
					{#if !u.can_manage}<p class="hint mt-2">{why(u, 'disable')}</p>{/if}
				</section>

				<section aria-labelledby="ud-groups">
					<div class="mb-2 flex items-center justify-between gap-2">
						<h3 id="ud-groups" class="text-sm font-semibold">Groups <span class="text-muted font-normal">({u.groups.length})</span></h3>
						{#if u.groups.length}
							{@const reason = why(u, 'remove-groups')}
							<Button size="sm" variant="ghost" icon={Users} disabled={!!reason || !!busy} title={reason ?? undefined} loading={busy === 'remove-groups'} onclick={() => run(u, 'remove-groups', { confirm: `Remove ${who} from all ${u.groups.length} groups?`, done: `${who} removed from every group.` })}>Remove from all</Button>
						{/if}
					</div>
					{#if u.groups.length}
						<ul class="divide-border border-border divide-y rounded-md border">
							{#each u.groups as g (g.id)}
								<li class="flex items-center gap-2 px-3 py-1.5 text-sm">
									<span class="min-w-0 flex-1 truncate">{g.name}</span>
									{#if g.privileged}<Badge tone="warning">Privileged</Badge>{/if}
									<IconButton icon={X} size="sm" label="Remove {who} from {g.name}" disabled={!!why(u, 'remove-groups') || !!busy} onclick={() => run(u, 'remove-groups', { confirm: `Remove ${who} from ${g.name}?`, done: `${who} removed from ${g.name}.`, body: { group_ids: [g.id] } })} />
								</li>
							{/each}
						</ul>
					{:else}
						<p class="text-muted text-sm">{u.kind === 'ad' ? 'No groups beyond the primary one.' : 'No groups.'}</p>
					{/if}
				</section>

				{#if templates.data?.length}
					{@const mine = templates.data.filter((t) => !t.client_id || t.client_id === u.client_id)}
					<section aria-labelledby="ud-ticket">
						<h3 id="ud-ticket" class="mb-2 text-sm font-semibold">Open a ticket about {who}</h3>
						<div class="flex gap-2">
							<Select aria-label="Template" class="min-w-0 flex-1" bind:value={template} options={[{ value: '', label: 'Choose a template…', disabled: true }, ...mine.map((t) => ({ value: t.id, label: t.name }))]} />
							<Button size="sm" icon={ListChecks} disabled={!template} loading={opening} onclick={() => openTicket(u)}>Open</Button>
						</div>
						<p class="hint mt-1">The ticket gets the template’s checklist; its actions run on this account.</p>
					</section>
				{/if}
			</div>
			{#if resetting}
				<ResetDialog user={u} onclose={() => (resetting = false)} ondone={() => (user.reload(), onchange?.())} />
			{/if}
		{/snippet}
	</Async>
</Drawer>
