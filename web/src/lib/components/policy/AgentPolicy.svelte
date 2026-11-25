<script lang="ts">
	import { Pin, PinOff, SlidersHorizontal, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { cx, num } from '#lib/format.js';
	import { itemHref, moduleLabels, overriddenAlong, setHref, singleModules, treeOrder } from '#lib/policy/policy.js';
	import type { AgentPolicy, ItemView, SetRow } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentDetail } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import AutomationHistory from './AutomationHistory.svelte';
	import CategoryChange from './CategoryChange.svelte';

	/** An agent's category, the policy set it uses and why, and every policy that reaches it. */
	let { agent, onchange }: { agent: AgentDetail; onchange?: () => void } = $props();

	const res = resource(() => api.get<AgentPolicy>(`/agents/${agent.id}/policy`));
	let changing = $state(false);
	let pinning = $state(false);
	let pinTo = $state('');
	const sets = resource(() => (pinning ? api.get<SetRow[]>(`/policy-sets?client_id=${agent.client_id}`) : Promise.resolve([] as SetRow[])));
	const tech = $derived(can('technician'));

	function why(p: AgentPolicy): string {
		switch (p.reason) {
			case 'pin':
				return 'Pinned to this device.';
			case 'site':
				return `Assigned to the site ${agent.site_name} for ${p.category.name}.`;
			case 'client':
				return `Assigned to ${agent.client_name} for ${p.category.name}.`;
			default:
				return `The default set of ${p.category.name}; nothing is assigned to ${agent.client_name} or ${agent.site_name} for it.`;
		}
	}
	function done(p: AgentPolicy, msg: string) {
		res.set(p);
		toast.success(msg);
		onchange?.();
	}
	async function pin(e: SubmitEvent) {
		e.preventDefault();
		await attempt(async () => {
			const p = await api.put<AgentPolicy>(`/agents/${agent.id}/policy-pin`, { policy_set_id: pinTo });
			pinning = false;
			done(p, `${agent.hostname} now uses ${p.set.name}, whatever its category and assignments say.`);
		});
	}
	async function unpin(p: AgentPolicy, deleteSet: boolean) {
		const set = p.pin!;
		if (deleteSet) {
			const ok = await confirmAction({ title: `Unpin and delete ${set.name}?`, message: 'The set and its policies are deleted. If anything else uses it, it stays and only the pin goes.', confirmLabel: 'Unpin and delete', danger: true });
			if (!ok) return;
		}
		await attempt(async () => {
			const next = await api.put<AgentPolicy>(`/agents/${agent.id}/policy-pin`, { policy_set_id: null });
			let msg = `${agent.hostname} uses ${next.set.name} again.`;
			if (deleteSet) {
				try {
					await api.del(`/policy-sets/${set.id}`);
					msg += ` ${set.name} deleted.`;
				} catch (err) {
					msg += ` ${set.name} was kept: ${err instanceof Error ? err.message : err}`;
				}
			}
			done(next, msg);
		});
	}
	async function customize(p: AgentPolicy) {
		const ok = await confirmAction({
			title: `Customize policies for ${agent.hostname}?`,
			message: `A new set below ${p.set.name}, named after the device and belonging to ${agent.client_name}, is pinned to it. It starts identical; change single fields in it without touching other devices.`,
			confirmLabel: 'Create and pin'
		});
		if (!ok) return;
		await attempt(async () => {
			const next = await api.post<AgentPolicy>(`/agents/${agent.id}/policy-pin/customize`);
			done(next, `${next.set.name} created and pinned. Override what this device needs there.`);
		});
	}
	async function setExcluded(v: ItemView, excluded: boolean) {
		const path = `/policy-items/${v.id}/exclusions/${agent.id}`;
		if (await attempt(() => (excluded ? api.put(path, {}) : api.del(path)), excluded ? `${agent.hostname} is left out of ${v.name}; its alerts from it are closed.` : `${v.name} covers ${agent.hostname} again.`)) res.reload();
	}

	const groups = (p: AgentPolicy) =>
		[
			{ m: 'alert', label: moduleLabels.alert, list: p.policies.filter((x) => x.module === 'alert') },
			{ m: 'schedule', label: moduleLabels.schedule, list: p.policies.filter((x) => x.module === 'schedule') },
			{ m: 'software', label: moduleLabels.software, list: p.policies.filter((x) => x.module === 'software') },
			{ m: 'automation', label: moduleLabels.automation, list: p.policies.filter((x) => x.module === 'automation') },
			{ m: 'settings', label: 'Settings', list: p.policies.filter((x) => singleModules.includes(x.module)) }
		].filter((g) => g.list.length);
	const onlyFor = (v: ItemView) => (v.limit.client_id && v.limit.client_id !== agent.client_id ? v.limit.client_name : v.limit.site_name) ?? 'other devices';
	const sameSet = (p: AgentPolicy) => (sets.data ?? []).length > 0 && pinTo === p.set.id;
</script>

<Async {res}>
	{#snippet children(p)}
		<div class="grid gap-4 xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)]">
			<section class="card self-start" aria-labelledby="ap-set">
				<header class="panel-head"><h2 id="ap-set" class="panel-title">Policy set</h2></header>
				<dl class="dl p-4">
					<dt>Category</dt>
					<dd>
						<span class="font-medium">{p.category.name}</span>
						<span class="text-muted block text-xs">{p.category.manual ? 'Set by hand' : `Automatic: ${agent.os_family === 'other' ? 'other OS' : p.platform}`}</span>
						{#if tech}<button type="button" class="link mt-0.5 text-xs" onclick={() => (changing = true)}>Change category</button>{/if}
					</dd>
					<dt>Uses</dt>
					<dd>
						<a class="link font-medium" href={setHref(p.set.id)}>{p.set.name}</a>
						{#if p.pin}<Badge tone="info" icon={Pin} class="ml-1">Pinned</Badge>{/if}
						<span class="text-muted mt-0.5 block text-xs">{p.chain.map((c) => c.name).join(' › ')}</span>
					</dd>
					<dt>Why</dt>
					<dd>{why(p)}</dd>
				</dl>
				{#if tech}
					<div class="border-border flex flex-wrap gap-2 border-t px-4 py-3">
						{#if p.pin}
							<Button size="sm" icon={PinOff} onclick={() => unpin(p, false)}>Unpin</Button>
							{#if p.pin.client_id}<Button size="sm" variant="ghost" icon={Trash2} onclick={() => unpin(p, true)}>Unpin and delete set</Button>{/if}
						{:else}
							<Button size="sm" icon={SlidersHorizontal} onclick={() => customize(p)}>Customize for this device</Button>
						{/if}
						<Button size="sm" variant="ghost" icon={Pin} onclick={() => ((pinTo = p.set.id), (pinning = true))}>{p.pin ? 'Pin another set…' : 'Pin a set…'}</Button>
					</div>
				{/if}
			</section>

			<section class="card min-w-0" aria-labelledby="ap-policies">
				<header class="panel-head">
					<div class="min-w-0">
						<h2 id="ap-policies" class="panel-title">Policies on this device</h2>
						<p class="text-muted text-xs">Everything that reaches {p.set.name}, with the set it's defined in and the sets that change it.</p>
					</div>
				</header>
				{#each groups(p) as g (g.m)}
					<h3 class="bg-sunken/60 text-muted border-border border-b px-4 py-1.5 text-xs font-medium">{g.label}{g.m !== 'settings' ? ` · ${num(g.list.length)}` : ''}</h3>
					<ul class="divide-border border-border divide-y border-b last:border-b-0">
						{#each g.list as v (v.id)}
							{@const along = overriddenAlong(v, p.chain)}
							{@const off = !v.enabled || v.applies === false}
							<li class="flex flex-wrap items-start gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
								<div class="min-w-0 flex-1">
									<div class="flex flex-wrap items-center gap-2">
										<a class={cx('inline-flex min-h-6 items-center', off ? 'text-muted hover:text-fg line-through decoration-1' : 'hover:text-accent font-medium')} href={itemHref(p.set.id, v)}>{g.m === 'settings' ? moduleLabels[v.module] : v.name}</a>
										{#if v.excluded}<Badge>Left out here</Badge>{:else if v.applies === false}<Badge title="Limited to {v.limit.client_name}{v.limit.site_name ? ` › ${v.limit.site_name}` : ''}">Only for {onlyFor(v)}</Badge>{:else if !v.enabled}<Badge>Off</Badge>{/if}
										{#if v.open_alerts}<a class="text-danger inline-flex min-h-6 items-center text-xs font-medium hover:underline" href="/alerts?policy={v.id}&agent={agent.id}">{v.open_alerts} open</a>{/if}
									</div>
									<p class="text-muted text-xs">
										From <a class="hover:text-fg underline decoration-dotted underline-offset-2" href={setHref(v.origin_set_id)}>{v.origin_set_name}</a>{#each along as a (a.set.id)}<span>{' · '}changed in <a class="hover:text-fg underline decoration-dotted underline-offset-2" href={setHref(a.set.id)}>{a.set.name}</a>: {a.fields.join(', ')}</span>{/each}
									</p>
								</div>
								{#if g.m !== 'settings' && v.editable && v.applies !== false}
									<Button size="sm" variant="ghost" onclick={() => setExcluded(v, !v.excluded)}>{v.excluded ? 'Include' : 'Leave out'}</Button>
								{:else if v.excluded && v.editable}
									<Button size="sm" variant="ghost" onclick={() => setExcluded(v, false)}>Include</Button>
								{/if}
							</li>
						{/each}
					</ul>
				{/each}
			</section>
			<AutomationHistory agentId={agent.id} />
		</div>

		{#if changing}<CategoryChange agentIds={[agent.id]} current={p.category.manual ? p.category.id : ''} onclose={() => (changing = false)} ondone={() => (res.reload(), onchange?.())} />{/if}
		{#if pinning}
			<Modal title="Pin a policy set to {agent.hostname}" onclose={() => (pinning = false)} size="sm" description="A pin wins over the category's assignments and default. Only MSP-wide sets and {agent.client_name}'s own.">
				<form id="pin-form" onsubmit={pin}>
					<Field label="Policy set" id="pin-set">
						<Select id="pin-set" class="w-full" bind:value={pinTo} options={treeOrder(sets.data ?? []).map((s) => ({ value: s.id, label: `${' '.repeat(s.depth)}${s.name}` }))} />
					</Field>
				</form>
				{#snippet footer()}
					<Button onclick={() => (pinning = false)}>Cancel</Button>
					<Button variant="primary" type="submit" form="pin-form" disabled={!pinTo || (sameSet(p) && !!p.pin)}>Pin</Button>
				{/snippet}
			</Modal>
		{/if}
	{/snippet}
</Async>
