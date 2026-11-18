<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { setHref, treeOrder } from '#lib/policy/policy.js';
	import type { Assignment, Category, SetRow } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	/**
	 * Which policy set each device category uses at one client: for the whole client, and per
	 * site. An empty cell follows the client's choice (sites) or the category's default.
	 */
	let { clientId, onchange }: { clientId: string; onchange?: () => void } = $props();

	$effect(() => {
		untrack(() => loadClients());
	});
	const client = $derived(clients.list.find((c) => c.id === clientId));
	const categories = resource(() => api.get<Category[]>('/device-categories'));
	const sets = resource(() => api.get<SetRow[]>(`/policy-sets?client_id=${clientId}`));
	const assignments = resource(() => api.get<Assignment[]>(`/policy-assignments?client_id=${clientId}`));
	const editable = $derived(can('technician'));
	const options = $derived(treeOrder(sets.data ?? []).map((s) => ({ value: s.id, label: `${' '.repeat(s.depth)}${s.name}` })));

	const find = (cat: string, site: string | null) => assignments.data?.find((a) => a.category_id === cat && a.site_id === site);
	function inherited(cat: Category, site: string | null): string {
		const c = site ? find(cat.id, null) : undefined;
		return c ? `Client: ${c.policy_set_name}` : `Default: ${cat.default_set_name}`;
	}
	async function pick(cat: Category, site: { id: string; name: string } | null, setId: string) {
		const cur = find(cat.id, site?.id ?? null);
		const where = `${cat.name} at ${site?.name ?? client?.name ?? 'this client'}`;
		const ok = await attempt(
			() => (setId ? api.put('/policy-assignments', { client_id: clientId, site_id: site?.id ?? null, category_id: cat.id, policy_set_id: setId }) : cur ? api.del(`/policy-assignments/${cur.id}`) : Promise.resolve()),
			setId ? `${where} now use ${sets.data?.find((s) => s.id === setId)?.name}.` : `${where} follow ${inherited(cat, site?.id ?? null).replace(/^\w+: /, '')} again.`
		);
		await assignments.reload();
		if (ok) onchange?.();
	}
	const scopes = $derived([null, ...(client?.sites ?? [])]);
</script>

{#if !categories.data || !assignments.data || !sets.data}
	<div class="space-y-2 p-4" aria-busy="true"><Skeleton lines={6} /></div>
{:else}
	<div class="scrollbar-thin overflow-x-auto">
		<table class="table min-w-full">
			<caption class="sr-only">Policy sets by device category{client ? ` at ${client.name}` : ''}</caption>
			<thead>
				<tr>
					<th scope="col" class="bg-raised sticky left-0 z-[1] min-w-40">Category</th>
					{#each scopes as sc (sc?.id ?? 'client')}
						<th scope="col" class="min-w-52">{sc ? sc.name : 'Whole client'}{#if !sc}<span class="text-muted block text-xs font-normal">Every site</span>{:else}<span class="text-muted block text-xs font-normal">Site</span>{/if}</th>
					{/each}
				</tr>
			</thead>
			<tbody>
				{#each categories.data as cat (cat.id)}
					<tr>
						<th scope="row" class="bg-raised sticky left-0 z-[1] text-left font-medium">{cat.name}{#if !cat.builtin}<span class="text-muted block text-xs font-normal">Custom</span>{/if}</th>
						{#each scopes as sc (sc?.id ?? 'client')}
							{@const a = find(cat.id, sc?.id ?? null)}
							<td>
								{#if editable}
									<select
										class={cx('control h-8 min-w-48 text-[13px]', !a && 'text-muted')}
										aria-label="{cat.name} at {sc?.name ?? `${client?.name ?? 'the client'} (every site)`}"
										value={a?.policy_set_id ?? ''}
										onchange={(e) => pick(cat, sc, e.currentTarget.value)}
									>
										<option value="">{inherited(cat, sc?.id ?? null)}</option>
										{#each options as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
									</select>
								{:else if a}
									<a class="link" href={setHref(a.policy_set_id)}>{a.policy_set_name}</a>
								{:else}
									<span class="text-muted">{inherited(cat, sc?.id ?? null)}</span>
								{/if}
								{#if a && editable}<a class="text-muted hover:text-fg mt-1 inline-flex min-h-6 items-center text-xs" href={setHref(a.policy_set_id)}>Assigned · open set</a>{/if}
							</td>
						{/each}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
