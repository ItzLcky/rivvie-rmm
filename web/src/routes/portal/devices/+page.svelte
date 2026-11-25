<script lang="ts">
	import { Monitor, RotateCw } from '@lucide/svelte';
	import { ago, datetime, plural } from '#lib/format.js';
	import { portal, PortalError } from '#lib/portal/api.js';
	import { me } from '#lib/portal/me.svelte.js';
	import type { PortalDevice } from '#lib/portal/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	let devices = $state<PortalDevice[] | null>(null);
	let error = $state('');
	let off = $state(false);

	async function load() {
		error = '';
		try {
			devices = await portal.get<PortalDevice[]>('/devices');
		} catch (e) {
			if (e instanceof PortalError && e.status === 404) off = true;
			else error = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		load();
	});

	const online = $derived(devices?.filter((d) => d.online).length ?? 0);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-medium">Devices</h1>
		<p class="text-muted mt-1 text-sm">
			{#if devices?.length}{plural(devices.length, 'device')} we look after for {me.data?.contact.client_name}, {online} online now.{:else}The computers we look after for you.{/if}
		</p>
	</div>

	{#if off}
		<div class="card"><EmptyState icon={Monitor} title="Device list not available" description="Your organisation hasn't turned on the device list in the portal." /></div>
	{:else if error}
		<div class="card"><ErrorState {error} onretry={load} /></div>
	{:else if !devices}
		<div class="card p-4"><Skeleton lines={6} /></div>
	{:else if !devices.length}
		<div class="card"><EmptyState icon={Monitor} title="No devices yet" /></div>
	{:else}
		<!-- Phones: one card per device. -->
		<ul class="space-y-2 md:hidden">
			{#each devices as d (d.id)}
				<li class="card p-4">
					<div class="flex items-center justify-between gap-2">
						<span class="min-w-0 truncate font-medium">{d.hostname}</span>
						<Badge tone={d.online ? 'success' : 'neutral'} dot>{d.online ? 'Online' : 'Offline'}</Badge>
					</div>
					<dl class="dl mt-3">
						<dt>Site</dt>
						<dd>{d.site_name}</dd>
						<dt>System</dt>
						<dd>{d.os_name} {d.os_version}</dd>
						<dt>Last seen</dt>
						<dd>{d.online ? 'Now' : ago(d.last_seen_at)}</dd>
						<dt>Updates</dt>
						<dd class="flex flex-wrap gap-1">
							{#if d.missing_patches}<Badge tone="warning">{plural(d.missing_patches, 'update')} pending</Badge>{:else}Up to date{/if}
							{#if d.reboot_pending}<Badge tone="info" icon={RotateCw}>Restart needed</Badge>{/if}
						</dd>
					</dl>
				</li>
			{/each}
		</ul>
		<div class="card hidden overflow-x-auto md:block">
			<table class="table">
				<caption class="sr-only">Devices</caption>
				<thead>
					<tr><th scope="col">Name</th><th scope="col">Site</th><th scope="col">System</th><th scope="col">Status</th><th scope="col">Last seen</th><th scope="col">Updates</th></tr>
				</thead>
				<tbody>
					{#each devices as d (d.id)}
						<tr>
							<td class="font-medium">{d.hostname}</td>
							<td>{d.site_name}</td>
							<td class="text-muted">{d.os_name} {d.os_version}</td>
							<td><Badge tone={d.online ? 'success' : 'neutral'} dot>{d.online ? 'Online' : 'Offline'}</Badge></td>
							<td class="text-muted whitespace-nowrap">{#if d.online}Now{:else}<time datetime={d.last_seen_at ?? undefined} title={datetime(d.last_seen_at)}>{ago(d.last_seen_at)}</time>{/if}</td>
							<td>
								<span class="flex flex-wrap gap-1">
									{#if d.missing_patches}<Badge tone="warning">{plural(d.missing_patches, 'update')} pending</Badge>{:else}<span class="text-muted">Up to date</span>{/if}
									{#if d.reboot_pending}<Badge tone="info" icon={RotateCw}>Restart needed</Badge>{/if}
								</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
