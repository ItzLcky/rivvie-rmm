<script lang="ts">
	import { BellOff, BellRing, Send } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { currentSubscription, disablePush, enablePush, ios, pushSupported, standalone } from '#lib/push.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { NotificationPrefs } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Account → Notifications: this device, and what each event sends. */
	let here = $state<boolean | null>(null);
	let busy = $state(false);
	const supported = pushSupported();
	const iosBrowser = ios() && !standalone();
	$effect(() => {
		currentSubscription().then((s) => (here = !!s)).catch(() => (here = false));
	});
	const prefs = resource(() => api.get<NotificationPrefs>('/account/notification-prefs'));

	async function toggleDevice() {
		busy = true;
		try {
			if (here) {
				await disablePush();
				here = false;
				toast.success('Notifications turned off on this device.');
			} else {
				await enablePush();
				here = true;
				toast.success('Notifications turned on for this device.');
			}
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	async function test() {
		const r = await api.post<{ sent: number }>('/push/test').catch((e) => (toast.error(e), null));
		if (r) toast.success(r.sent ? `Sent to ${r.sent} device${r.sent === 1 ? '' : 's'}.` : 'No device of yours has notifications on.');
	}
	async function save(p: NotificationPrefs) {
		await attempt(() => api.put<NotificationPrefs>('/account/notification-prefs', { hide_details: p.hide_details, events: p.events.map(({ event, push, email }) => ({ event, push, email })) }).then((v) => prefs.set(v)));
	}
</script>

<div class="space-y-4">
	<div class="flex flex-wrap items-center gap-3">
		{#if supported}
			<Button icon={here ? BellOff : BellRing} variant={here ? 'secondary' : 'primary'} loading={busy} disabled={here === null} onclick={toggleDevice}>
				{here ? 'Turn off on this device' : 'Turn on for this device'}
			</Button>
			<Button icon={Send} onclick={test}>Send a test</Button>
		{:else}
			<p class="text-muted text-sm">This browser can’t receive notifications{iosBrowser ? '' : '.'}</p>
		{/if}
	</div>
	{#if iosBrowser}
		<p class="hint">On an iPhone or iPad, add this app to the Home Screen first (Share → Add to Home Screen, iOS 16.4 or later), then turn notifications on from there.</p>
	{/if}
	<Async res={prefs} compact>
		{#snippet children(p)}
			<table class="table">
				<thead><tr><th>Event</th><th class="w-20 text-center">Push</th><th class="w-20 text-center">Email</th></tr></thead>
				<tbody>
					{#each p.events as e (e.event)}
						<tr>
							<td>{e.label}</td>
							<td class="text-center"><Switch label="Push: {e.label}" bind:checked={e.push} onchange={() => save(p)} /></td>
							<td class="text-center">{#if e.email_applies}<Switch label="Email: {e.label}" bind:checked={e.email} onchange={() => save(p)} />{:else}<span class="text-muted text-xs" title="Alerts email through notification channels; pages by your contact methods">–</span>{/if}</td>
						</tr>
					{/each}
				</tbody>
			</table>
			<Switch bind:checked={p.hide_details} onchange={() => save(p)}>Hide client and device names on the lock screen</Switch>
		{/snippet}
	</Async>
</div>
