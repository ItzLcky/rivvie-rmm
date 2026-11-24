<script lang="ts">
	import { ExternalLink } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Board, DeskSettings } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	let { boards }: { boards: Board[] } = $props();
	const settings = resource(() => api.get<DeskSettings>('/settings/service-desk'));
	let saving = $state(false);

	async function save(e: SubmitEvent, s: DeskSettings) {
		e.preventDefault();
		saving = true;
		if (await attempt(() => api.put('/settings/service-desk', s), 'Portal settings saved.')) settings.reload();
		saving = false;
	}
</script>

<section class="card" aria-labelledby="portal-h">
	<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="portal-h" class="font-semibold">Client portal and surveys</h2>
			<p class="text-muted text-xs">Contacts with portal access sign in at /portal with an emailed link (or a password they set) to follow and open tickets.</p>
		</div>
		<Button size="sm" icon={ExternalLink} href="/portal/login">Open the portal</Button>
	</header>
	<Async res={settings} compact>
		{#snippet children(s)}
			<form class="space-y-4 px-5 py-4" onsubmit={(e) => save(e, s)}>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Requests from the portal go to" id="ps-board">
						<Select id="ps-board" class="w-full" bind:value={() => s.portal_board_id ?? '', (v) => (s.portal_board_id = v || null)} options={[{ value: '', label: 'The first board' }, ...boards.map((b) => ({ value: b.id, label: b.name }))]} />
					</Field>
					<Field label="Requests from the tray app go to" id="ps-tray-board" hint="Help requests people send from a device.">
						<Select id="ps-tray-board" class="w-full" bind:value={() => s.tray_board_id ?? '', (v) => (s.tray_board_id = v || null)} options={[{ value: '', label: 'The portal\'s board' }, ...boards.map((b) => ({ value: b.id, label: b.name }))]} />
					</Field>
				</div>
				<Field label="Welcome text" id="ps-welcome" hint="Shown on the portal's sign-in page and home page.">
					<Textarea id="ps-welcome" rows={3} maxlength={2000} bind:value={s.portal_welcome} />
				</Field>
				<div>
					<Switch bind:checked={s.csat_enabled}>Ask how we did when a ticket is resolved</Switch>
					<p class="hint pl-11.5">One email per ticket with Good / Bad links; answers show on the ticket and in reports.</p>
				</div>
				<p class="hint">Give contacts access on the client's Contacts tab (and send them an invitation from there). Whether the portal lists a client's devices is set on the client.</p>
				<Button variant="primary" type="submit" loading={saving}>Save</Button>
			</form>
		{/snippet}
	</Async>
</section>
