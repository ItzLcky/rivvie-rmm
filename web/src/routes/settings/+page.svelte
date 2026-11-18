<script lang="ts">
	import { api } from '#lib/api.js';
	import { ROOT_SET } from '#lib/policy/policy.js';
	import { company } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	interface Settings {
		company_name: string; session_idle_hours: number | null; session_idle_hours_default: number; require_2fa_all: boolean;
	}

	let form = $state({ company_name: '', idle: '', require_2fa_all: false });
	let defaultIdle = $state(12);
	let saved = $state('');
	let busy = $state(false);
	let idleError = $state('');

	function apply(s: Settings) {
		form = { company_name: s.company_name, idle: s.session_idle_hours?.toString() ?? '', require_2fa_all: s.require_2fa_all };
		defaultIdle = s.session_idle_hours_default;
		company.name = s.company_name;
		saved = JSON.stringify(form);
		return s;
	}
	const res = resource(() => api.get<Settings>('/settings').then(apply));
	const dirty = $derived(JSON.stringify(form) !== saved);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const idle = form.idle.trim();
		idleError = idle && !/^\d+$/.test(idle) ? 'A whole number of hours, 1–168' : '';
		if (idleError) return;
		busy = true;
		try {
			apply(
				await api.put<Settings>('/settings', {
					company_name: form.company_name, session_idle_hours: idle ? Number(idle) : null, require_2fa_all: form.require_2fa_all
				})
			);
			toast.success('Settings saved.');
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Async {res}>
	{#snippet children()}
		<form class="max-w-2xl space-y-5" onsubmit={save}>
			<section class="card space-y-4 p-5">
				<h2 class="font-semibold">Organisation</h2>
				<Field label="Company name" id="cn" hint="Shown in the sidebar, on the sign-in page and in the browser tab.">
					<Input id="cn" maxlength={100} placeholder="Acme IT" bind:value={form.company_name} />
				</Field>
			</section>
			<section class="card space-y-4 p-5">
				<h2 class="font-semibold">Security</h2>
				<Field label="Session idle timeout (hours)" id="idle" error={idleError}>
					<Input id="idle" class="max-w-48" inputmode="numeric" placeholder="{defaultIdle} (server default)" bind:value={form.idle} invalid={!!idleError} />
					{#snippet hint()}
						Sign users out after this long without activity, 1–168 hours. Leave empty for the server default ({defaultIdle} h, from <code>RMM_SESSION_IDLE_HOURS</code>). Sessions always end after 7 days.
					{/snippet}
				</Field>
				<div>
					<Switch bind:checked={form.require_2fa_all}>Require two-factor authentication for all users</Switch>
					<p class="hint ml-11.5">Admins always need it. When on, technicians and read-only users must set it up at their next sign-in before they can use the dashboard.</p>
				</div>
			</section>
			<section class="card space-y-4 p-5">
				<h2 class="font-semibold">Agents</h2>
				<p class="text-muted text-sm">
					Automatic agent updates are part of the agent policy: switch them on or off in <a class="link" href="/policies/sets/{ROOT_SET}?section=agent">All devices</a>, and differently for any set below it (say, servers updated by hand). Without them, update from the Agents page.
				</p>
			</section>
			<div class="flex items-center justify-end gap-3">
				{#if dirty}<span class="text-warning text-xs">Unsaved changes</span>{/if}
				<Button variant="primary" type="submit" loading={busy} disabled={!dirty}>Save</Button>
			</div>
		</form>
	{/snippet}
</Async>
