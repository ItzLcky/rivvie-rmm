<script lang="ts">
	import { api } from '#lib/api.js';
	import { company } from '#lib/session.svelte.js';

	interface Settings {
		company_name: string; session_idle_hours: number | null; session_idle_hours_default: number; require_2fa_all: boolean;
		auto_update_agents: boolean;
	}

	let form = $state({ company_name: '', idle: '', require_2fa_all: false, auto_update_agents: false });
	let defaultIdle = $state(12);
	let loaded = $state(false);
	let error = $state('');
	let done = $state('');
	let busy = $state(false);

	function apply(s: Settings) {
		form = {
			company_name: s.company_name, idle: s.session_idle_hours?.toString() ?? '', require_2fa_all: s.require_2fa_all,
			auto_update_agents: s.auto_update_agents
		};
		defaultIdle = s.session_idle_hours_default;
		company.name = s.company_name;
		loaded = true;
	}

	$effect(() => {
		api.get<Settings>('/settings').then(apply).catch((e) => (error = (e as Error).message));
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		done = '';
		const idle = form.idle.trim();
		if (idle && !/^\d+$/.test(idle)) {
			error = 'Idle timeout must be a whole number of hours';
			return;
		}
		busy = true;
		try {
			apply(
				await api.put<Settings>('/settings', {
					company_name: form.company_name, session_idle_hours: idle ? Number(idle) : null, require_2fa_all: form.require_2fa_all,
					auto_update_agents: form.auto_update_agents
				})
			);
			done = 'Saved.';
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

{#if loaded}
	<form class="max-w-2xl space-y-6" onsubmit={save}>
		<section class="card space-y-3 p-4">
			<h2 class="font-semibold">Organisation</h2>
			<div>
				<label class="label" for="cn">Company name</label>
				<input id="cn" class="input" maxlength="100" placeholder="Acme IT" bind:value={form.company_name} />
				<p class="mt-1 text-xs text-slate-500">Shown in the sidebar, on the sign-in page and in the browser tab.</p>
			</div>
		</section>
		<section class="card space-y-3 p-4">
			<h2 class="font-semibold">Security</h2>
			<div>
				<label class="label" for="idle">Session idle timeout (hours)</label>
				<input id="idle" class="input max-w-40" inputmode="numeric" placeholder={`${defaultIdle} (server default)`} bind:value={form.idle} />
				<p class="mt-1 text-xs text-slate-500">
					Sign users out after this long without activity, 1–168 hours. Leave empty to use the server default ({defaultIdle} h, from <code>RMM_SESSION_IDLE_HOURS</code>). Sessions always end after 7 days.
				</p>
			</div>
			<div>
				<label class="flex items-center gap-2 text-sm"><input type="checkbox" class="accent-sky-500" bind:checked={form.require_2fa_all} /> Require two-factor authentication for all users</label>
				<p class="mt-1 text-xs text-slate-500">Admins always need it. When on, technicians and read-only users must also set it up at their next sign-in before they can use the dashboard.</p>
			</div>
		</section>
		<section class="card space-y-3 p-4">
			<h2 class="font-semibold">Agents</h2>
			<div>
				<label class="flex items-center gap-2 text-sm"><input type="checkbox" class="accent-sky-500" bind:checked={form.auto_update_agents} /> Update agents automatically</label>
				<p class="mt-1 text-xs text-slate-500">
					When an agent connects and the server has a newer signed release for its platform, the agent installs it (after its running jobs finish) and rolls back by itself if the new version can't reconnect. A version that failed or rolled back on an agent isn't retried there automatically. Off: update from the Agents page.
				</p>
			</div>
		</section>
		{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
		<div class="flex items-center justify-end gap-3">
			{#if done}<span class="text-sm text-emerald-400">{done}</span>{/if}
			<button class="btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
		</div>
	</form>
{:else if error}
	<p class="text-sm text-red-400">{error}</p>
{/if}
