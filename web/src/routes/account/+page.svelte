<script lang="ts">
	import { Monitor, Moon, Sun } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { prefs, setPref, type Density, type Theme } from '#lib/prefs.svelte.js';
	import { can, session } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { cx } from '#lib/format.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import ApiKeys from '#lib/components/ApiKeys.svelte';
	import Passkeys from '#lib/components/Passkeys.svelte';
	import Sessions from '#lib/components/Sessions.svelte';
	import TwoFactor from '#lib/components/TwoFactor.svelte';
	import ContactMethods from '#lib/oncall/ContactMethods.svelte';
	import DeviceNotifications from '#lib/oncall/DeviceNotifications.svelte';

	let form = $state({ current: '', next: '', confirm: '' });
	let error = $state('');
	let busy = $state(false);
	// Bumped after a password change so the session list reloads (others were revoked).
	let gen = $state(0);

	async function change(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		if (form.next !== form.confirm) {
			error = 'The new passwords don’t match';
			return;
		}
		busy = true;
		try {
			const r = await api.post<{ sessions_revoked: number }>('/auth/password', { current_password: form.current, new_password: form.next });
			form = { current: '', next: '', confirm: '' };
			toast.success(r.sessions_revoked ? `Password changed. Signed out ${r.sessions_revoked} other session${r.sessions_revoked === 1 ? '' : 's'}.` : 'Password changed.');
			gen++;
		} catch (err) {
			error = (err as Error).message;
		} finally {
			busy = false;
		}
	}

	const themes: { value: Theme; label: string; icon: typeof Sun }[] = [
		{ value: 'system', label: 'System', icon: Monitor },
		{ value: 'light', label: 'Light', icon: Sun },
		{ value: 'dark', label: 'Dark', icon: Moon }
	];
	const setup = $derived(!!session.user?.mfa_setup_required);
</script>

<PageHeader title="Account" description={session.user ? `${session.user.name} · ${session.user.email}` : undefined} />

<div class="grid max-w-5xl gap-5 lg:grid-cols-2">
	<section id="two-factor" class={cx('card scroll-mt-4 p-5', setup && 'lg:col-span-2 lg:max-w-xl')}>
		<h2 class="font-semibold">Two-factor authentication</h2>
		<p class="text-muted mt-0.5 mb-4 text-sm">A code from an authenticator app on your phone, asked for at every sign-in.</p>
		{#key gen}<TwoFactor onchange={() => gen++} />{/key}
	</section>

	<section id="passkeys" class={cx('card scroll-mt-4 p-5', setup && 'lg:col-span-2 lg:max-w-xl')}>
		<h2 class="font-semibold">Passkeys</h2>
		<p class="text-muted mt-0.5 mb-4 text-sm">A security key, or this device’s fingerprint or screen lock. Asked for after your password, instead of an authenticator code if you prefer.</p>
		{#key gen}<Passkeys onchange={() => gen++} />{/key}
	</section>

	{#if !setup}
		<section id="notifications" class="card scroll-mt-4 p-5">
			<h2 class="font-semibold">Notifications</h2>
			<p class="text-muted mt-0.5 mb-4 text-sm">Alerts, pages and ticket updates on this phone or computer, through the browser or the installed app.</p>
			<DeviceNotifications />
		</section>

		{#if can('technician')}
			<section id="reach-me" class="card scroll-mt-4 p-5">
				<h2 class="font-semibold">How to reach me</h2>
				<p class="text-muted mt-0.5 mb-4 text-sm">When you’re on call and paged. Acknowledging stops the rest.</p>
				<ContactMethods />
			</section>
		{/if}

		<section class="card p-5">
			<h2 class="font-semibold">Appearance</h2>
			<p class="text-muted mt-0.5 mb-4 text-sm">Saved to your account, so it follows you to other browsers.</p>
			<div class="space-y-4">
				<div>
					<div class="label">Theme</div>
					<div class="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Theme">
						{#each themes as t (t.value)}
							{@const on = (prefs.theme ?? 'system') === t.value}
							<button
								role="radio"
								aria-checked={on}
								class={cx('flex flex-col items-center gap-1.5 rounded-lg border p-3 text-sm transition-colors', on ? 'border-accent bg-accent-soft text-accent font-medium' : 'border-border hover:bg-hover text-muted')}
								onclick={() => setPref('theme', t.value)}
							>
								<t.icon class="size-5" />{t.label}
							</button>
						{/each}
					</div>
					<p class="hint">System follows your device’s light or dark setting.</p>
				</div>
				<div>
					<div class="label">Table density</div>
					<Segmented
						label="Table density"
						size="md"
						value={prefs.density ?? 'compact'}
						onchange={(v: Density) => setPref('density', v)}
						options={[
							{ value: 'compact', label: 'Compact' },
							{ value: 'comfortable', label: 'Comfortable' }
						]}
					/>
				</div>
			</div>
		</section>

		<section class="card p-5">
			<h2 class="font-semibold">Change password</h2>
			<p class="text-muted mt-0.5 mb-4 text-sm">Your other sessions are signed out.</p>
			<form class="space-y-3" onsubmit={change}>
				<input type="email" class="hidden" autocomplete="username" value={session.user?.email ?? ''} readonly />
				<Field label="Current password" id="pc"><Input id="pc" type="password" autocomplete="current-password" required bind:value={form.current} /></Field>
				<Field label="New password" id="pn" hint="At least 12 characters."><Input id="pn" type="password" autocomplete="new-password" required minlength={12} bind:value={form.next} /></Field>
				<Field label="Repeat new password" id="pr" {error}><Input id="pr" type="password" autocomplete="new-password" required bind:value={form.confirm} invalid={!!error} /></Field>
				<div class="flex justify-end"><Button variant="primary" type="submit" loading={busy}>Change password</Button></div>
			</form>
		</section>

		<section class="card p-5">
			<h2 class="font-semibold">Sessions</h2>
			<p class="text-muted mt-0.5 mb-4 text-sm">Browsers and API clients signed in as you. Sessions end after a period of inactivity, or after 7 days.</p>
			{#key gen}<Sessions base="/auth/sessions" />{/key}
		</section>

		<div class="lg:col-span-2"><ApiKeys /></div>
	{/if}
</div>
