<script lang="ts">
	import { ImageUp, Trash2 } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { api } from '#lib/api.js';
	import type { Branding } from '#lib/branding.js';
	import { applyBranding } from '#lib/branding.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { company } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import SupportCard from './SupportCard.svelte';

	/**
	 * Edits one branding row: the instance's (Settings → Branding) or a client's override (the
	 * client's Settings tab, `clientId` set), with a preview of the rail, the sign-in page, an
	 * email and the support card.
	 */
	let { clientId = null, clientName = '' }: { clientId?: string | null; clientName?: string } = $props();

	type Variant = 'logo_light' | 'logo_dark' | 'icon';
	type View = {
		exists: boolean;
		product_name: string | null;
		accent: string | null;
		support_email: string | null;
		support_phone: string | null;
		support_url: string | null;
		support_hours: string | null;
		email_from_name: string | null;
		email_footer: string | null;
		logo_light: string | null;
		logo_dark: string | null;
		icon: string | null;
		updated_at: string | null;
		resolved: Branding;
	};
	const FIELDS = ['product_name', 'accent', 'support_email', 'support_phone', 'support_url', 'support_hours', 'email_from_name', 'email_footer'] as const;
	type Form = Record<(typeof FIELDS)[number], string>;

	const base = $derived(clientId ? `/clients/${clientId}/branding` : '/settings/branding');
	const uid = $derived(clientId ? `cb-${clientId.slice(0, 8)}` : 'brand');
	let form = $state<Form>(Object.fromEntries(FIELDS.map((f) => [f, ''])) as Form);
	let saved = $state('');
	let busy = $state(false);
	let uploading = $state<Variant | null>(null);
	let error = $state('');

	function apply(v: View) {
		form = Object.fromEntries(FIELDS.map((f) => [f, v[f] ?? ''])) as Form;
		saved = JSON.stringify(form);
		// The console itself shows the instance's branding.
		if (!clientId) {
			company.branding = v.resolved;
			applyBranding(v.resolved);
		}
		return v;
	}
	const res = resource(() => api.get<View>(base).then(apply));
	// A client's form shows what it inherits from the instance as placeholders.
	const inherited = resource(() => (clientId ? api.get<View>('/settings/branding') : Promise.resolve(null)));
	const dirty = $derived(JSON.stringify(form) !== saved);
	const placeholder = (f: keyof Form, fallback: string) => (clientId ? (inherited.data?.[f] ?? fallback) || fallback : fallback);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			res.set(apply(await api.put<View>(base, Object.fromEntries(FIELDS.map((f) => [f, form[f].trim() || null])))));
			toast.success(clientId ? `Branding for ${clientName} saved.` : 'Branding saved.');
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function upload(v: Variant, e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const f = input.files?.[0];
		if (!f) return;
		uploading = v;
		try {
			const body = new FormData();
			body.append('file', f);
			const r = await fetch(`/api${base}/${v}`, { method: 'POST', body, credentials: 'same-origin' });
			const data = await r.json().catch(() => null);
			if (!r.ok) throw new Error(data?.error ?? r.statusText);
			res.set(apply(data as View));
			toast.success('Image uploaded.');
		} catch (err) {
			toast.error(err);
		} finally {
			uploading = null;
			input.value = '';
		}
	}

	async function removeImage(v: Variant) {
		try {
			res.set(apply(await api.del<View>(`${base}/${v}`)));
		} catch (err) {
			toast.error(err);
		}
	}

	async function removeOverride() {
		const ok = await confirmAction({
			title: `Remove ${clientName}'s branding?`,
			message: `Its people see the instance's branding again. Its own images are deleted.`,
			confirmLabel: 'Remove',
			danger: true
		});
		if (!ok) return;
		try {
			res.set(apply(await api.del<View>(base)));
			toast.success('Branding override removed.');
		} catch (err) {
			toast.error(err);
		}
	}

	const images: { v: Variant; label: string; hint: string; dark: boolean }[] = [
		{ v: 'logo_light', label: 'Logo for light backgrounds', hint: 'The sign-in pages in the light theme, PDF headers. PNG or JPEG, up to 512 KiB.', dark: false },
		{ v: 'logo_dark', label: 'Logo for dark backgrounds', hint: 'The navigation rail and portal header (both always dark), the dark theme. PNG or JPEG, up to 512 KiB.', dark: true },
		{ v: 'icon', label: 'Square icon', hint: 'Browser tab, collapsed rail, Windows “Apps & features”. A square PNG, 64 to 1024 pixels.', dark: false }
	];

	// The preview uses the saved palette for the theme in use.
	const theme = $derived(typeof document !== 'undefined' && document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
	function previewStyle(b: Branding | undefined): string {
		const p = b?.theme?.[theme];
		if (!p) return '';
		return `--accent:${p.accent};--on-accent:${p.on_accent};--cta:${p.cta};--cta-hover:${p.cta_hover};--on-cta:${p.on_cta};--nav-indicator:${p.nav_indicator};--accent-soft:${p.accent_soft};--accent-ink:${p.accent_ink}`;
	}
</script>

<Async {res}>
	{#snippet children(view: View)}
		{@const r = view.resolved}
		{@const name = form.product_name.trim() || r.name}
		<div class="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
			<form class="min-w-0 space-y-5" onsubmit={save}>
				{#if clientId}
					<p class="text-muted text-sm">
						What {clientName}'s people see: the portal after they sign in, emails to its contacts, PDFs for it, and the prompts and installers on its devices. Empty fields use the instance's branding (Settings → Branding).
					</p>
				{/if}
				<section class="card space-y-4 p-5">
					<h2 class="font-semibold">Name and colour</h2>
					<Field label="Product name" id="{uid}-name" hint="Replaces “RMM” in the console, the portal, installers and the Windows service name. The program, service id and install paths stay rmm-agent.">
						<Input id="{uid}-name" maxlength={60} placeholder={placeholder('product_name', company.name ? `${company.name} RMM` : 'RMM')} bind:value={form.product_name} />
					</Field>
					<Field label="Accent colour" id="{uid}-accent" hint="#rrggbb. Buttons use it with white or dark text, whichever reads at 4.5:1; links use a shade of it that reads on each theme. Mid-tones that neither text colour can reach 4.5:1 on are refused.">
						<div class="flex items-center gap-2">
							<input
								type="color"
								aria-label="Pick the accent colour"
								class="border-border size-9 shrink-0 cursor-pointer rounded-md border bg-transparent p-0.5"
								value={/^#[0-9a-fA-F]{6}$/.test(form.accent) ? form.accent : '#14b8a6'}
								oninput={(e) => (form.accent = e.currentTarget.value)}
							/>
							<Input id="{uid}-accent" class="max-w-36 font-mono" maxlength={7} placeholder={placeholder('accent', '#14b8a6')} bind:value={form.accent} />
						</div>
					</Field>
				</section>

				<section class="card space-y-4 p-5">
					<h2 class="font-semibold">Images</h2>
					{#each images as img (img.v)}
						{@const url = view[img.v]}
						<div class="flex flex-wrap items-center gap-4">
							<div class={['flex h-14 w-32 shrink-0 items-center justify-center rounded-md border p-2', img.dark ? 'bg-nav border-nav-border' : 'bg-raised border-border']}>
								{#if url}<img src={url} alt="" class="max-h-full max-w-full object-contain" />{:else}<span class={['text-xs', img.dark ? 'text-nav-muted' : 'text-muted']}>None</span>{/if}
							</div>
							<div class="min-w-0 flex-1">
								<div class="text-sm font-medium">{img.label}</div>
								<p class="text-muted text-xs">{img.hint}</p>
							</div>
							<div class="flex gap-2">
								<label class="sr-only" for="{uid}-{img.v}">Upload {img.label.toLowerCase()}</label>
								<input id="{uid}-{img.v}" type="file" accept="image/png,image/jpeg" class="sr-only" onchange={(e) => upload(img.v, e)} />
								<Button size="sm" icon={ImageUp} loading={uploading === img.v} onclick={() => document.getElementById(`${uid}-${img.v}`)?.click()}>Upload</Button>
								{#if url}<Button size="sm" variant="ghost" icon={Trash2} aria-label="Remove {img.label.toLowerCase()}" onclick={() => removeImage(img.v)}>Remove</Button>{/if}
							</div>
						</div>
					{/each}
				</section>

				<section class="card space-y-4 p-5">
					<h2 class="font-semibold">Support contact</h2>
					<p class="text-muted -mt-2 text-xs">Shown at the foot of the portal.</p>
					<div class="grid gap-4 sm:grid-cols-2">
						<Field label="Email" id="{uid}-email"><Input id="{uid}-email" type="email" maxlength={254} placeholder={placeholder('support_email', 'help@example.com')} bind:value={form.support_email} /></Field>
						<Field label="Phone" id="{uid}-phone"><Input id="{uid}-phone" type="tel" maxlength={40} placeholder={placeholder('support_phone', '+1 555 0100')} bind:value={form.support_phone} /></Field>
						<Field label="Web page" id="{uid}-url"><Input id="{uid}-url" type="url" maxlength={300} placeholder={placeholder('support_url', 'https://example.com/support')} bind:value={form.support_url} /></Field>
						<Field label="Hours" id="{uid}-hours"><Input id="{uid}-hours" maxlength={100} placeholder={placeholder('support_hours', 'Mon–Fri 8:00–18:00')} bind:value={form.support_hours} /></Field>
					</div>
				</section>

				<section class="card space-y-4 p-5">
					<h2 class="font-semibold">Email</h2>
					<Field label="Sender name" id="{uid}-from" hint="The name on mail the server sends{clientId ? ' to this client' : ''}. The address is the mail server's (Notifications).">
						<Input id="{uid}-from" maxlength={80} placeholder={placeholder('email_from_name', company.name || 'Support')} bind:value={form.email_from_name} />
					</Field>
					<Field label="Footer" id="{uid}-footer" hint="Plain text under every message, e.g. your address and phone number.">
						<Textarea id="{uid}-footer" rows={3} maxlength={1000} placeholder={placeholder('email_footer', '')} bind:value={form.email_footer} />
					</Field>
				</section>

				{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
				<div class="flex flex-wrap items-center justify-end gap-3">
					{#if clientId && view.exists}<Button variant="danger-ghost" class="mr-auto" onclick={removeOverride}>Remove override</Button>{/if}
					{#if dirty}<span class="text-warning text-xs">Unsaved changes</span>{/if}
					<Button variant="primary" type="submit" loading={busy} disabled={!dirty}>Save</Button>
				</div>
				<p class="text-muted text-xs">
					The console and portal always link to this server's licence and source code (AGPL-3.0, from <code>RMM_SOURCE_URL</code>), whatever the branding.
				</p>
			</form>

			<aside class="min-w-0 space-y-4" aria-label="Preview" style={previewStyle(r)}>
				<h2 class="text-muted text-xs font-semibold tracking-[0.08em] uppercase">Preview</h2>
				<div class="bg-nav border-nav-border rounded-panel overflow-hidden border">
					<div class="border-nav-border flex h-14 items-center gap-3 border-b px-4">
						{#if r.logo_dark ?? r.logo_light}
							<img src={r.logo_dark ?? r.logo_light} alt="" class="h-8 max-w-[11rem] object-contain object-left" />
						{:else}
							<img src={r.icon ?? favicon} alt="" class="size-7" />
							<span class="font-display truncate font-bold text-white">{name}</span>
						{/if}
					</div>
					<div class="space-y-0.5 p-3 text-sm">
						<div class="bg-nav-active before:bg-nav-indicator relative rounded-md px-3 py-2 font-medium text-white before:absolute before:top-1.5 before:bottom-1.5 before:-left-3 before:w-[3px] before:rounded-r-full">Devices</div>
						<div class="text-nav-muted px-3 py-2">Alerts</div>
					</div>
				</div>
				<div class="card space-y-3 p-5">
					{#if r.logo_light}<img src={r.logo_light} alt="" class="h-8 max-w-[12rem] object-contain object-left" />{/if}
					<div class="text-lg font-semibold">Sign in</div>
					<p class="text-muted text-sm">Use your {name} account. <a class="link" href="#preview" onclick={(e) => e.preventDefault()}>Forgot?</a></p>
					<span class="bg-cta text-on-cta inline-flex h-9 w-full items-center justify-center rounded-md text-sm font-medium">Sign in</span>
				</div>
				<div class="card space-y-2 p-5 text-sm">
					<div class="text-muted text-xs">From: <span class="text-fg font-medium">{form.email_from_name.trim() || (clientId ? inherited.data?.email_from_name : null) || company.name || 'Support'}</span></div>
					<p>Thanks, we've received your request and opened ticket T-1042.</p>
					{#if form.email_footer.trim() || (clientId && inherited.data?.email_footer)}
						<pre class="text-muted border-border border-t pt-2 font-sans text-xs whitespace-pre-wrap">-- {'\n'}{form.email_footer.trim() || inherited.data?.email_footer}</pre>
					{/if}
				</div>
				<SupportCard
					support={{
						email: form.support_email.trim() || r.support.email,
						phone: form.support_phone.trim() || r.support.phone,
						url: form.support_url.trim() || r.support.url,
						hours: form.support_hours.trim() || r.support.hours
					}}
				/>
				<p class="text-muted text-xs">The contact card is shown in the portal and in the tray app on devices, with {name} as its title.</p>
			</aside>
		</div>
	{/snippet}
</Async>
