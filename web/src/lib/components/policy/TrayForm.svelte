<script lang="ts" module>
	import type { Config } from '#lib/policy/types.js';

	type Link = { label: string; url: string };
	type Draft = { enabled: boolean; requestHelp: boolean; card: boolean; screenshot: boolean; links: Link[] };
	const fromConfig = (c: Config): Draft => ({
		enabled: c.enabled !== false,
		requestHelp: c.request_help !== false,
		card: c.contact_card !== false,
		screenshot: c.screenshot_default !== false,
		links: Array.isArray(c.links) ? (c.links as Link[]).map((l) => ({ label: String(l.label ?? ''), url: String(l.url ?? '') })) : []
	});
	const toConfig = (d: Draft): Config => ({
		enabled: d.enabled,
		request_help: d.requestHelp,
		contact_card: d.card,
		screenshot_default: d.screenshot,
		links: d.links.map((l) => ({ label: l.label.trim(), url: l.url.trim() }))
	});
	export const normalize = (c: Config) => toConfig(fromConfig(c));
	export const MAX_LINKS = 10;
	export const linkError = (l: Link): string | null => {
		if (!l.label.trim()) return 'Give the link a label.';
		if (l.label.trim().length > 60) return 'Labels are limited to 60 characters.';
		if (!/^https?:\/\/[^\s"]+\.[^\s"]+/.test(l.url.trim())) return 'Use an http:// or https:// address.';
		return null;
	};
</script>

<script lang="ts">
	import { untrack } from 'svelte';
	import { Plus, Trash2 } from '@lucide/svelte';
	import Button from '#lib/ui/Button.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import PField from './PField.svelte';

	/** The tray app on devices: what the person at the machine can do and see. */
	let { config, onchange, disabled = false }: { config: Config; onchange: (config: Config, valid: boolean) => void; disabled?: boolean } = $props();

	let d = $state(fromConfig(untrack(() => config)));
	const valid = $derived(d.links.length <= MAX_LINKS && d.links.every((l) => !linkError(l)));
	$effect(() => {
		const c = toConfig(d);
		const ok = valid;
		untrack(() => onchange(c, ok));
	});
</script>

<fieldset class="card max-w-3xl space-y-5 p-4" {disabled}>
	<legend class="sr-only">Tray app policy</legend>
	<PField path="enabled" name="Tray app" hint="Windows shows an icon in the notification area for whoever signs in; Linux desktops get a Help launcher in the applications menu. Off: no icon, and requests from the device are refused.">
		<Switch bind:checked={d.enabled} {disabled}>Show the tray app on devices</Switch>
	</PField>
	<PField path="request_help" name="Request help" hint="Opens a ticket for the device's client, linked to the device, with what the device knows (OS, uptime, addresses, open alerts) as an internal note. Five requests an hour per user, twenty a day per device.">
		<Switch bind:checked={d.requestHelp} disabled={disabled || !d.enabled}>Let people request help</Switch>
	</PField>
	<PField path="screenshot_default" name="Screenshot" hint="The picture is taken before the form opens. People can untick it; nothing is captured on Wayland desktops.">
		<Switch bind:checked={d.screenshot} disabled={disabled || !d.enabled || !d.requestHelp}>Attach a screenshot unless the person unticks it</Switch>
	</PField>
	<PField path="contact_card" name="Contact card" hint="The support phone, email, web address and hours from Settings → Branding (the client's own, where it has one).">
		<Switch bind:checked={d.card} disabled={disabled || !d.enabled}>Show the contact card</Switch>
	</PField>
	<PField path="links" name="Links" hint="Extra menu entries that open in the browser, such as a status page or a knowledge base. Up to {MAX_LINKS}.">
		<div class="space-y-2">
			{#each d.links as link, i (i)}
				{@const err = linkError(link)}
				<div class="flex flex-wrap items-start gap-2">
					<Input class="min-w-40 flex-1" aria-label="Link {i + 1} label" placeholder="Label" maxlength={60} bind:value={link.label} {disabled} invalid={!!err && !!link.label} />
					<Input class="min-w-56 flex-[2]" aria-label="Link {i + 1} address" placeholder="https://" bind:value={link.url} {disabled} invalid={!!err && !!link.url} inputmode="url" />
					<IconButton icon={Trash2} label="Remove link {i + 1}" onclick={() => d.links.splice(i, 1)} {disabled} />
					{#if err && (link.label || link.url)}<p class="text-danger w-full text-xs">{err}</p>{/if}
				</div>
			{/each}
			{#if d.links.length < MAX_LINKS}
				<Button size="sm" icon={Plus} onclick={() => d.links.push({ label: '', url: '' })} {disabled}>Add a link</Button>
			{/if}
		</div>
	</PField>
	<p class="hint">The product name and icon come from Settings → Branding.</p>
</fieldset>
