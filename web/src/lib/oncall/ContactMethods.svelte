<script lang="ts">
	import { Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { ContactMethods } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** Account → How to reach me: the mobile number and what a page does, in order. */
	let phone = $state('');
	let rules = $state<ContactMethods['rules']>([]);
	let code = $state('');
	let codeSent = $state(false);
	let saved = $state('');
	function apply(c: ContactMethods) {
		phone = c.phone ?? '';
		rules = c.rules.map((r) => ({ ...r }));
		saved = JSON.stringify({ phone, rules });
		return c;
	}
	const res = resource(() => api.get<ContactMethods>('/account/contact-methods').then(apply));
	const dirty = $derived(JSON.stringify({ phone, rules }) !== saved);
	const methods = [
		{ value: 'push' as const, label: 'Push to my devices' },
		{ value: 'sms' as const, label: 'Text message' },
		{ value: 'email' as const, label: 'Email' }
	];
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const ok = await attempt(
			() => api.put<ContactMethods>('/account/contact-methods', { phone: phone.trim() || null, rules: rules.map((r) => ({ ...r, delay_minutes: Number(r.delay_minutes) })) }).then(apply),
			'Saved.'
		);
		if (ok) res.reload();
	}
	async function sendCode() {
		if (await attempt(() => api.post('/account/phone/verify', {}), 'Code sent.')) codeSent = true;
	}
	async function verify() {
		try {
			await api.post('/account/phone/verify', { code });
			toast.success('Number verified.');
			codeSent = false;
			code = '';
			res.reload();
		} catch (err) {
			toast.error(err);
		}
	}
</script>

<Async {res} compact>
	{#snippet children(c)}
		<form class="space-y-4" onsubmit={save}>
			<div class="flex flex-wrap items-end gap-3">
				<Field label="Mobile number" id="cm-phone" hint="International form, like +447700900123." class="min-w-56 flex-1">
					<Input id="cm-phone" type="tel" autocomplete="tel" bind:value={phone} />
				</Field>
				{#if c.phone && c.phone === phone}
					{#if c.phone_verified}<Badge tone="success">Verified</Badge>{:else if c.sms_available}<Button size="sm" onclick={sendCode}>Text me a code</Button>{:else}<Badge>Not verified</Badge>{/if}
				{/if}
			</div>
			{#if codeSent}
				<div class="flex flex-wrap items-end gap-3">
					<Field label="Code" id="cm-code"><Input id="cm-code" inputmode="numeric" autocomplete="one-time-code" maxlength={6} bind:value={code} /></Field>
					<Button onclick={verify} disabled={code.length !== 6}>Verify</Button>
				</div>
			{/if}
			<div>
				<div class="label">When I’m paged</div>
				{#if rules.length}
					<ul class="space-y-2">
						{#each rules as r, i (i)}
							<li class="flex flex-wrap items-center gap-2 text-sm">
								<Select aria-label="Method {i + 1}" class="w-52" bind:value={r.method} options={methods} />
								<span>after</span>
								<Input aria-label="Minutes after the page, rule {i + 1}" class="w-20" type="number" min="0" max="120" bind:value={r.delay_minutes} />
								<span>minutes</span>
								<IconButton icon={Trash2} size="sm" label="Remove rule {i + 1}" onclick={() => rules.splice(i, 1)} />
							</li>
						{/each}
					</ul>
				{:else}
					<p class="text-muted text-sm">Push and email at once{c.phone_verified ? ', and a text message' : ''}. Add rules to choose for yourself.</p>
				{/if}
				<Button size="sm" class="mt-2" icon={Plus} onclick={() => rules.push({ method: 'push', delay_minutes: rules.length ? 5 : 0 })}>Add a rule</Button>
				{#if rules.some((r) => r.method === 'sms') && !c.phone_verified}<p class="text-warning mt-2 text-xs">Text messages need a verified number.</p>{/if}
				{#if rules.some((r) => r.method === 'push') && !c.devices}<p class="text-warning mt-2 text-xs">Push needs notifications turned on on a device (below).</p>{/if}
			</div>
			<div class="flex justify-end"><Button variant="primary" type="submit" disabled={!dirty}>Save</Button></div>
		</form>
	{/snippet}
</Async>
