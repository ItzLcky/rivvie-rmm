<script lang="ts">
	import { goto } from '$app/navigation';
	import { ArrowLeft, Send } from '@lucide/svelte';
	import { portal } from '#lib/portal/api.js';
	import { formWith, ticketNumber, urgencies, type Urgency } from '#lib/portal/format.js';
	import FilePicker from '#lib/portal/FilePicker.svelte';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	let subject = $state('');
	let description = $state('');
	let urgency = $state<Urgency>('normal');
	let files = $state<File[]>([]);
	let busy = $state(false);
	let error = $state('');

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!subject.trim()) {
			error = 'Give the request a subject.';
			return;
		}
		busy = true;
		error = '';
		try {
			const r = await portal.form<{ id: string; number: number }>('/tickets', formWith({ subject: subject.trim(), description, urgency }, files));
			toast.success(`Request ${ticketNumber(r.number)} sent. We'll be in touch.`);
			await goto(`/portal/tickets/${r.id}`, { replace: true });
		} catch (e) {
			const m = e instanceof Error ? e.message : String(e);
			error = m.charAt(0).toUpperCase() + m.slice(1);
		} finally {
			busy = false;
		}
	}
</script>

<div class="mx-auto max-w-2xl space-y-6">
	<div>
		<a href="/portal" class="text-muted hover:text-fg inline-flex items-center gap-1 text-sm"><ArrowLeft class="size-4" aria-hidden="true" />All requests</a>
		<h1 class="mt-2 text-2xl font-semibold tracking-tight">New request</h1>
		<p class="text-muted mt-1 text-sm">Tell us what's going on. The more detail, the faster we can help.</p>
	</div>

	<form class="card space-y-5 p-4 sm:p-6" onsubmit={submit}>
		<Field label="Subject" id="subject" required hint="A short summary, like “Printer on the 2nd floor won't print”.">
			<Input id="subject" required maxlength={300} bind:value={subject} class="h-10" />
		</Field>
		<Field label="Description" id="description" hint="What happened, when it started, and anything you've already tried.">
			<Textarea id="description" rows={8} maxlength={100000} bind:value={description} />
		</Field>
		<Field label="How urgent is it?" id="urgency">
			<Select id="urgency" bind:value={urgency} options={urgencies} class="h-10 sm:max-w-xs" />
		</Field>
		<div>
			<span class="label" id="files-label">Attachments</span>
			<p class="hint mb-2 mt-0">Screenshots or documents that help explain the problem.</p>
			<FilePicker id="new-files" bind:files disabled={busy} />
		</div>
		{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
		<div class="border-border flex flex-wrap items-center justify-end gap-2 border-t pt-4">
			<Button variant="ghost" href="/portal">Cancel</Button>
			<Button variant="primary" type="submit" icon={Send} loading={busy}>Send request</Button>
		</div>
	</form>
</div>
