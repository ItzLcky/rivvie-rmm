<script lang="ts">
	import { Info, OctagonAlert, TriangleAlert } from '@lucide/svelte';
	import { cx } from '#lib/format.js';
	import { fence, type CalloutTone } from '#lib/docs/markdown.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Insert block → Callout: pick the kind, write (or keep the selected) text. */
	let { text = '', oninsert, onclose }: { text?: string; oninsert: (md: string) => void; onclose: () => void } = $props();
	let tone = $state<CalloutTone>('info');
	// svelte-ignore state_referenced_locally
	let body = $state(text);
	const tones = [
		{ value: 'info', label: 'Note', hint: 'Background, a tip', icon: Info, cls: 'doc-callout-info' },
		{ value: 'warning', label: 'Warning', hint: 'Check before you act', icon: TriangleAlert, cls: 'doc-callout-warning' },
		{ value: 'danger', label: 'Danger', hint: 'Can break things', icon: OctagonAlert, cls: 'doc-callout-danger' }
	] as const;
	function submit(e: SubmitEvent) {
		e.preventDefault();
		oninsert(fence('callout', body.trim() || 'Text', tone));
	}
</script>

<Modal title="Insert a callout" {onclose} size="md">
	<form id="callout-form" class="space-y-4" onsubmit={submit}>
		<fieldset>
			<legend class="label">Kind</legend>
			<div class="grid gap-2 sm:grid-cols-3">
				{#each tones as t (t.value)}
					<label class={cx('doc-callout flex cursor-pointer items-start gap-2 !p-2.5 text-sm has-[:checked]:ring-2 has-[:checked]:ring-[var(--accent)] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-[var(--focus)]', t.cls)}>
						<input type="radio" name="callout-tone" value={t.value} bind:group={tone} class="sr-only" />
						<t.icon class="doc-callout-icon !mt-0.5" aria-hidden="true" />
						<span><span class="block font-medium">{t.label}</span><span class="text-muted text-xs">{t.hint}</span></span>
					</label>
				{/each}
			</div>
		</fieldset>
		<Field label="Text" id="callout-text" hint="Markdown works here: **bold**, lists, links.">
			<!-- svelte-ignore a11y_autofocus -->
			<Textarea id="callout-text" rows={4} bind:value={body} autofocus />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="callout-form">Insert</Button>
	{/snippet}
</Modal>
