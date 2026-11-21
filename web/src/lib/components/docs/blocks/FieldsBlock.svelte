<script lang="ts">
	import { parseFields, renderInline, type FieldRow } from '#lib/docs/markdown.js';
	import type { BlockProps } from '#lib/docs/blocks.js';
	import CopyButton from '#lib/ui/CopyButton.svelte';

	/** `Label: value` rows as a definition grid; each value copies with one click. */
	let { seg }: BlockProps = $props();

	type Group = { kind: 'fields'; rows: { key: string; value: string }[] } | { kind: 'text'; text: string };
	const groups = $derived.by(() => {
		const out: Group[] = [];
		for (const r of parseFields(seg.body) as FieldRow[]) {
			if ('text' in r) out.push({ kind: 'text', text: r.text });
			else if (out.at(-1)?.kind === 'fields') (out.at(-1) as Extract<Group, { kind: 'fields' }>).rows.push(r);
			else out.push({ kind: 'fields', rows: [r] });
		}
		return out;
	});
</script>

<div class="doc-block doc-fields">
	{#each groups as g, i (i)}
		{#if g.kind === 'text'}
			<p class="doc-fields-note">{@html renderInline(g.text)}</p>
		{:else}
			<dl>
				{#each g.rows as r, j (j)}
					<div class="doc-field">
						<dt>{r.key}</dt>
						<dd>
							{#if r.value}
								<span class="doc-field-value">{@html renderInline(r.value)}</span>
								<span class="doc-field-copy"><CopyButton text={r.value} label="Copy {r.key}" /></span>
							{:else}
								<span class="text-subtle" aria-hidden="true">—</span><span class="sr-only">Not filled in</span>
							{/if}
						</dd>
					</div>
				{/each}
			</dl>
		{/if}
	{/each}
</div>
