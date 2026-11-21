<script lang="ts">
	import { onMount } from 'svelte';
	import type { EditorView } from '@codemirror/view';

	/**
	 * The Markdown source editor: CodeMirror 6 with Markdown highlighting, loaded on first use
	 * like CodeEditor (a textarea shows until then, and stays if loading fails). The toolbar
	 * edits through the exported functions, which work on either.
	 */
	let {
		value = $bindable(''),
		id,
		label = 'Page text',
		onsave
	}: { value?: string; id?: string; label?: string; /** Ctrl/Cmd+S. */ onsave?: () => void } = $props();

	let host: HTMLDivElement;
	let area = $state<HTMLTextAreaElement>();
	let view: EditorView | undefined;
	let ready = $state(false);

	/** The selection, as offsets into the text. */
	function selection(): { from: number; to: number } {
		if (view) {
			const r = view.state.selection.main;
			return { from: r.from, to: r.to };
		}
		return { from: area?.selectionStart ?? value.length, to: area?.selectionEnd ?? value.length };
	}
	/** Replaces [from, to) with `insert` and selects [selFrom, selTo) of the result. */
	function apply(from: number, to: number, insert: string, selFrom: number, selTo = selFrom) {
		if (view) {
			view.dispatch({ changes: { from, to, insert }, selection: { anchor: selFrom, head: selTo }, scrollIntoView: true, userEvent: 'input' });
			view.focus();
			return;
		}
		value = value.slice(0, from) + insert + value.slice(to);
		requestAnimationFrame(() => {
			area?.focus();
			area?.setSelectionRange(selFrom, selTo);
		});
	}
	const text = () => (view ? view.state.doc.toString() : value);

	/** Wraps the selection (or a placeholder word) in `before`/`after`; again to unwrap. */
	export function wrap(before: string, after = before, placeholder = 'text') {
		const { from, to } = selection();
		const t = text();
		if (t.slice(from - before.length, from) === before && t.slice(to, to + after.length) === after) {
			apply(from - before.length, to + after.length, t.slice(from, to), from - before.length, to - before.length);
			return;
		}
		const inner = t.slice(from, to) || placeholder;
		apply(from, to, before + inner + after, from + before.length, from + before.length + inner.length);
	}

	/** Toggles `prefix` at the start of every selected line (`## `, `- `, `1. `, `- [ ] `). */
	export function prefixLines(prefix: string | ((i: number) => string), strip: RegExp) {
		const { from, to } = selection();
		const t = text();
		const start = t.lastIndexOf('\n', from - 1) + 1;
		const endNl = t.indexOf('\n', to);
		const end = endNl < 0 ? t.length : endNl;
		const lines = t.slice(start, end).split('\n');
		const all = lines.every((l) => strip.test(l) || !l.trim());
		const out = lines.map((l, i) => (all ? l.replace(strip, '') : l.replace(strip, '').replace(/^/, typeof prefix === 'string' ? prefix : prefix(i)))).join('\n');
		apply(start, end, out, start + out.length);
	}

	/** Inserts a block on lines of its own at the cursor (replacing the selection). */
	export function insertBlock(block: string, select?: string) {
		const { from, to } = selection();
		const t = text();
		const lead = from === 0 ? '' : t.slice(0, from).endsWith('\n\n') ? '' : t.slice(0, from).endsWith('\n') ? '\n' : '\n\n';
		const rest = t.slice(to);
		const trail = rest.startsWith('\n\n') ? '' : rest.startsWith('\n') ? '\n' : rest ? '\n\n' : '\n';
		const insert = lead + block + trail;
		const at = select ? block.indexOf(select) : -1;
		const selFrom = at >= 0 ? from + lead.length + at : from + lead.length + block.length;
		apply(from, to, insert, selFrom, at >= 0 ? selFrom + select!.length : selFrom);
	}

	/** Inserts text at the cursor. */
	export function insertText(s: string, selectFrom?: number, selectTo?: number) {
		const { from, to } = selection();
		apply(from, to, s, from + (selectFrom ?? s.length), from + (selectTo ?? selectFrom ?? s.length));
	}

	export function focus() {
		if (view) view.focus();
		else area?.focus();
	}

	/** The selected text (for a link's label, a callout's body). */
	export function selected(): string {
		const { from, to } = selection();
		return text().slice(from, to);
	}

	// Formatting shortcuts, shared by CodeMirror's keymap and the fallback textarea.
	const shortcuts: Record<string, () => void> = {
		b: () => wrap('**', '**', 'bold text'),
		i: () => wrap('_', '_', 'italic text'),
		k: () => wrap('[', '](https://)', 'link text'),
		s: () => onsave?.()
	};
	function areaKey(e: KeyboardEvent) {
		const f = (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey ? shortcuts[e.key.toLowerCase()] : undefined;
		if (f) {
			e.preventDefault();
			f();
		}
	}

	onMount(() => {
		let destroyed = false;
		(async () => {
			const [{ EditorView, keymap, drawSelection, placeholder, highlightActiveLine }, { EditorState }, cmd, language, { tags: t }, { markdown, markdownLanguage }] =
				await Promise.all([
					import('@codemirror/view'),
					import('@codemirror/state'),
					import('@codemirror/commands'),
					import('@codemirror/language'),
					import('@lezer/highlight'),
					import('@codemirror/lang-markdown')
				]);
			if (destroyed) return;
			const { HighlightStyle, syntaxHighlighting } = language;
			const style = HighlightStyle.define([
				{ tag: t.heading1, fontWeight: '700', fontSize: '1.15em', color: 'var(--fg)' },
				{ tag: [t.heading2, t.heading3], fontWeight: '700', color: 'var(--fg)' },
				{ tag: [t.heading4, t.heading5, t.heading6], fontWeight: '600', color: 'var(--fg)' },
				{ tag: t.strong, fontWeight: '700' },
				{ tag: t.emphasis, fontStyle: 'italic' },
				{ tag: t.strikethrough, textDecoration: 'line-through' },
				{ tag: [t.link, t.url], color: 'var(--syntax-variable)' },
				{ tag: t.monospace, color: 'var(--syntax-string)' },
				{ tag: [t.processingInstruction, t.meta, t.contentSeparator, t.list, t.quote], color: 'var(--syntax-keyword)' },
				{ tag: [t.labelName, t.string], color: 'var(--syntax-function)' },
				{ tag: t.comment, color: 'var(--syntax-comment)' }
			]);
			const theme = EditorView.theme({
				'&': { backgroundColor: 'var(--raised)', color: 'var(--fg)', fontSize: '13px', height: '100%' },
				'&.cm-focused': { outline: 'none' },
				'.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.65', overflow: 'auto' },
				'.cm-content': { caretColor: 'var(--accent)', padding: '12px 0', maxWidth: '100%' },
				'.cm-line': { padding: '0 16px' },
				'.cm-activeLine': { backgroundColor: 'color-mix(in srgb, var(--hover) 45%, transparent)' },
				'&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'color-mix(in srgb, var(--accent) 25%, transparent) !important' },
				'.cm-cursor': { borderLeftColor: 'var(--accent)' },
				'.cm-placeholder': { color: 'var(--subtle)' }
			});
			const mod = (k: string) => ({ key: `Mod-${k}`, run: () => (shortcuts[k](), true), preventDefault: true });
			view = new EditorView({
				parent: host,
				state: EditorState.create({
					doc: value,
					extensions: [
						highlightActiveLine(),
						drawSelection(),
						EditorView.lineWrapping,
						cmd.history(),
						keymap.of([mod('b'), mod('i'), mod('k'), mod('s'), ...cmd.defaultKeymap, ...cmd.historyKeymap, cmd.indentWithTab]),
						markdown({ base: markdownLanguage }),
						syntaxHighlighting(style),
						theme,
						placeholder('Write in Markdown. Insert block adds fields, credentials, callouts and devices.'),
						EditorView.contentAttributes.of({ 'aria-label': label, 'aria-multiline': 'true', tabindex: '0', ...(id ? { id } : {}) }),
						EditorView.updateListener.of((u) => {
							if (u.docChanged) value = u.state.doc.toString();
						})
					]
				})
			});
			ready = true;
		})().catch((e) => console.error('markdown editor failed to load', e));
		return () => {
			destroyed = true;
			view?.destroy();
		};
	});

	// Text replaced from outside (a credential slot filled from the preview): apply the smallest
	// change, so the cursor and undo history survive.
	$effect(() => {
		const v = value;
		if (!view) return;
		const cur = view.state.doc.toString();
		if (v === cur) return;
		let a = 0;
		while (a < v.length && a < cur.length && v[a] === cur[a]) a++;
		let b = 0;
		while (b < v.length - a && b < cur.length - a && v[v.length - 1 - b] === cur[cur.length - 1 - b]) b++;
		view.dispatch({ changes: { from: a, to: cur.length - b, insert: v.slice(a, v.length - b) } });
	});
</script>

<div class="h-full min-h-0">
	<div bind:this={host} class="h-full" class:hidden={!ready}></div>
	{#if !ready}
		<textarea
			bind:this={area}
			{id}
			bind:value
			aria-label={label}
			spellcheck="true"
			onkeydown={areaKey}
			class="bg-raised block h-full min-h-[20rem] w-full resize-none px-4 py-3 font-mono text-[13px] leading-relaxed outline-none"
		></textarea>
	{/if}
</div>
