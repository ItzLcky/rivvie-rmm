<script lang="ts">
	import { onMount } from 'svelte';
	import type { EditorView } from '@codemirror/view';
	import type { Compartment } from '@codemirror/state';
	import type { Interpreter } from '#lib/types.js';

	/**
	 * CodeMirror 6, loaded on first use so it stays out of the main bundle. Highlighting follows
	 * the interpreter; colours come from the theme's syntax tokens. A plain textarea shows
	 * until it loads (and stays, if loading fails).
	 */
	let {
		value = $bindable(''),
		interpreter,
		id,
		label = 'Script',
		minHeight = '16rem',
		readonly = false
	}: { value?: string; interpreter: Interpreter; id?: string; label?: string; minHeight?: string; readonly?: boolean } = $props();

	let host: HTMLDivElement;
	let view: EditorView | undefined;
	let lang: Compartment | undefined;
	let ready = $state(false);
	let languageFor: ((i: Interpreter) => Promise<unknown>) | undefined;

	onMount(() => {
		let destroyed = false;
		(async () => {
			const [{ EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection, placeholder }, { EditorState, Compartment }, cmd, language, { tags: t }] =
				await Promise.all([
					import('@codemirror/view'),
					import('@codemirror/state'),
					import('@codemirror/commands'),
					import('@codemirror/language'),
					import('@lezer/highlight')
				]);
			if (destroyed) return;
			const { StreamLanguage, HighlightStyle, syntaxHighlighting, indentOnInput, bracketMatching } = language;
			languageFor = async (i: Interpreter) => {
				if (i === 'python') return (await import('@codemirror/lang-python')).python();
				if (i === 'powershell') return StreamLanguage.define((await import('@codemirror/legacy-modes/mode/powershell')).powerShell);
				if (i === 'bash' || i === 'sh') return StreamLanguage.define((await import('@codemirror/legacy-modes/mode/shell')).shell);
				return [];
			};
			const style = HighlightStyle.define([
				{ tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.definitionKeyword], color: 'var(--syntax-keyword)' },
				{ tag: [t.string, t.special(t.string)], color: 'var(--syntax-string)' },
				{ tag: [t.comment, t.lineComment, t.blockComment], color: 'var(--syntax-comment)', fontStyle: 'italic' },
				{ tag: [t.number, t.bool, t.null, t.atom], color: 'var(--syntax-number)' },
				{ tag: [t.variableName, t.special(t.variableName)], color: 'var(--syntax-variable)' },
				{ tag: [t.function(t.variableName), t.standard(t.variableName)], color: 'var(--syntax-function)' },
				{ tag: [t.operator, t.punctuation], color: 'var(--muted)' }
			]);
			const theme = EditorView.theme({
				'&': { backgroundColor: 'var(--raised)', color: 'var(--fg)', fontSize: '12.5px', minHeight },
				'&.cm-focused': { outline: 'none' },
				'.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.55', minHeight },
				'.cm-content': { caretColor: 'var(--accent)', padding: '8px 0' },
				'.cm-gutters': { backgroundColor: 'var(--sunken)', color: 'var(--subtle)', border: 'none', borderRight: '1px solid var(--border)' },
				'.cm-activeLine': { backgroundColor: 'color-mix(in srgb, var(--hover) 60%, transparent)' },
				'.cm-activeLineGutter': { backgroundColor: 'var(--hover)', color: 'var(--muted)' },
				'&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'color-mix(in srgb, var(--accent) 25%, transparent) !important' },
				'.cm-cursor': { borderLeftColor: 'var(--accent)' },
				'.cm-placeholder': { color: 'var(--subtle)' }
			});
			lang = new Compartment();
			view = new EditorView({
				parent: host,
				state: EditorState.create({
					doc: value,
					extensions: [
						lineNumbers(),
						highlightActiveLine(),
						drawSelection(),
						indentOnInput(),
						bracketMatching(),
						cmd.history(),
						keymap.of([...cmd.defaultKeymap, ...cmd.historyKeymap, cmd.indentWithTab]),
						syntaxHighlighting(style),
						theme,
						placeholder(interpreter === 'powershell' ? 'Get-Service | Where-Object Status -eq Running' : 'uptime && df -h'),
						EditorState.readOnly.of(readonly),
						EditorView.contentAttributes.of({ 'aria-label': label, ...(id ? { id } : {}) }),
						EditorView.updateListener.of((u) => {
							if (u.docChanged) value = u.state.doc.toString();
						}),
						lang.of((await languageFor(interpreter)) as never)
					]
				})
			});
			ready = true;
		})().catch((e) => console.error('code editor failed to load', e));
		return () => {
			destroyed = true;
			view?.destroy();
		};
	});

	// Interpreter changed: swap the language.
	$effect(() => {
		const i = interpreter;
		if (!ready || !languageFor) return;
		languageFor(i).then((ext) => view?.dispatch({ effects: lang!.reconfigure(ext as never) }));
	});
	// Value replaced from outside (e.g. a saved script was picked).
	$effect(() => {
		const v = value;
		if (view && v !== view.state.doc.toString()) view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } });
	});
</script>

<div class="border-border-strong focus-within:border-accent focus-within:ring-accent/25 overflow-hidden rounded-md border focus-within:ring-3">
	<div bind:this={host} class:hidden={!ready}></div>
	{#if !ready}
		<textarea {id} bind:value aria-label={label} {readonly} spellcheck="false" class="bg-raised block w-full resize-y p-2 font-mono text-xs outline-none" style="min-height: {minHeight}"></textarea>
	{/if}
</div>
