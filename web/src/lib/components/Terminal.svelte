<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import '@xterm/xterm/css/xterm.css';
	import { AArrowDown, AArrowUp, Maximize2, Minimize2, RotateCcw } from '@lucide/svelte';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { cx } from '#lib/format.js';
	import Button from '#lib/ui/Button.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';

	/** The browser terminal. Loaded only when its tab opens (xterm.js is large). */
	/** `ticketId`: opened from a ticket, which records the session on its timeline. */
	let { agentId, hostname, ticketId }: { agentId: string; hostname: string; ticketId?: string } = $props();

	let el: HTMLDivElement;
	let status = $state<'connecting' | 'open' | 'closed'>('connecting');
	let reason = $state('');
	let full = $state(false);
	let term: Terminal | undefined;
	let fit: FitAddon | undefined;
	let ws: WebSocket | undefined;
	let ro: ResizeObserver | undefined;
	const size = $derived(prefs.terminalFontSize ?? 13);

	function css(name: string) {
		return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
	}

	function connect() {
		term?.dispose();
		ws?.close();
		status = 'connecting';
		reason = '';

		term = new Terminal({
			cursorBlink: true,
			fontFamily: "'Geist Mono Variable', ui-monospace, Menlo, Consolas, monospace",
			fontSize: size,
			scrollback: 5000,
			theme: { background: css('--terminal-bg'), foreground: css('--terminal-fg'), cursor: css('--accent'), selectionBackground: '#3b4a63' }
		});
		fit = new FitAddon();
		term.loadAddon(fit);
		term.open(el);
		fit.fit();

		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		ws = new WebSocket(`${proto}://${location.host}/api/agents/${agentId}/shell?cols=${term.cols}&rows=${term.rows}${ticketId ? `&ticket_id=${ticketId}` : ''}`);
		ws.binaryType = 'arraybuffer';
		const enc = new TextEncoder();

		ws.onmessage = (e) => {
			if (typeof e.data === 'string') {
				const msg = JSON.parse(e.data);
				if (msg.type === 'opened') {
					status = 'open';
					term?.focus();
				} else if (msg.type === 'closed') {
					reason = msg.reason ?? '';
				}
			} else {
				term?.write(new Uint8Array(e.data));
			}
		};
		ws.onclose = () => {
			status = 'closed';
			term?.write(`\r\n\x1b[90m[session closed${reason ? `: ${reason}` : ''}]\x1b[0m\r\n`);
		};
		term.onData((d) => ws?.readyState === WebSocket.OPEN && ws.send(enc.encode(d)));
		term.onResize(({ cols, rows }) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ type: 'resize', cols, rows })));

		ro?.disconnect();
		ro = new ResizeObserver(() => fit?.fit());
		ro.observe(el);
	}

	function setSize(n: number) {
		const v = Math.min(22, Math.max(10, n));
		setPref('terminalFontSize', v);
		if (term) {
			term.options.fontSize = v;
			fit?.fit();
		}
	}

	onMount(connect);
	onDestroy(() => {
		ro?.disconnect();
		ws?.close();
		term?.dispose();
	});
</script>

<svelte:window onkeydown={(e) => full && e.key === 'Escape' && e.shiftKey && (full = false)} />

<div class={cx('card flex flex-col overflow-hidden', full ? 'fixed inset-2 z-40' : 'h-[calc(100dvh-14rem)] min-h-80')}>
	<div class="border-border flex items-center gap-2 border-b px-3 py-1.5 text-xs">
		<span class={cx('inline-flex items-center gap-1.5 font-medium', status === 'open' ? 'text-success' : status === 'connecting' ? 'text-warning' : 'text-muted')}>
			<span class={cx('size-2 rounded-full', status === 'open' ? 'bg-success' : status === 'connecting' ? 'bg-warning animate-pulse' : 'bg-subtle')}></span>
			{status === 'open' ? 'Connected' : status === 'connecting' ? 'Connecting…' : 'Disconnected'}
		</span>
		<span class="text-muted truncate font-mono">{hostname}</span>
		<div class="ml-auto flex items-center gap-0.5">
			<IconButton icon={AArrowDown} label="Smaller text" size="sm" onclick={() => setSize(size - 1)} />
			<span class="text-muted w-6 text-center tabular">{size}</span>
			<IconButton icon={AArrowUp} label="Larger text" size="sm" onclick={() => setSize(size + 1)} />
			<IconButton icon={full ? Minimize2 : Maximize2} label={full ? 'Exit full screen (Shift+Esc)' : 'Full screen'} size="sm" onclick={() => ((full = !full), setTimeout(() => fit?.fit(), 50))} />
		</div>
	</div>
	{#if status === 'closed'}
		<div class="border-border bg-warning-soft text-warning flex flex-wrap items-center gap-3 border-b px-3 py-2 text-sm" role="status">
			<span class="flex-1">The session ended{reason ? `: ${reason}` : ''}.</span>
			<Button size="sm" icon={RotateCcw} onclick={connect}>Reconnect</Button>
		</div>
	{/if}
	<div bind:this={el} class="min-h-0 flex-1 p-2" style="background: var(--terminal-bg)"></div>
</div>
