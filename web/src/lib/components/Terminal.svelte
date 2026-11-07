<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import '@xterm/xterm/css/xterm.css';

	let { agentId }: { agentId: string } = $props();

	let el: HTMLDivElement;
	let status = $state<'connecting' | 'open' | 'closed'>('connecting');
	let reason = $state('');
	let term: Terminal | undefined;
	let ws: WebSocket | undefined;
	let ro: ResizeObserver | undefined;

	function connect() {
		term?.dispose();
		ws?.close();
		status = 'connecting';
		reason = '';

		term = new Terminal({
			cursorBlink: true,
			fontFamily: 'JetBrains Mono, ui-monospace, Menlo, monospace',
			fontSize: 13,
			theme: { background: '#020617', foreground: '#e2e8f0', cursor: '#38bdf8', selectionBackground: '#334155' }
		});
		const fit = new FitAddon();
		term.loadAddon(fit);
		term.open(el);
		fit.fit();

		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		ws = new WebSocket(`${proto}://${location.host}/api/agents/${agentId}/shell?cols=${term.cols}&rows=${term.rows}`);
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
		ro = new ResizeObserver(() => fit.fit());
		ro.observe(el);
	}

	onMount(connect);
	onDestroy(() => {
		ro?.disconnect();
		ws?.close();
		term?.dispose();
	});
</script>

<div class="card overflow-hidden">
	<div class="flex items-center justify-between border-b border-slate-800 px-3 py-2 text-xs">
		<span class={status === 'open' ? 'text-emerald-400' : status === 'connecting' ? 'text-amber-400' : 'text-slate-500'}>
			● {status === 'open' ? 'Connected' : status === 'connecting' ? 'Connecting…' : 'Disconnected'}
		</span>
		{#if status === 'closed'}<button class="btn-ghost py-0.5 text-xs" onclick={connect}>Reconnect</button>{/if}
	</div>
	<div bind:this={el} class="h-[60vh] bg-[#020617] p-2"></div>
</div>
