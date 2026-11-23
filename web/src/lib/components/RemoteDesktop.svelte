<script lang="ts" module>
	export type Quality = 'low' | 'balanced' | 'high';
	export interface Monitor { name: string; x: number; y: number; width: number; height: number; primary: boolean }
	type MouseButton = 'left' | 'middle' | 'right' | 'back' | 'forward';
	type InputEvent =
		| { t: 'move'; x: number; y: number }
		| { t: 'button'; button: MouseButton; down: boolean; x: number; y: number }
		| { t: 'wheel'; dx: number; dy: number }
		| { t: 'key'; code: string; down: boolean }
		| { t: 'text'; text: string }
		| { t: 'ctrl_alt_del' };

	/** Longest text the agent types in one go (rmm_proto::desktop::TEXT_MAX). */
	const TEXT_MAX = 4096;
	const BUTTONS: MouseButton[] = ['left', 'middle', 'right', 'back', 'forward'];
	const NO_CURSOR = -2147483648;

	interface Rect { x: number; y: number; w: number; h: number; codec: number; data: Uint8Array }
	interface Frame { seq: number; screenW: number; screenH: number; width: number; height: number; cursor: { x: number; y: number } | null; rects: Rect[] }

	/** The binary frame layout of `/api/agents/{id}/desktop` (big-endian, see desktop_ws.rs). */
	function parse(buf: ArrayBuffer): Frame | null {
		const v = new DataView(buf);
		if (v.byteLength < 23 || v.getUint8(0) !== 1) return null;
		const cx = v.getInt32(13);
		const cy = v.getInt32(17);
		const f: Frame = {
			seq: v.getUint32(1), screenW: v.getUint16(5), screenH: v.getUint16(7), width: v.getUint16(9), height: v.getUint16(11),
			cursor: cx === NO_CURSOR || cy === NO_CURSOR ? null : { x: cx, y: cy }, rects: []
		};
		const n = v.getUint16(21);
		let o = 23;
		for (let i = 0; i < n && o + 13 <= v.byteLength; i++) {
			const len = v.getUint32(o + 9);
			if (o + 13 + len > v.byteLength) break;
			f.rects.push({ x: v.getUint16(o), y: v.getUint16(o + 2), w: v.getUint16(o + 4), h: v.getUint16(o + 6), codec: v.getUint8(o + 8), data: new Uint8Array(buf, o + 13, len) });
			o += 13 + len;
		}
		return f;
	}
</script>

<script lang="ts">
	import { onDestroy, onMount, tick } from 'svelte';
	import { Keyboard, Maximize2, Minimize2, Monitor as MonitorIcon, RotateCcw, Scan, ScanLine, Type, Unplug } from '@lucide/svelte';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { cx } from '#lib/format.js';
	import Button from '#lib/ui/Button.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** The remote desktop viewer. Loaded only when its tab opens. */
	/** `ticketId`: opened from a ticket, which records the session on its timeline. */
	let { agentId, hostname, ticketId }: { agentId: string; hostname: string; ticketId?: string } = $props();

	let container: HTMLDivElement;
	let canvas: HTMLCanvasElement;
	/** The focusable element over the canvas that takes the pointer and keyboard. */
	let surface: HTMLDivElement;
	let status = $state<'connecting' | 'waiting' | 'open' | 'closed'>('connecting');
	let reason = $state('');
	let full = $state(false);
	let actual = $state(false);
	let monitors = $state<Monitor[]>([]);
	let monitor = $state(0);
	/** Picture size (canvas pixels) and the remote screen size (input coordinates). */
	let frame = $state<{ w: number; h: number } | null>(null);
	let screen = { w: 0, h: 0 };
	let cursor = $state<{ x: number; y: number } | null>(null);
	let local = $state<{ x: number; y: number } | null>(null);
	let typing = $state<{ text: string } | null>(null);
	const quality = $derived<Quality>(prefs.desktopQuality ?? 'balanced');

	let ws: WebSocket | undefined;
	let ctx: CanvasRenderingContext2D | null = null;
	/** Bumped on every connect, so a previous session's queued frames are dropped. */
	let session = 0;
	let queue: Promise<void> = Promise.resolve();
	const keys = new Set<string>();
	const buttons = new Set<MouseButton>();
	let pendingMove: { x: number; y: number } | null = null;
	let raf = 0;
	const wheel = { x: 0, y: 0 };

	function send(msg: unknown) {
		if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
	}
	function input(...events: InputEvent[]) {
		if (pendingMove) {
			events.unshift({ t: 'move', ...pendingMove });
			pendingMove = null;
		}
		if (events.length && status === 'open') send({ type: 'input', events });
	}

	function connect() {
		ws?.close();
		session++;
		const mine = session;
		queue = Promise.resolve();
		status = 'connecting';
		reason = '';
		cursor = null;
		keys.clear();
		buttons.clear();

		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		const sock = new WebSocket(`${proto}://${location.host}/api/agents/${agentId}/desktop?quality=${quality}&monitor=${monitor}${ticketId ? `&ticket_id=${ticketId}` : ''}`);
		ws = sock;
		sock.binaryType = 'arraybuffer';
		sock.onmessage = (e) => {
			if (mine !== session) return;
			if (typeof e.data === 'string') {
				const msg = JSON.parse(e.data);
				if (msg.type === 'waiting') status = 'waiting';
				else if (msg.type === 'info') {
					monitors = msg.monitors ?? [];
					monitor = msg.monitor ?? 0;
					status = 'open';
				} else if (msg.type === 'closed') reason = msg.reason ?? '';
			} else {
				const buf = e.data as ArrayBuffer;
				queue = queue.then(() => draw(buf, mine));
			}
		};
		sock.onclose = () => {
			if (mine !== session) return;
			status = 'closed';
			releaseAll(false);
			if (document.fullscreenElement === container) document.exitFullscreen().catch(() => {});
		};
	}

	/** Decodes and paints one frame, then acknowledges it so the agent sends the next. */
	async function draw(buf: ArrayBuffer, mine: number) {
		const f = parse(buf);
		if (!f || mine !== session) return;
		try {
			const bitmaps = await Promise.all(f.rects.map((r) => (r.codec === 1 ? createImageBitmap(new Blob([r.data as BlobPart], { type: 'image/jpeg' })) : Promise.resolve(null))));
			if (mine !== session) return bitmaps.forEach((b) => b?.close());
			if (canvas.width !== f.width || canvas.height !== f.height) {
				canvas.width = f.width;
				canvas.height = f.height;
				ctx = null;
			}
			ctx ??= canvas.getContext('2d', { alpha: false });
			f.rects.forEach((r, i) => {
				const b = bitmaps[i];
				if (b) {
					ctx?.drawImage(b, r.x, r.y);
					b.close();
				}
			});
		} catch {
			/* a corrupt rect: skip it, the next full frame repairs the picture */
		}
		screen = { w: f.screenW, h: f.screenH };
		if (frame?.w !== f.width || frame?.h !== f.height) frame = { w: f.width, h: f.height };
		cursor = f.cursor;
		if (status !== 'open') status = 'open';
		send({ type: 'ack', seq: f.seq });
	}

	function settings() {
		send({ type: 'settings', monitor, quality });
	}
	function setQuality(q: Quality) {
		setPref('desktopQuality', q);
		settings();
	}

	function disconnect() {
		reason = '';
		releaseAll(true);
		ws?.close();
	}

	/** Lets go of every key and button we pressed (on blur or disconnect). */
	function releaseAll(notify: boolean) {
		const ev: InputEvent[] = [];
		for (const code of keys) ev.push({ t: 'key', code, down: false });
		const p = local ?? { x: 0, y: 0 };
		for (const button of buttons) ev.push({ t: 'button', button, down: false, ...p });
		keys.clear();
		buttons.clear();
		if (notify && ev.length) input(...ev);
	}

	/** Pointer position in the remote screen's pixels. */
	function toScreen(e: { clientX: number; clientY: number }) {
		const r = surface.getBoundingClientRect();
		const clamp = (v: number, max: number) => Math.min(max - 1, Math.max(0, Math.round(v)));
		return { x: clamp(((e.clientX - r.left) / r.width) * screen.w, screen.w), y: clamp(((e.clientY - r.top) / r.height) * screen.h, screen.h) };
	}

	function onpointermove(e: PointerEvent) {
		if (!screen.w) return;
		local = pendingMove = toScreen(e);
		if (!raf) raf = requestAnimationFrame(() => ((raf = 0), input()));
	}
	function onpointerdown(e: PointerEvent) {
		const button = BUTTONS[e.button];
		surface.focus();
		if (!button || !screen.w) return;
		e.preventDefault();
		surface.setPointerCapture(e.pointerId);
		buttons.add(button);
		pendingMove = null;
		input({ t: 'button', button, down: true, ...toScreen(e) });
	}
	function onpointerup(e: PointerEvent) {
		const button = BUTTONS[e.button];
		if (!button || !buttons.has(button)) return;
		e.preventDefault();
		buttons.delete(button);
		pendingMove = null;
		input({ t: 'button', button, down: false, ...toScreen(e) });
	}
	function onwheel(e: WheelEvent) {
		e.preventDefault();
		// Pixel deltas: about 100 px per notch. Lines: 3 per notch. Pages: one notch each.
		const unit = e.deltaMode === 1 ? 3 : e.deltaMode === 2 ? 1 : 100;
		wheel.x += e.deltaX / unit;
		wheel.y += e.deltaY / unit;
		const dx = Math.max(-100, Math.min(100, Math.trunc(wheel.x)));
		const dy = Math.max(-100, Math.min(100, Math.trunc(wheel.y)));
		wheel.x -= Math.trunc(wheel.x);
		wheel.y -= Math.trunc(wheel.y);
		if (dx || dy) input({ t: 'wheel', dx, dy });
	}
	function onkeydown(e: KeyboardEvent) {
		if (!e.code || e.isComposing) return;
		e.preventDefault();
		keys.add(e.code);
		input({ t: 'key', code: e.code, down: true });
	}
	function onkeyup(e: KeyboardEvent) {
		if (!e.code) return;
		e.preventDefault();
		if (!keys.delete(e.code)) return;
		input({ t: 'key', code: e.code, down: false });
	}

	async function toggleFull() {
		if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
		else await container.requestFullscreen?.().catch(() => {});
		surface.focus();
	}
	type KeyboardLock = { lock?: () => Promise<void>; unlock?: () => void };
	function onfullscreenchange() {
		full = document.fullscreenElement === container;
		const kb = (navigator as Navigator & { keyboard?: KeyboardLock }).keyboard;
		// In full screen, also capture Esc, Alt+Tab and the like where the browser allows it.
		if (full) kb?.lock?.().catch(() => {});
		else kb?.unlock?.();
	}

	async function openTyping() {
		typing = { text: '' };
		try {
			const t = await navigator.clipboard?.readText();
			if (t && typing && !typing.text) typing.text = t.slice(0, TEXT_MAX);
		} catch {
			/* no clipboard permission: start empty */
		}
	}
	async function sendText(e: SubmitEvent) {
		e.preventDefault();
		if (!typing?.text) return;
		input({ t: 'text', text: typing.text.slice(0, TEXT_MAX) });
		typing = null;
		await tick();
		surface.focus();
	}

	$effect(() => {
		// Non-passive so the page doesn't scroll while the wheel goes to the remote machine.
		surface.addEventListener('wheel', onwheel, { passive: false });
		return () => surface.removeEventListener('wheel', onwheel);
	});

	onMount(connect);
	onDestroy(() => {
		cancelAnimationFrame(raf);
		releaseAll(true);
		session++;
		ws?.close();
	});

	const statusLabel = $derived({ connecting: 'Connecting…', waiting: 'Waiting for approval', open: 'Connected', closed: 'Disconnected' }[status]);
	const tone = $derived(status === 'open' ? 'success' : status === 'closed' ? 'muted' : 'warning');
	// The remote pointer, when it isn't simply following ours.
	const marker = $derived(
		cursor && frame && screen.w && (!local || Math.hypot(cursor.x - local.x, cursor.y - local.y) > 24)
			? { left: (cursor.x / screen.w) * 100, top: (cursor.y / screen.h) * 100 }
			: null
	);
	const size = $derived(
		!frame ? 'width: 0; height: 0' : actual ? `width: ${frame.w}px; height: ${frame.h}px` : `width: min(100cqw, ${frame.w}px, calc(100cqh * ${frame.w / frame.h})); aspect-ratio: ${frame.w} / ${frame.h}`
	);
</script>

<svelte:document {onfullscreenchange} />

<div bind:this={container} class={cx('card flex flex-col overflow-hidden', !full && 'h-[calc(100dvh-16rem)] min-h-96')}>
	<div class="border-border flex flex-wrap items-center gap-x-2 gap-y-1 border-b px-3 py-1.5 text-xs">
		<span class={cx('inline-flex items-center gap-1.5 font-medium', tone === 'success' ? 'text-success' : tone === 'warning' ? 'text-warning' : 'text-muted')}>
			<span class={cx('size-2 rounded-full', tone === 'success' ? 'bg-success' : tone === 'warning' ? 'bg-warning animate-pulse' : 'bg-subtle')}></span>
			{statusLabel}
		</span>
		<span class="text-muted truncate font-mono">{hostname}</span>
		<div class="ml-auto flex flex-wrap items-center gap-1">
			{#if monitors.length > 1}
				<label class="inline-flex items-center gap-1">
					<MonitorIcon class="text-muted size-3.5" aria-hidden="true" />
					<span class="sr-only">Monitor</span>
					<select class="control h-7 w-auto py-0 text-xs" value={monitor} onchange={(e) => ((monitor = Number(e.currentTarget.value)), settings())} disabled={status !== 'open'}>
						{#each monitors as m, i (i)}<option value={i}>{m.name || `Display ${i + 1}`} ({m.width}×{m.height}){m.primary ? ' · primary' : ''}</option>{/each}
					</select>
				</label>
			{/if}
			<Segmented label="Picture quality" value={quality} onchange={setQuality} options={[{ value: 'low', label: 'Low' }, { value: 'balanced', label: 'Balanced' }, { value: 'high', label: 'High' }]} />
			<Button size="sm" variant="ghost" icon={Keyboard} disabled={status !== 'open'} onclick={() => (input({ t: 'ctrl_alt_del' }), surface.focus())} title="Send Ctrl+Alt+Del">Ctrl+Alt+Del</Button>
			<IconButton icon={Type} label="Type text" size="sm" disabled={status !== 'open'} onclick={openTyping} />
			<IconButton icon={actual ? Scan : ScanLine} label={actual ? 'Fit to window' : 'Actual size'} size="sm" active={actual} onclick={() => (actual = !actual)} />
			<IconButton icon={full ? Minimize2 : Maximize2} label={full ? 'Exit full screen' : 'Full screen'} size="sm" onclick={toggleFull} />
			<IconButton icon={Unplug} label="Disconnect" size="sm" variant="danger-ghost" disabled={status === 'closed'} onclick={disconnect} />
		</div>
	</div>
	{#if status === 'closed'}
		<div class="border-border bg-warning-soft text-warning flex flex-wrap items-center gap-3 border-b px-3 py-2 text-sm" role="status">
			<span class="flex-1">The session ended{reason ? `: ${reason}` : ''}.</span>
			<Button size="sm" icon={RotateCcw} onclick={connect}>Reconnect</Button>
		</div>
	{/if}
	<div class={cx('relative flex min-h-0 flex-1', actual ? 'overflow-auto' : 'overflow-hidden')} style="background: var(--terminal-bg); container-type: size">
		<!-- An ARIA application: it takes every key, like a remote desktop should. -->
		<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
		<div
			bind:this={surface}
			class="focus-visible:outline-accent relative m-auto shrink-0 cursor-default outline-2 -outline-offset-2 outline-transparent"
			style={size}
			tabindex="0"
			role="application"
			aria-roledescription="remote screen"
			aria-label="Screen of {hostname}. Click to control it; keys go to the remote machine."
			{onpointermove}
			{onpointerdown}
			{onpointerup}
			onpointerleave={() => (local = null)}
			oncontextmenu={(e) => e.preventDefault()}
			onauxclick={(e) => e.preventDefault()}
			{onkeydown}
			{onkeyup}
			onblur={() => releaseAll(true)}
		>
			<canvas bind:this={canvas} class="block size-full" aria-hidden="true"></canvas>
			{#if marker}
				<span class="border-accent pointer-events-none absolute size-3 -translate-1/2 rounded-full border-2 bg-white/60" style="left: {marker.left}%; top: {marker.top}%" aria-hidden="true"></span>
			{/if}
		</div>
		{#if status !== 'closed' && (!frame || status === 'waiting')}
			<div class="absolute inset-0 flex flex-col items-center justify-center gap-3 p-6 text-center text-sm" style="color: var(--terminal-fg)">
				{#if status === 'waiting'}
					<Spinner class="size-6" label="Waiting" />
					<p class="max-w-sm">Waiting for the person at {hostname} to allow the session…</p>
				{:else}
					<Spinner class="size-6" label={status === 'connecting' ? 'Connecting' : 'Starting'} />
					<p>{status === 'connecting' ? 'Connecting…' : 'Starting the session…'}</p>
				{/if}
			</div>
		{/if}
	</div>
</div>

{#if typing}
	<Modal title="Type text on {hostname}" description="Typed as keystrokes, whatever the remote keyboard layout. Up to {TEXT_MAX.toLocaleString('en-US')} characters." onclose={() => (typing = null)}>
		<form id="desktop-type" onsubmit={sendText}>
			<label class="label" for="desktop-text">Text</label>
			<!-- svelte-ignore a11y_autofocus -->
			<Textarea id="desktop-text" rows={6} maxlength={TEXT_MAX} class="font-mono text-[13px]" bind:value={typing.text} autofocus />
		</form>
		{#snippet footer()}
			<Button onclick={() => (typing = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="desktop-type" disabled={!typing?.text}>Type it</Button>
		{/snippet}
	</Modal>
{/if}
