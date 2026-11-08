<script lang="ts">
	import { AlertDialog } from 'bits-ui';
	import { TriangleAlert } from '@lucide/svelte';
	import { confirmState, settle } from '#lib/confirm.svelte.js';
	import Button from './Button.svelte';

	let typed = $state('');
	const c = $derived(confirmState.current);
	const ready = $derived(!c?.typeToConfirm || typed.trim() === c.typeToConfirm);
	$effect(() => {
		if (c) typed = '';
	});
	function finish(ok: boolean) {
		settle(ok && ready);
	}
</script>

<AlertDialog.Root open={!!c} onOpenChange={(o) => !o && finish(false)}>
	<AlertDialog.Portal>
		<AlertDialog.Overlay class="bg-overlay fixed inset-0 z-[60]" />
		<AlertDialog.Content class="border-border bg-raised shadow-pop fixed top-[18vh] left-1/2 z-[60] w-[calc(100vw-1.5rem)] max-w-md -translate-x-1/2 rounded-xl border p-5 outline-none">
			{#if c}
				<form onsubmit={(e) => { e.preventDefault(); finish(true); }}>
					<div class="flex gap-3">
						{#if c.danger}
							<div class="bg-danger-soft text-danger flex size-9 shrink-0 items-center justify-center rounded-full"><TriangleAlert class="size-4" /></div>
						{/if}
						<div class="min-w-0 flex-1">
							<AlertDialog.Title class="text-base font-semibold">{c.title}</AlertDialog.Title>
							{#if c.message}<AlertDialog.Description class="text-muted mt-1 text-sm">{c.message}</AlertDialog.Description>{/if}
							{#if c.typeToConfirm}
								<label class="mt-4 block text-sm" for="confirm-type">Type <strong class="font-mono font-semibold">{c.typeToConfirm}</strong> to confirm</label>
								<input id="confirm-type" class="control mt-1.5" bind:value={typed} autocomplete="off" spellcheck="false" />
							{/if}
						</div>
					</div>
					<div class="mt-5 flex justify-end gap-2">
						<AlertDialog.Cancel>
							{#snippet child({ props })}<Button {...props}>Cancel</Button>{/snippet}
						</AlertDialog.Cancel>
						<Button type="submit" variant={c.danger ? 'danger' : 'primary'} disabled={!ready}>{c.confirmLabel ?? 'Confirm'}</Button>
					</div>
				</form>
			{/if}
		</AlertDialog.Content>
	</AlertDialog.Portal>
</AlertDialog.Root>
