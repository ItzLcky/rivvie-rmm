<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { CircleCheck, ThumbsDown, ThumbsUp } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { cx } from '#lib/format.js';
	import { PortalError, survey } from '#lib/portal/api.js';
	import { ticketNumber } from '#lib/portal/format.js';
	import type { Survey } from '#lib/portal/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	type Rating = 'good' | 'bad';

	const token = $derived(page.params.token ?? '');
	let s = $state<Survey | null>(null);
	let loadError = $state('');
	let missing = $state(false);
	let rating = $state<Rating | null>(null);
	let comment = $state('');
	let busy = $state(false);
	let error = $state('');
	let commentSent = $state(false);

	const cap = (e: unknown) => {
		const m = e instanceof Error ? e.message : String(e);
		return m.charAt(0).toUpperCase() + m.slice(1);
	};

	onMount(async () => {
		try {
			s = await survey.get<Survey>(token);
			comment = s.comment ?? '';
			commentSent = !!s.comment;
			const fromLink = page.url.searchParams.get('rating');
			if (fromLink === 'good' || fromLink === 'bad') await rate(fromLink);
			else if (s.rating) rating = s.rating;
		} catch (e) {
			if (e instanceof PortalError && e.status === 404) missing = true;
			else loadError = cap(e);
		}
	});

	async function rate(r: Rating) {
		busy = true;
		error = '';
		try {
			await survey.answer(token, r, comment.trim());
			rating = r;
		} catch (e) {
			error = cap(e);
		} finally {
			busy = false;
		}
	}

	async function sendComment(e: SubmitEvent) {
		e.preventDefault();
		if (!rating) return;
		busy = true;
		error = '';
		try {
			await survey.answer(token, rating, comment.trim());
			commentSent = true;
		} catch (e) {
			error = cap(e);
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>How did we do? · {s?.company_name || 'Support'}</title>
</svelte:head>

<div class="bg-surface flex min-h-dvh flex-col items-center justify-center px-4 py-10">
	<main class="w-full max-w-lg">
		<div class="mb-6 flex items-center gap-2.5">
			<img src={favicon} alt="" class="size-8" />
			<span class="text-[0.9375rem] font-semibold tracking-tight">{s?.company_name ? `${s.company_name} support` : 'Support'}</span>
		</div>
		<div class="card p-6 sm:p-8">
			{#if missing}
				<h1 class="text-2xl font-medium">Survey not found</h1>
				<p class="text-muted mt-2 text-sm">This survey link isn't valid any more. Thanks for wanting to tell us how we did.</p>
			{:else if loadError}
				<h1 class="text-2xl font-medium">Something went wrong</h1>
				<p class="text-muted mt-2 text-sm" role="alert">{loadError}</p>
				<Button class="mt-4" onclick={() => location.reload()}>Try again</Button>
			{:else if !s || (busy && !rating)}
				<p class="text-muted flex items-center gap-2 text-sm" role="status"><Spinner />{s ? 'Saving your rating…' : 'Loading…'}</p>
			{:else if !rating}
				<h1 class="text-2xl font-medium">How did we do?</h1>
				<p class="text-muted mt-2 text-sm">
					About your request <span class="font-mono">{ticketNumber(s.number)}</span>: <span class="text-fg font-medium break-words">{s.subject}</span>
				</p>
				<div class="mt-6 grid grid-cols-2 gap-3" role="group" aria-label="Rate the support you got">
					{#each [{ r: 'good' as const, label: 'Good', icon: ThumbsUp, tone: 'hover:border-success hover:bg-success-soft focus-visible:border-success' }, { r: 'bad' as const, label: 'Bad', icon: ThumbsDown, tone: 'hover:border-danger hover:bg-danger-soft focus-visible:border-danger' }] as o (o.r)}
						<button
							type="button"
							class={cx(
								'border-border-strong bg-raised shadow-card focus-visible:ring-accent/30 flex h-32 cursor-pointer flex-col items-center justify-center gap-2 rounded-panel border-2 text-lg font-semibold transition-colors focus-visible:ring-4 focus-visible:outline-none disabled:opacity-60',
								o.tone
							)}
							disabled={busy}
							onclick={() => rate(o.r)}
						>
							<o.icon class={cx('size-8', o.r === 'good' ? 'text-success' : 'text-danger')} aria-hidden="true" />
							{o.label}
						</button>
					{/each}
				</div>
				{#if error}<p class="bg-danger-soft text-danger mt-4 rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
			{:else}
				<div role="status">
					<div class="bg-success-soft text-success mb-4 flex size-11 items-center justify-center rounded-lg"><CircleCheck class="size-5" aria-hidden="true" /></div>
					<h1 class="text-2xl font-medium">Thanks for your feedback</h1>
					<p class="text-muted mt-2 text-sm">
						You rated <span class="font-mono">{ticketNumber(s.number)}</span>
						<strong class={cx('font-semibold', rating === 'good' ? 'text-success' : 'text-danger')}>{rating === 'good' ? 'good' : 'bad'}</strong>.
						<button type="button" class="link" disabled={busy} onclick={() => rate(rating === 'good' ? 'bad' : 'good')}>Change to {rating === 'good' ? 'bad' : 'good'}</button>
					</p>
				</div>
				<form class="mt-6 space-y-3" onsubmit={sendComment}>
					<Field label={rating === 'good' ? 'Anything you’d like to add? (optional)' : 'What could we have done better? (optional)'} id="comment">
						<Textarea id="comment" rows={4} maxlength={5000} bind:value={comment} oninput={() => (commentSent = false)} />
					</Field>
					{#if error}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{error}</p>{/if}
					<div class="flex flex-wrap items-center justify-end gap-3">
						{#if commentSent && comment.trim()}<span class="text-success text-sm" role="status">Comment sent</span>{/if}
						<Button variant="primary" type="submit" loading={busy} disabled={!comment.trim() || commentSent}>Send comment</Button>
					</div>
				</form>
			{/if}
		</div>
	</main>
</div>
