<script lang="ts">
	import { Command, Dialog } from 'bits-ui';
	import { goto } from '$app/navigation';
	import { Building2, Clock, FileCode2, Keyboard, LifeBuoy, MapPin, Monitor, Moon, Play, Plus, Search, Globe } from '@lucide/svelte';
	import type { Component } from 'svelte';
	import { api } from '#lib/api.js';
	import { cx, interpreterLabel } from '#lib/format.js';
	import { setPref } from '#lib/prefs.svelte.js';
	import { recentAgents } from '#lib/recent.js';
	import { currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { SearchResults } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import OsIcon from '#lib/components/OsIcon.svelte';
	import { nav } from './nav';

	let {
		open = $bindable(false),
		onrun,
		onshortcuts
	}: { open?: boolean; onrun: (agentId: string) => void; onshortcuts: () => void } = $props();

	let query = $state('');
	/** 'run': the next agent picked gets the Run script dialog. */
	let mode = $state<'search' | 'run'>('search');
	let allClients = $state(false);
	let results = $state<SearchResults | null>(null);
	let searching = $state(false);
	const scoped = $derived(allClients ? undefined : currentClient());

	$effect(() => {
		if (!open) {
			query = '';
			mode = 'search';
			allClients = false;
			results = null;
		}
	});

	$effect(() => {
		const q = query.trim();
		const client = scoped?.id;
		if (!q) {
			results = null;
			return;
		}
		searching = true;
		const t = setTimeout(() => {
			api.get<SearchResults>(`/search${qs({ q, client_id: client })}`)
				.then((r) => {
					if (q === query.trim()) results = r;
				})
				.catch(() => {})
				.finally(() => (searching = false));
		}, 120);
		return () => clearTimeout(t);
	});

	interface Action {
		id: string;
		label: string;
		icon: Component<{ class?: string }>;
		run: () => void;
		hint?: string;
		show?: boolean;
	}
	const actions = $derived<Action[]>(
		[
			{ id: 'run', label: 'Run script on…', icon: Play, run: () => ((mode = 'run'), (query = '')), show: can('technician') },
			{ id: 'new-script', label: 'New script', icon: Plus, run: () => go('/scripts/new'), show: can('technician') },
			{ id: 'add-client', label: 'Add client', icon: Plus, run: () => go('/clients?new=1'), show: can('admin') },
			{ id: 'enroll', label: 'Enroll agents', icon: Plus, run: () => go(withClient('/clients')), show: can('technician') },
			{ id: 'theme', label: `Theme: switch to ${document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'}`, icon: Moon, run: () => (setPref('theme', document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'), (open = false)) },
			{ id: 'keys', label: 'Keyboard shortcuts', icon: Keyboard, hint: '?', run: () => ((open = false), onshortcuts()) }
		].filter((a) => a.show !== false)
	);
	const pages = nav.flatMap((g) => g.items).filter((i) => !i.role || can(i.role));

	const q = $derived(query.trim().toLowerCase());
	const matches = (s: string) => !q || s.toLowerCase().includes(q);
	const shownActions = $derived(mode === 'search' ? actions.filter((a) => matches(a.label)) : []);
	const shownPages = $derived(mode === 'search' && q ? pages.filter((p) => matches(p.label)) : []);
	const recent = $derived(!q ? recentAgents() : []);

	function go(href: string) {
		open = false;
		goto(href);
	}
	function pickAgent(id: string) {
		if (mode === 'run') {
			open = false;
			onrun(id);
		} else go(`/agents/${id}`);
	}

	const item = 'data-[selected]:bg-hover flex h-9 cursor-pointer items-center gap-2.5 rounded-md px-2 text-sm outline-none select-none [&_svg]:size-4 [&_svg]:shrink-0';
	const heading = 'text-muted px-2 pt-2 pb-1 text-xs font-medium';
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay class="bg-overlay fixed inset-0 z-50" />
		<Dialog.Content class="border-border bg-raised shadow-pop fixed top-[10vh] left-1/2 z-50 w-[calc(100vw-1.5rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border outline-none">
			<Dialog.Title class="sr-only">Search and commands</Dialog.Title>
			<Command.Root shouldFilter={false} loop label="Search and commands">
				<div class="border-border flex items-center gap-2 border-b px-3">
					<Search class="text-muted size-4 shrink-0" />
					<Command.Input
						bind:value={query}
						placeholder={mode === 'run' ? 'Run a script on which agent? Type a hostname…' : 'Search agents, tickets, clients, sites, scripts, or type a command…'}
						class="placeholder:text-subtle h-12 min-w-0 flex-1 bg-transparent text-sm outline-none"
					/>
					{#if mode === 'run'}<button class="text-muted hover:text-fg text-xs" onclick={() => (mode = 'search')}>Back</button>{/if}
				</div>
				<Command.List class="max-h-[min(60vh,28rem)] overflow-y-auto p-1.5">
					<Command.Viewport>
						{#if scoped && q}
							<Command.Item value="all-clients" class={item} onSelect={() => (allClients = true)}>
								<Globe class="text-muted" /> <span>Searching <strong>{scoped.name}</strong> only. Search all clients</span>
							</Command.Item>
						{/if}
						{#if recent.length}
							<Command.Group>
								<Command.GroupHeading class={heading}>{mode === 'run' ? 'Recent agents' : 'Recently viewed'}</Command.GroupHeading>
								<Command.GroupItems>
									{#each recent as a (a.id)}
										<Command.Item value="recent-{a.id}" class={item} onSelect={() => pickAgent(a.id)}>
											<Clock class="text-muted" /><span class="truncate">{a.hostname}</span><span class="text-muted ml-auto truncate text-xs">{a.client_name}</span>
										</Command.Item>
									{/each}
								</Command.GroupItems>
							</Command.Group>
						{/if}
						{#if results?.agents.length}
							<Command.Group>
								<Command.GroupHeading class={heading}>Agents</Command.GroupHeading>
								<Command.GroupItems>
									{#each results.agents as a (a.id)}
										<Command.Item value="agent-{a.id}" class={item} onSelect={() => pickAgent(a.id)}>
											<span class={cx('size-2 shrink-0 rounded-full', a.online ? 'bg-success' : 'bg-subtle')} aria-label={a.online ? 'online' : 'offline'}></span>
											<OsIcon os={a.os_family} />
											<span class="truncate font-medium">{a.hostname}</span>
											<span class="text-muted ml-auto truncate text-xs">{a.client_name} › {a.site_name}</span>
										</Command.Item>
									{/each}
								</Command.GroupItems>
							</Command.Group>
						{/if}
						{#if mode === 'search' && results?.tickets?.length}
							<Command.Group>
								<Command.GroupHeading class={heading}>Tickets</Command.GroupHeading>
								<Command.GroupItems>
									{#each results.tickets as t (t.id)}
										<Command.Item value="ticket-{t.id}" class={item} onSelect={() => go(`/tickets/${t.id}`)}>
											<LifeBuoy class="text-muted" />
											<span class="text-muted font-mono text-xs">T-{t.number}</span>
											<span class="truncate">{t.subject}</span>
											<span class="text-muted ml-auto truncate text-xs">{t.client_name ?? 'Triage'} · {t.status_name}</span>
										</Command.Item>
									{/each}
								</Command.GroupItems>
							</Command.Group>
						{/if}
						{#if mode === 'search' && results}
							{#each [['Clients', results.clients, Building2], ['Sites', results.sites, MapPin], ['Scripts', results.scripts, FileCode2]] as const as [label, list, Icon] (label)}
								{#if list.length}
									<Command.Group>
										<Command.GroupHeading class={heading}>{label}</Command.GroupHeading>
										<Command.GroupItems>
											{#each list as r (r.id)}
												<Command.Item
													value="{label}-{r.id}"
													class={item}
													onSelect={() => go(label === 'Scripts' ? `/scripts/${r.id}` : label === 'Sites' ? `/clients/${'client_id' in r ? r.client_id : ''}?tab=sites` : `/clients/${r.id}`)}
												>
													<Icon class="text-muted" />
													<span class="truncate">{r.name}</span>
													<span class="text-muted ml-auto truncate text-xs">
														{#if 'interpreter' in r}{interpreterLabel(r.interpreter)}{r.client_name ? ` · ${r.client_name}` : ''}{:else if 'client_name' in r}{r.client_name}{/if}
													</span>
												</Command.Item>
											{/each}
										</Command.GroupItems>
									</Command.Group>
								{/if}
							{/each}
						{/if}
						{#if shownPages.length}
							<Command.Group>
								<Command.GroupHeading class={heading}>Go to</Command.GroupHeading>
								<Command.GroupItems>
									{#each shownPages as p (p.href)}
										<Command.Item value="page-{p.href}" class={item} onSelect={() => go(p.scoped ? withClient(p.href) : p.href)}>
											<p.icon class="text-muted" />{p.label}{#if p.key}<span class="text-muted ml-auto font-mono text-xs">g {p.key}</span>{/if}
										</Command.Item>
									{/each}
								</Command.GroupItems>
							</Command.Group>
						{/if}
						{#if shownActions.length}
							<Command.Group>
								<Command.GroupHeading class={heading}>Commands</Command.GroupHeading>
								<Command.GroupItems>
									{#each shownActions as a (a.id)}
										<Command.Item value="action-{a.id}" class={item} onSelect={a.run}>
											<a.icon class="text-muted" />{a.label}{#if a.hint}<span class="text-muted ml-auto font-mono text-xs">{a.hint}</span>{/if}
										</Command.Item>
									{/each}
								</Command.GroupItems>
							</Command.Group>
						{/if}
						{#if q && results && !results.agents.length && !results.clients.length && !results.sites.length && !results.scripts.length && !results.tickets?.length && !shownPages.length && !shownActions.length}
							<p class="text-muted px-3 py-8 text-center text-sm">No matches for “{query.trim()}”{scoped ? ` in ${scoped.name}` : ''}.</p>
						{:else if q && !results && searching}
							<p class="text-muted px-3 py-8 text-center text-sm">Searching…</p>
						{/if}
					</Command.Viewport>
				</Command.List>
				<div class="border-border text-muted flex items-center gap-3 border-t px-3 py-2 text-[11px]">
					<span><kbd class="kbd">↑</kbd> <kbd class="kbd">↓</kbd> move</span>
					<span><kbd class="kbd">↵</kbd> open</span>
					<span><kbd class="kbd">esc</kbd> close</span>
					{#if mode === 'run'}<span class="ml-auto"><Monitor class="inline size-3" /> picking an agent</span>{/if}
				</div>
			</Command.Root>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
