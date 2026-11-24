<script lang="ts">
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Page } from '#lib/types.js';
	import { monitorKinds, type Monitor, type MonitorKind } from '#lib/uptime.js';
	import Button from '#lib/ui/Button.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Add an uptime monitor, or change one. */
	let { monitor = null, siteId = '', onclose, ondone }: { monitor?: Monitor | null; siteId?: string; onclose: () => void; ondone: (id?: string) => void } = $props();

	// svelte-ignore state_referenced_locally
	const m = monitor;
	const c = (k: string) => (m?.config[k] ?? null) as never;
	let open = $state(true);
	const sites = $derived(clients.list.flatMap((cl) => cl.sites.map((s) => ({ value: s.id, label: `${cl.name} › ${s.name}`, client: cl.id }))));
	// svelte-ignore state_referenced_locally
	let site = $state(m?.site_id ?? siteId);
	let name = $state(m?.name ?? '');
	let kind = $state<MonitorKind>(m?.kind ?? 'http');
	let host = $state<string>(c('host') ?? '');
	let port = $state<number>(c('port') ?? 443);
	let url = $state<string>(c('url') ?? 'https://');
	let method = $state<'get' | 'head'>(c('method') ?? 'get');
	let statuses = $state<string>(((c('statuses') as number[] | null) ?? []).join(', '));
	let keyword = $state<string>(c('keyword') ?? '');
	let keywordAbsent = $state<boolean>(!!c('keyword_absent'));
	let verifyTls = $state<boolean>(c('verify_tls') ?? true);
	let serverName = $state<string>(c('server_name') ?? '');
	let dnsName = $state<string>(c('name') ?? '');
	let record = $state<string>(c('record') ?? 'A');
	let dnsServer = $state<string>(c('server') ?? '');
	let expect = $state<string>(((c('expect') as string[] | null) ?? []).join('\n'));
	/** An agent id, '' for the site's designated agent, or SERVER. */
	const SERVER = 'server';
	let agent = $state<string>(m?.runner === 'server' ? SERVER : (m?.agent_id ?? ''));
	let interval = $state(m?.interval_secs ?? 60);
	let timeout = $state(m?.timeout_secs ?? 10);
	let enabled = $state(m?.enabled ?? true);
	let saving = $state(false);

	$effect(() => {
		if (!site && sites.length) site = sites[0].value;
	});
	const clientOf = $derived(m?.client_id ?? sites.find((s) => s.value === site)?.client ?? '');
	const agents = resource(() => (clientOf ? api.get<Page<AgentSummary>>(`/agents?client_id=${clientOf}&limit=500&sort=hostname`) : Promise.resolve(null)));
	const designated = resource(() => (site ? api.get<{ agent_id: string | null; agent_hostname: string | null }>(`/sites/${site}/network`) : Promise.resolve(null)));
	$effect(() => {
		clientOf;
		agents.reload();
	});
	$effect(() => {
		site;
		designated.reload();
	});
	const runnerOptions = $derived([
		{ value: '', label: designated.data?.agent_hostname ? `The site’s designated agent (${designated.data.agent_hostname})` : 'The site’s designated agent (none chosen yet)' },
		...(agents.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.hostname} · ${a.site_name}${a.online ? '' : ' (offline)'}` })),
		{ value: SERVER, label: 'The server (public addresses only)' }
	]);

	function config(): Record<string, unknown> {
		switch (kind) {
			case 'ping':
				return { host };
			case 'tcp':
				return { host, port: Number(port) };
			case 'tls':
				return { host, port: Number(port), server_name: serverName.trim() || null };
			case 'http':
				return {
					url: url.trim(), method, keyword: method === 'get' ? keyword.trim() || null : null, keyword_absent: keywordAbsent, verify_tls: verifyTls,
					statuses: statuses.split(/[\s,]+/).filter(Boolean).map(Number)
				};
			case 'dns':
				return { name: dnsName, record, server: dnsServer.trim() || null, expect: expect.split('\n').map((e) => e.trim()).filter(Boolean) };
		}
	}

	function pickKind(k: MonitorKind) {
		kind = k;
		if (k === 'tls' && (!port || port === 80)) port = 443;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			const body = { site_id: site, name, kind, config: config(), runner: agent === SERVER ? 'server' : 'agent', agent_id: agent && agent !== SERVER ? agent : null, interval_secs: Number(interval), timeout_secs: Number(timeout), enabled };
			if (m) {
				await api.put(`/uptime/monitors/${m.id}`, body);
				toast.success(`${name} saved.`);
				open = false;
				ondone();
			} else {
				const r = await api.post<{ id: string }>('/uptime/monitors', body);
				toast.success(`${name} added; the first check runs now.`);
				open = false;
				ondone(r.id);
			}
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Drawer bind:open title={m ? `Edit ${m.name}` : 'Add an uptime monitor'} side="right" width="w-[36rem]" {onclose}>
	<form class="space-y-4 px-4 pb-6" onsubmit={save}>
		<h2 class="text-base font-semibold">{m ? `Edit ${m.name}` : 'Add an uptime monitor'}</h2>
		<div role="radiogroup" aria-label="What to check" class="grid gap-1.5 sm:grid-cols-2">
			{#each monitorKinds as k (k.value)}
				{@const on = kind === k.value}
				<button type="button" role="radio" aria-checked={on} class={cx('rounded-md border px-3 py-2 text-left text-sm transition-colors', on ? 'border-accent bg-accent-soft' : 'border-border hover:bg-hover')} onclick={() => pickKind(k.value)}>
					<span class={cx('block font-medium', on && 'text-accent')}>{k.label}</span>
					<span class="text-muted block text-xs">{k.hint}</span>
				</button>
			{/each}
		</div>
		{#if !m}
			<Field label="Site" id="um-site" required hint="The monitor belongs to this site's client.">
				<Select id="um-site" class="w-full" required bind:value={site} options={[{ value: '', label: 'Choose a site…', disabled: true }, ...sites]} />
			</Field>
		{/if}
		<Field label="Name" id="um-name" required><Input id="um-name" required maxlength={100} bind:value={name} placeholder="Client website" /></Field>

		{#if kind === 'http'}
			<Field label="URL" id="um-url" required hint="http:// or https://. A user name or password in the URL is refused.">
				<Input id="um-url" required class="font-mono text-[13px]" bind:value={url} placeholder="https://www.example.com/health" />
			</Field>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Request" id="um-method"><Select id="um-method" class="w-full" bind:value={method} options={[{ value: 'get', label: 'GET' }, { value: 'head', label: 'HEAD (no body)' }]} /></Field>
				<Field label="Expected status" id="um-status" hint="Comma-separated; empty: any 2xx or 3xx."><Input id="um-status" bind:value={statuses} placeholder="200, 204" /></Field>
			</div>
			{#if method === 'get'}
				<Field label="Keyword" id="um-kw" hint="Case-insensitive; looked for in the first 256 KB of the page. The page itself is never stored.">
					<Input id="um-kw" bind:value={keyword} placeholder="All systems operational" />
				</Field>
				{#if keyword.trim()}<Switch bind:checked={keywordAbsent}>Fail when the keyword is there (an error message)</Switch>{/if}
			{/if}
			{#if url.startsWith('https')}<Switch bind:checked={verifyTls}>Fail when the certificate isn’t trusted by the agent’s machine</Switch>{/if}
		{:else if kind === 'dns'}
			<div class="grid gap-3 sm:grid-cols-[1fr_8rem]">
				<Field label="Name" id="um-dns" required><Input id="um-dns" required class="font-mono text-[13px]" bind:value={dnsName} placeholder="mail.example.com" /></Field>
				<Field label="Record" id="um-rec"><Select id="um-rec" class="w-full" bind:value={record} options={['A', 'AAAA', 'CNAME', 'MX', 'TXT'].map((r) => ({ value: r, label: r }))} /></Field>
			</div>
			<Field label="DNS server" id="um-dsrv" hint="An address; empty: the agent's own resolvers."><Input id="um-dsrv" class="font-mono text-[13px]" bind:value={dnsServer} placeholder="10.0.0.53" /></Field>
			<Field label="Expected answers" id="um-exp" hint="One per line; the check fails unless one of them comes back. MX as “10 mail.example.com”. Empty: any answer.">
				<Textarea id="um-exp" rows={2} class="font-mono text-[13px]" bind:value={expect} placeholder="203.0.113.10" />
			</Field>
		{:else}
			<div class={cx('grid gap-3', kind !== 'ping' && 'sm:grid-cols-[1fr_8rem]')}>
				<Field label="Host" id="um-host" required hint="A name or an address; private ones are fine, the agent is on that network.">
					<Input id="um-host" required class="font-mono text-[13px]" bind:value={host} placeholder={kind === 'ping' ? '192.168.1.1' : 'db.corp.example'} />
				</Field>
				{#if kind !== 'ping'}<Field label="Port" id="um-port" required><Input id="um-port" type="number" min="1" max="65535" required bind:value={port} /></Field>{/if}
			</div>
			{#if kind === 'tls'}
				<Field label="Server name (SNI)" id="um-sni" hint="If the certificate is for another name than the host."><Input id="um-sni" class="font-mono text-[13px]" bind:value={serverName} /></Field>
			{/if}
		{/if}

		<Field label="Checked by" id="um-agent" hint={agent === SERVER ? 'From the server, over the internet: it can’t reach private, loopback or link-local addresses.' : 'Any agent of the client, or the server. The designated agent is chosen under Network → Settings.'}>
			<Select id="um-agent" class="w-full" bind:value={agent} options={runnerOptions} />
		</Field>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Every (seconds)" id="um-int" hint="30 to 86400."><Input id="um-int" type="number" min="30" max="86400" bind:value={interval} /></Field>
			<Field label="Timeout (seconds)" id="um-to" hint="1 to 120."><Input id="um-to" type="number" min="1" max="120" bind:value={timeout} /></Field>
		</div>
		<Switch bind:checked={enabled}>Check it (switched off: no checks and no alerts)</Switch>
		<p class="hint">{#if agent === SERVER}Alerts come from <em>Uptime monitor</em> items in All devices that cover this client and site.{:else}Alerts come from an <em>Uptime monitor</em> item in the checking agent’s policy set.{/if}</p>
		<div class="flex justify-end gap-2 pt-2">
			<Button variant="ghost" onclick={() => ((open = false), onclose())}>Cancel</Button>
			<Button variant="primary" type="submit" loading={saving} disabled={!site || !name.trim()}>{m ? 'Save' : 'Add monitor'}</Button>
		</div>
	</form>
</Drawer>
