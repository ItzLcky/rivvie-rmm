<script lang="ts">
	import { ChevronDown, ExternalLink, LockKeyhole } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';

	// The reference is generated from the server's own OpenAPI document (/api/openapi.json), so it
	// can't drift from what the API does.
	interface Param { name: string; in: 'path' | 'query'; description?: string; required?: boolean; schema?: { type?: string | string[]; format?: string } }
	interface Operation {
		operationId: string; summary: string; description: string; tags: string[]; parameters: Param[];
		requestBody?: { content: { 'application/json': { schema: { $ref: string } } } };
		'x-rmm-scope': string; 'x-rmm-access': 'read' | 'write';
	}
	interface Spec {
		info: { title: string; version: string; description: string };
		tags: { name: string; description: string }[];
		paths: Record<string, Record<string, Operation>>;
		components: { schemas: Record<string, { description?: string; properties?: Record<string, { type?: string | string[]; format?: string; description?: string }>; required?: string[] }> };
	}
	const spec = resource(() => api.get<Spec>('/openapi.json'));

	const methodTone = { get: 'info', post: 'success', patch: 'warning', put: 'warning', delete: 'danger' } as const;
	function ops(s: Spec, tag: string) {
		const out: { method: keyof typeof methodTone; path: string; op: Operation }[] = [];
		for (const [path, item] of Object.entries(s.paths))
			for (const [method, op] of Object.entries(item)) if (op.tags.includes(tag)) out.push({ method: method as keyof typeof methodTone, path, op });
		return out;
	}
	const typeOf = (p?: { type?: string | string[]; format?: string }) => (p ? [([] as string[]).concat(p.type ?? 'any').join(' | '), p.format].filter(Boolean).join(' · ') : '');
	const schemaName = (ref: string) => ref.split('/').pop() ?? ref;

	let open = $state<Record<string, boolean>>({});
	const origin = typeof location === 'undefined' ? '' : location.origin;
	const example = `curl -H "Authorization: Bearer rmm_k_…" \\
  ${origin || 'https://rmm.example.com'}/api/v1/agents?online=true&limit=50`;
	const verify = `import hmac, hashlib

def valid(secret: str, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)`;
	const payload = `{
  "id": "6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111",   // = X-RMM-Delivery, the same on retries
  "event": "ticket.status_changed",
  "created_at": "2026-06-15T14:30:00Z",
  "data": {
    "ticket": { "id": "…", "number": 10423, "subject": "…", "status": { "name": "Resolved", "category": "resolved" }, "client": { "id": "…", "name": "…" } },
    "change": { "field": "status", "from": "Open", "to": "Resolved", "category": "resolved" },
    "actor": { "type": "user", "id": "…", "name": "Dana Admin" }
  }
}`;
</script>

<PageHeader title="API reference" description="The public REST API, as the server describes it" />

<Async res={spec}>
	{#snippet children(s)}
		<div class="grid max-w-5xl gap-5">
			<section class="card space-y-3 p-5" aria-labelledby="start-h">
				<h2 id="start-h" class="font-semibold">Getting started</h2>
				<p class="text-sm">
					Create a key under <a class="link" href="/account">Account</a> (admins can also make keys for service accounts under <a class="link" href="/settings/api-keys">Company settings → API</a>), then send it as a bearer token.
					Base URL <code>/api/v1</code>, version <strong>{s.info.version}</strong>.
				</p>
				<CodeBlock code={example} label="Example request" />
				<ul class="text-muted list-disc space-y-1 pl-5 text-sm">
					<li>A key acts as its owner and never with more: the owner’s clients and permissions are checked on every request. Read-only keys can only <code>GET</code>.</li>
					<li>Each route needs the key’s <em>scope</em> shown beside it. The agent connection, remote shell and desktop, the password vault and administration are not in the API.</li>
					<li>Lists return <code>{'{ items, next, prev, total }'}</code>; pass <code>next</code> as <code>after</code> for the next page. Errors are <code>{'{ "error": "…" }'}</code>.</li>
					<li>Every key has a request budget per minute; beyond it you get HTTP 429 and <code>Retry-After</code>.</li>
					<li>The machine-readable document: <a class="link inline-flex items-center gap-1" href="/api/v1/openapi.json">openapi.json <ExternalLink class="size-3" aria-hidden="true" /></a>.</li>
				</ul>
			</section>

			{#each s.tags.filter((t) => ops(s, t.name).length) as tag (tag.name)}
				<section class="card" aria-labelledby="tag-{tag.name}">
					<header class="border-border border-b px-5 py-3">
						<h2 id="tag-{tag.name}" class="font-semibold capitalize">{tag.name}</h2>
						<p class="text-muted text-xs">{tag.description}</p>
					</header>
					<ul class="divide-border divide-y">
						{#each ops(s, tag.name) as o (o.op.operationId)}
							{@const isOpen = !!open[o.op.operationId]}
							<li>
								<button
									class="hover:bg-hover flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-5 py-2.5 text-left text-sm"
									aria-expanded={isOpen}
									aria-controls="op-{o.op.operationId}"
									onclick={() => (open[o.op.operationId] = !isOpen)}
								>
									<Badge tone={methodTone[o.method]}><span class="font-mono uppercase">{o.method}</span></Badge>
									<code class="text-fg font-mono text-xs break-all">{o.path}</code>
									<span class="text-muted min-w-0 flex-1">{o.op.summary}</span>
									{#if o.op['x-rmm-access'] === 'write'}<span title="Needs a key with write access"><LockKeyhole class="text-warning size-4" aria-label="Write access" /></span>{/if}
									<ChevronDown class={cx('text-muted size-4 transition-transform', isOpen && 'rotate-180')} aria-hidden="true" />
								</button>
								{#if isOpen}
									<div id="op-{o.op.operationId}" class="border-border bg-sunken/40 space-y-3 border-t px-5 py-3 text-sm">
										<p>{o.op.description}</p>
										{#if o.op.parameters.length}
											<div class="overflow-x-auto">
												<table class="table">
													<thead><tr><th>Parameter</th><th>In</th><th>Type</th><th>Description</th></tr></thead>
													<tbody>
														{#each o.op.parameters as p (p.in + p.name)}
															<tr><td><code>{p.name}</code></td><td>{p.in}</td><td class="text-muted">{typeOf(p.schema)}</td><td>{p.description ?? ''}</td></tr>
														{/each}
													</tbody>
												</table>
											</div>
										{/if}
										{#if o.op.requestBody}
											{@const name = schemaName(o.op.requestBody.content['application/json'].schema.$ref)}
											{@const body = s.components.schemas[name]}
											<div>
												<div class="label">JSON body: {name}</div>
												<ul class="space-y-0.5 text-xs">
													{#each Object.entries(body?.properties ?? {}) as [field, def] (field)}
														<li><code>{field}</code>{#if body?.required?.includes(field)} <span class="text-danger">required</span>{/if} <span class="text-muted">{typeOf(def)}{def.description ? ` · ${def.description}` : ''}</span></li>
													{/each}
												</ul>
											</div>
										{/if}
										<p class="text-muted text-xs">Scope <code>{o.op['x-rmm-scope']}</code> · {o.op['x-rmm-access'] === 'write' ? 'write key' : 'any key'}</p>
									</div>
								{/if}
							</li>
						{/each}
					</ul>
				</section>
			{/each}

			<section id="webhooks" class="card scroll-mt-4 space-y-3 p-5" aria-labelledby="hooks-h">
				<h2 id="hooks-h" class="font-semibold">Webhooks</h2>
				<p class="text-sm">
					Admins subscribe a URL to ticket and alert events under <a class="link" href="/settings/webhooks">Company settings → Webhooks</a>. Each delivery is a <code>POST</code> of
					JSON with <code>X-RMM-Event</code>, <code>X-RMM-Delivery</code> and <code>X-RMM-Signature: sha256=…</code>, the hex HMAC-SHA256 of the raw body with the subscription’s secret.
					Any 2xx response counts as delivered; otherwise it is retried after 1, 5, 30 and 120 minutes, always with the same body.
				</p>
				<CodeBlock code={payload} label="Example delivery body" />
				<CodeBlock code={verify} label="Verifying the signature" />
				<p class="text-muted text-sm">
					Events: <code>ticket.created</code>, <code>ticket.updated</code>, <code>ticket.status_changed</code>, <code>ticket.resolved</code>, <code>ticket.comment</code>,
					<code>alert.created</code>, <code>alert.acknowledged</code>, <code>alert.resolved</code>, and <code>ping</code> from the Test button. Internal notes are only sent to subscriptions that ask for them.
				</p>
			</section>
		</div>
	{/snippet}
</Async>
