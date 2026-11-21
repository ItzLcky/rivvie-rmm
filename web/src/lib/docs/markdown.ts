/**
 * Markdown for client documents: one markdown-it instance, the custom blocks split out of the
 * token stream, template placeholders and `.md` front matter.
 *
 * Document bodies are untrusted (any technician writes them, and imports come from anywhere),
 * so raw HTML is never rendered (`html: false`), links pass an allowlist of schemes, and
 * images only load from this origin or inline data. What comes out is safe for `{@html}`.
 */
import MarkdownIt from 'markdown-it';
import type { Token } from 'markdown-it';

export const BLOCK_NAMES = ['fields', 'credential', 'callout', 'device'] as const;
export type BlockName = (typeof BLOCK_NAMES)[number];
const isBlock = (s: string): s is BlockName => (BLOCK_NAMES as readonly string[]).includes(s);

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Schemes a link may use. Anything without a scheme (relative paths, #anchors) is fine too.
 * An allowlist rather than markdown-it's blocklist: a page can't carry `javascript:` in any
 * spelling, nor a scheme a browser or OS handler might do something surprising with.
 */
const SAFE_SCHEMES = new Set(['http', 'https', 'mailto', 'tel', 'ftp', 'sftp', 'ssh', 'rdp', 'vnc', 'smb', 'vault', 'doc']);
const SCHEME = /^([a-z][a-z0-9+.-]*):/i;

export function safeLink(url: string): boolean {
	const s = url.trim();
	const m = SCHEME.exec(s);
	return !m || SAFE_SCHEMES.has(m[1].toLowerCase());
}
/** Same-origin paths and inline raster images; the CSP would block anything else anyway. */
function loadableImage(src: string): boolean {
	const s = src.trim();
	if (/^data:image\/(png|gif|jpeg|webp);/i.test(s)) return true;
	return !SCHEME.test(s) && !s.startsWith('//') && !s.startsWith('\\');
}
/** http(s) URLs only: everything else (host names, rdp://) is shown as text, not a link. */
export function webUrl(url: string): string | null {
	const s = url.trim();
	return /^https?:\/\/[^\s]+$/i.test(s) ? s : null;
}

export const md = new MarkdownIt({ html: false, linkify: true, breaks: true, typographer: false });
md.validateLink = safeLink;
const esc = md.utils.escapeHtml;

// --- rendering rules ---------------------------------------------------------------------------

// The page title is the h2; a document's own headings sit below it.
md.renderer.rules.heading_open = (tokens, idx) => `<h${Math.min(6, Number(tokens[idx].tag.slice(1)) + 1)}>`;
md.renderer.rules.heading_close = (tokens, idx) => `</h${Math.min(6, Number(tokens[idx].tag.slice(1)) + 1)}>\n`;

// Wide tables scroll inside the page instead of widening it.
md.renderer.rules.table_open = () => '<div class="doc-table" tabindex="0" role="region" aria-label="Table"><table>\n';
md.renderer.rules.table_close = () => '</table></div>\n';

const ICON_KEY =
	'<svg class="doc-chip-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>';

/**
 * `vault:<id>` links become a button (the page opens the credential in a popover), `doc:<id>`
 * links point at that page of the same client, and web links open in a new tab.
 */
md.renderer.rules.link_open = (tokens, idx, options, _env, self) => {
	const t = tokens[idx];
	const href = String(t.attrGet('href') ?? '').trim();
	const scheme = SCHEME.exec(href)?.[1].toLowerCase();
	if (scheme === 'vault') {
		for (let j = idx + 1; j < tokens.length; j++) {
			if (tokens[j].type === 'link_close') {
				tokens[j].meta = { vault: true };
				break;
			}
		}
		const id = href.slice(6);
		return `<button type="button" class="doc-chip" data-vault="${esc(id)}" aria-haspopup="dialog">${ICON_KEY}<span>`;
	}
	if (scheme === 'doc') {
		const id = href.slice(4);
		t.attrSet('href', `?tab=docs&doc=${encodeURIComponent(id)}`);
		t.attrSet('data-doc', id);
	} else if (scheme === 'http' || scheme === 'https') {
		t.attrSet('target', '_blank');
		t.attrSet('rel', 'noopener noreferrer');
	}
	return self.renderToken(tokens, idx, options);
};
md.renderer.rules.link_close = (tokens, idx, options, _env, self) => (tokens[idx].meta?.vault ? '</span></button>' : self.renderToken(tokens, idx, options));

md.renderer.rules.image = (tokens, idx, options, env, self) => {
	const t = tokens[idx];
	const src = String(t.attrGet('src') ?? '');
	const alt = self.renderInlineAsText(t.children ?? [], options, env);
	if (loadableImage(src)) {
		t.attrSet('alt', alt);
		t.attrSet('loading', 'lazy');
		return self.renderToken(tokens, idx, options);
	}
	// External images would be blocked by the CSP (and would tell another server who read the page).
	return safeLink(src) && webUrl(src)
		? `<a href="${esc(src)}" target="_blank" rel="noopener noreferrer">${esc(alt || 'Image')}</a>`
		: esc(alt || '');
};

// Read-only task lists: `- [ ]` and `- [x]` at the start of a list item.
md.core.ruler.after('inline', 'tasks', (state) => {
	const toks = state.tokens;
	for (let i = 2; i < toks.length; i++) {
		const t = toks[i];
		if (t.type !== 'inline' || toks[i - 1].type !== 'paragraph_open' || toks[i - 2].type !== 'list_item_open') continue;
		const first = t.children?.[0];
		const m = first?.type === 'text' ? /^\[([ xX])\](?:\s+|$)/.exec(first.content) : null;
		if (!first || !m) continue;
		first.content = first.content.slice(m[0].length);
		const box = new state.Token('task_box', '', 0);
		box.meta = { done: m[1] !== ' ' };
		t.children!.unshift(box);
		toks[i - 2].attrJoin('class', 'task');
		for (let j = i - 3; j >= 0; j--) {
			if ((toks[j].type === 'bullet_list_open' || toks[j].type === 'ordered_list_open') && toks[j].level === toks[i - 2].level - 1) {
				if (!String(toks[j].attrGet('class') ?? '').includes('tasks')) toks[j].attrJoin('class', 'tasks');
				break;
			}
		}
	}
});
md.renderer.rules.task_box = (tokens, idx) =>
	tokens[idx].meta?.done
		? '<span class="task-box done" aria-hidden="true"></span><span class="sr-only">Done: </span>'
		: '<span class="task-box" aria-hidden="true"></span><span class="sr-only">To do: </span>';

// --- segments ----------------------------------------------------------------------------------

export type Segment =
	| { kind: 'md'; html: string }
	| {
			kind: 'block';
			name: BlockName;
			/** The words after the block name (`callout warning` → "warning"). */
			arg: string;
			body: string;
			/** Source lines [from, to) of the whole fence, for rewriting it. */
			from: number;
			to: number;
	  };

/**
 * Renders a document as Markdown HTML with the registered blocks split out. Only top-level
 * fences are blocks; inside a list or a quote they stay code.
 */
export function segments(src: string): Segment[] {
	const env = {};
	const tokens = md.parse(src, env);
	const out: Segment[] = [];
	let start = 0;
	const flush = (end: number) => {
		if (end > start) {
			const html = md.renderer.render(tokens.slice(start, end), md.options, env);
			if (html.trim()) out.push({ kind: 'md', html });
		}
	};
	tokens.forEach((t: Token, i: number) => {
		if (t.type !== 'fence' || t.level !== 0 || !t.map) return;
		const [name = '', ...rest] = t.info.trim().split(/\s+/);
		if (!isBlock(name)) return;
		flush(i);
		out.push({ kind: 'block', name, arg: rest.join(' '), body: t.content.replace(/\n$/, ''), from: t.map[0], to: t.map[1] });
		start = i + 1;
	});
	flush(tokens.length);
	return out;
}

/** Markdown for a fragment inside a block (a callout's text). */
export const renderMarkdown = (src: string) => md.render(src);
/** One line of inline Markdown (a field's value). */
export const renderInline = (src: string) => md.renderInline(src);

// --- block bodies ------------------------------------------------------------------------------

/** `key: value` lines, keys lower-cased. Lines that aren't one are returned separately. */
export function keyValues(body: string): { values: Record<string, string>; other: string[] } {
	const values: Record<string, string> = {};
	const other: string[] = [];
	for (const line of body.split('\n')) {
		if (!line.trim()) continue;
		const m = /^\s*([A-Za-z][\w -]*?)\s*:\s*(.*)$/.exec(line);
		if (m) values[m[1].toLowerCase()] = m[2].trim();
		else other.push(line.trim());
	}
	return { values, other };
}

export type FieldRow = { key: string; value: string } | { text: string };

/**
 * A `fields` block: `Label: value` rows. A line ending in `:` is a field with no value yet
 * (templates leave them empty); a line without `: ` is a full-width row.
 */
export function parseFields(body: string): FieldRow[] {
	return body
		.split('\n')
		.map((l) => l.trim())
		.filter(Boolean)
		.map((l) => {
			const i = l.indexOf(': ');
			if (i > 0) return { key: l.slice(0, i).trim(), value: l.slice(i + 2).trim() };
			if (l.length > 1 && l.endsWith(':')) return { key: l.slice(0, -1).trim(), value: '' };
			return { text: l };
		});
}

/** A `credential` block: a vault item, or an empty slot with a label. */
export function parseCredential(body: string): { item: string | null; label: string; error?: string } {
	const { values } = keyValues(body);
	const label = values.label ?? '';
	if (values.item === undefined || values.item === '') return { item: null, label };
	const m = /^vault:(.+)$/i.exec(values.item);
	if (!m || !UUID.test(m[1].trim())) return { item: null, label, error: 'item: must be vault:<id>' };
	return { item: m[1].trim().toLowerCase(), label };
}

export function parseDevice(body: string): { agent: string | null; error?: string } {
	const a = keyValues(body).values.agent?.trim() ?? '';
	if (!a) return { agent: null, error: 'agent: is missing' };
	if (!/^[A-Za-z0-9-]{1,64}$/.test(a)) return { agent: null, error: 'agent: must be the id of a device' };
	return { agent: UUID.test(a) ? a.toLowerCase() : a };
}

export const CALLOUT_TONES = ['info', 'warning', 'danger'] as const;
export type CalloutTone = (typeof CALLOUT_TONES)[number];
export function calloutTone(arg: string): CalloutTone | null {
	const a = (arg.trim().split(/\s+/)[0] || 'info').toLowerCase();
	return (CALLOUT_TONES as readonly string[]).includes(a) ? (a as CalloutTone) : null;
}

/** A fenced block, with a fence longer than any backtick run in the body. */
export function fence(name: string, body: string, arg = ''): string {
	const longest = Math.max(2, ...[...body.matchAll(/`+/g)].map((m) => m[0].length));
	const f = '`'.repeat(longest + 1);
	return `${f}${name}${arg ? ` ${arg}` : ''}\n${body.replace(/\n+$/, '')}\n${f}`;
}

export function credentialFence(itemId: string, label?: string): string {
	return fence('credential', `item: vault:${itemId}${label ? `\nlabel: ${label}` : ''}`);
}

/** Replaces source lines [from, to) with `text`. */
export function replaceLines(src: string, from: number, to: number, text: string): string {
	const lines = src.split('\n');
	lines.splice(from, to - from, ...text.split('\n'));
	return lines.join('\n');
}

/** The ids of every `vault:<id>` reference, as the server derives links. */
export function vaultRefs(src: string): string[] {
	const out = new Set<string>();
	for (const m of src.matchAll(/vault:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi)) out.add(m[1].toLowerCase());
	return [...out];
}

// --- templates and files -----------------------------------------------------------------------

/** Fills `{{client.name}}`, `{{date}}`, `{{user.name}}`; unknown placeholders stay as written. */
export function fillPlaceholders(body: string, vars: Record<string, string>): string {
	return body.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (m, k: string) => (Object.hasOwn(vars, k) ? vars[k] : m));
}

/** Today in the user's time zone, as an ISO date. */
export function isoToday(d = new Date()): string {
	return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/**
 * Reads YAML-style front matter (`---` lines around `key: value`) as the server's export
 * writes it: values are JSON strings, but plain and single-quoted ones are accepted too. The
 * blank line after the closing `---` belongs to the front matter.
 */
export function parseFrontMatter(text: string): { meta: Record<string, string>; body: string } {
	const src = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
	const m = /^---[ \t]*\n(?:([\s\S]*?)\n)?---[ \t]*(?:\n|$)/.exec(src);
	if (!m) return { meta: {}, body: src };
	const meta: Record<string, string> = {};
	for (const line of (m[1] ?? '').split('\n')) {
		const kv = /^([A-Za-z_][\w-]*)\s*:\s*(.*?)\s*$/.exec(line);
		if (!kv) continue;
		let v = kv[2];
		if (v.startsWith('"')) {
			try {
				v = String(JSON.parse(v));
			} catch {
				v = v.replace(/^"|"$/g, '');
			}
		} else if (v.length >= 2 && v.startsWith("'") && v.endsWith("'")) {
			v = v.slice(1, -1).replace(/''/g, "'");
		}
		meta[kv[1].toLowerCase()] = v;
	}
	let body = src.slice(m[0].length);
	if (body.startsWith('\n')) body = body.slice(1);
	return { meta, body };
}
