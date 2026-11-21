/**
 * The block registry: every fenced block a document can use. Adding a block is one component
 * under components/docs/blocks/ and one entry here (plus, if it needs one, an insert form).
 */
import type { Component } from 'svelte';
import { Info, KeyRound, Monitor, TableProperties } from '@lucide/svelte';
import type { AgentSummary } from '#lib/types.js';
import type { BlockName, Segment } from './markdown.js';
import type { VaultItem } from './types.js';
import type { VaultProblem } from './vault.js';
import FieldsBlock from '#lib/components/docs/blocks/FieldsBlock.svelte';
import CredentialBlock from '#lib/components/docs/blocks/CredentialBlock.svelte';
import CalloutBlock from '#lib/components/docs/blocks/CalloutBlock.svelte';
import DeviceBlock from '#lib/components/docs/blocks/DeviceBlock.svelte';

export type BlockSegment = Extract<Segment, { kind: 'block' }>;

/** What blocks need from the page around them. */
export interface DocContext {
	/** The client the document belongs to; null for templates. */
	clientId: string | null;
	/** Vault items the page may show, by id (metadata only). */
	credentials: Map<string, VaultItem>;
	/** The page links to credentials the server didn't send (no vault access). */
	credentialsHidden: boolean;
	/** Why the editor couldn't load the client's vault, if it couldn't. */
	vaultProblem?: VaultProblem | null;
	/** The client's devices, fetched on first use by a device block. */
	agents: () => Promise<Map<string, AgentSummary>>;
	/** Set in the editor's preview: fill (or change) a credential block from the vault. */
	chooseCredential?: (seg: BlockSegment, label: string) => void;
	/**
	 * Set where the page is shown outside its client's Docs tab (a ticket's drawer): where a
	 * `doc:` link goes, and what a plain click on one does instead of following it.
	 */
	docHref?: (id: string) => string;
	openDoc?: (id: string) => void;
}

export interface BlockProps {
	seg: BlockSegment;
	ctx: DocContext;
}

/** What Insert block offers: a snippet to insert, or a form that produces one. */
export type InsertForm = 'credential' | 'device' | 'callout';

export interface BlockDef {
	name: BlockName;
	label: string;
	description: string;
	icon: Component<{ class?: string }>;
	component: Component<BlockProps>;
	/** The Markdown inserted when there's no form. */
	insert: () => string;
	form?: InsertForm;
	/** Needs a client (not offered while editing a template). */
	needsClient?: boolean;
}

export const BLOCKS: Record<BlockName, BlockDef> = {
	fields: {
		name: 'fields',
		label: 'Fields',
		description: 'Label: value rows with a copy button each',
		icon: TableProperties,
		component: FieldsBlock,
		insert: () => '```fields\nLabel: value\nAnother label:\n```'
	},
	credential: {
		name: 'credential',
		label: 'Credential',
		description: 'A login from the vault, or an empty slot for one',
		icon: KeyRound,
		component: CredentialBlock,
		insert: () => '```credential\nlabel: Admin login\n```',
		form: 'credential'
	},
	callout: {
		name: 'callout',
		label: 'Callout',
		description: 'A tinted note, warning or danger box',
		icon: Info,
		component: CalloutBlock,
		insert: () => '```callout info\nText\n```',
		form: 'callout'
	},
	device: {
		name: 'device',
		label: 'Device',
		description: 'One of the client’s devices, with its live state',
		icon: Monitor,
		component: DeviceBlock,
		insert: () => '```device\nagent: \n```',
		form: 'device',
		needsClient: true
	}
};
