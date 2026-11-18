/**
 * What a policy form tells each of its fields: where the field's value comes from in the set
 * being edited, and how to get back to the inherited value. `ItemEditor` provides it; `PField`
 * reads it. Without it (a form used on its own) fields show no source.
 */
import { getContext, setContext } from 'svelte';
import type { ChainEntry } from './types';

export type FieldState =
	/** Editing the item where it's defined: every field is defined here. */
	| { kind: 'defined' }
	| { kind: 'inherited'; from: ChainEntry | undefined }
	/** `saved` false: changed in the form, not saved yet. */
	| { kind: 'overridden'; saved: boolean };

export interface FieldCtx {
	state(path: string): FieldState;
	/** Back to the inherited value: drops an unsaved change, or removes the field from the saved override. */
	reset(path: string): void;
	/** The user may change the override. */
	readonly canReset: boolean;
}

const KEY = Symbol('policy-fields');
export const provideFields = (ctx: FieldCtx) => setContext(KEY, ctx);
export const fieldCtx = () => getContext<FieldCtx | undefined>(KEY);
