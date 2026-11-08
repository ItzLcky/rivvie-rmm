/** Promise-based replacement for `window.confirm()`, rendered by `<ConfirmHost>` in the layout. */
export interface ConfirmOptions {
	title: string;
	message?: string;
	confirmLabel?: string;
	danger?: boolean;
	/** Big deletes: the user must type this (e.g. the client's name) to enable the button. */
	typeToConfirm?: string;
}

interface Pending extends ConfirmOptions {
	resolve: (ok: boolean) => void;
}

export const confirmState = $state<{ current: Pending | null }>({ current: null });

export function confirmAction(opts: ConfirmOptions): Promise<boolean> {
	confirmState.current?.resolve(false);
	return new Promise((resolve) => {
		confirmState.current = { ...opts, resolve };
	});
}

export function settle(ok: boolean) {
	const c = confirmState.current;
	confirmState.current = null;
	c?.resolve(ok);
}
