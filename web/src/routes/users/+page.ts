import { redirect } from '@sveltejs/kit';

// The Users page moved under Company settings.
export const load = () => redirect(308, '/settings/users');
