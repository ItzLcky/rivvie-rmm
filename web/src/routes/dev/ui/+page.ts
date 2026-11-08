import { error } from '@sveltejs/kit';

// The component gallery exists in dev builds, and in builds made for the visual regression
// tests (VITE_UI_GALLERY=1). Production bundles don't include it.
export const load = () => {
	if (!import.meta.env.DEV && !import.meta.env.VITE_UI_GALLERY) error(404, 'Not found');
};
