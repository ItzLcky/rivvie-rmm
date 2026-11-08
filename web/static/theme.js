// Runs before first paint (a plain script, so the strict CSP's script-src 'self' allows it):
// applies the saved theme and density so the page never flashes the wrong colours. The app
// (src/lib/theme.svelte.ts) takes over once loaded and keeps this localStorage copy in sync
// with the user's server-side preferences.
(function () {
	var d = document.documentElement;
	var theme = 'system';
	var density = 'compact';
	try {
		theme = localStorage.getItem('rmm.theme') || 'system';
		density = localStorage.getItem('rmm.density') || 'compact';
	} catch (e) {
		/* storage blocked: use the defaults */
	}
	var dark = theme === 'dark' || (theme !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
	d.dataset.theme = dark ? 'dark' : 'light';
	d.dataset.density = density;
})();
